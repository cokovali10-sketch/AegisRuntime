//go:build linux

package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type WSMessage struct {
	Type      string      `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
}

type WSAuditStream struct {
	ContainerID string      `json:"container_id"`
	Events      []WSMessage `json:"events"`
	Connected   bool        `json:"connected"`
}

type WSManager struct {
	clients    map[*websocket.Conn]*WSClient
	broadcast  chan WSMessage
	mu         sync.RWMutex
	stats      *WSStats
	register   chan *WSClient
	unregister chan *WSClient
}

type WSClient struct {
	conn        *websocket.Conn
	containerID string
	send        chan WSMessage
	mu          sync.Mutex
}

type WSStats struct {
	TotalConnections   int64     `json:"total_connections"`
	ActiveConnections  int       `json:"active_connections"`
	MessagesSent       int64     `json:"messages_sent"`
	MessagesReceived   int64     `json:"messages_received"`
	LastActivityTime   time.Time `json:"last_activity_time"`
	StartTime          time.Time `json:"start_time"`
	mu                 sync.RWMutex
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func NewWSManager() *WSManager {
	wm := &WSManager{
		clients:    make(map[*websocket.Conn]*WSClient),
		broadcast:  make(chan WSMessage, 256),
		register:   make(chan *WSClient),
		unregister: make(chan *WSClient),
		stats: &WSStats{
			StartTime: time.Now(),
		},
	}
	go wm.run()
	return wm
}

func (wm *WSManager) run() {
	for {
		select {
		case client := <-wm.register:
			wm.mu.Lock()
			wm.clients[client.conn] = client
			wm.mu.Unlock()
			wm.stats.mu.Lock()
			wm.stats.TotalConnections++
			wm.stats.ActiveConnections = len(wm.clients)
			wm.stats.mu.Unlock()
			log.Printf("[WS] Client connected: %s (total: %d)", client.containerID, len(wm.clients))

		case client := <-wm.unregister:
			wm.mu.Lock()
			if _, ok := wm.clients[client.conn]; ok {
				delete(wm.clients, client.conn)
				close(client.send)
			}
			wm.mu.Unlock()
			wm.stats.mu.Lock()
			wm.stats.ActiveConnections = len(wm.clients)
			wm.stats.mu.Unlock()
			log.Printf("[WS] Client disconnected: %s (total: %d)", client.containerID, len(wm.clients))

		case msg := <-wm.broadcast:
			wm.mu.RLock()
			for conn, client := range wm.clients {
				select {
				case client.send <- msg:
					wm.stats.mu.Lock()
					wm.stats.MessagesSent++
					wm.stats.LastActivityTime = time.Now()
					wm.stats.mu.Unlock()
				default:
					close(client.send)
					delete(wm.clients, conn)
				}
			}
			wm.mu.RUnlock()
		}
	}
}

func (wm *WSManager) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WS] Upgrade error: %v", err)
		return
	}

	containerID := r.URL.Query().Get("container_id")
	if containerID == "" {
		containerID = fmt.Sprintf("container-%d", time.Now().UnixNano())
	}

	client := &WSClient{
		conn:        conn,
		containerID: containerID,
		send:        make(chan WSMessage, 256),
	}

	wm.register <- client

	welcomeMsg := WSMessage{
		Type:      "system",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"message":      "Connected to AegisRuntime Audit Stream",
			"container_id": containerID,
			"server_time":  time.Now().Format(time.RFC3339),
		},
	}
	client.send <- welcomeMsg

	go client.writePump()
	go client.readPump(wm)
}

func (wm *WSManager) HandleAuditStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	stream := WSAuditStream{
		ContainerID: r.URL.Query().Get("container_id"),
		Events:      make([]WSMessage, 0, 100),
		Connected:   false,
	}

	events := wm.GetRecentEvents(stream.ContainerID, 50)
	stream.Events = events
	stream.Connected = wm.IsContainerConnected(stream.ContainerID)

	wm.stats.mu.RLock()
	stats := map[string]interface{}{
		"active_connections": wm.stats.ActiveConnections,
		"total_connections":  wm.stats.TotalConnections,
		"messages_sent":      wm.stats.MessagesSent,
		"uptime":             time.Since(wm.stats.StartTime).String(),
	}
	wm.stats.mu.RUnlock()

	response := map[string]interface{}{
		"stream": stream,
		"stats":  stats,
	}

	json.NewEncoder(w).Encode(response)
}

func (wm *WSManager) BroadcastEvent(containerID string, eventType string, data interface{}) {
	msg := WSMessage{
		Type:      eventType,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"container_id": containerID,
			"payload":      data,
		},
	}
	wm.broadcast <- msg
}

func (wm *WSManager) BroadcastToContainer(containerID string, msg WSMessage) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	for _, client := range wm.clients {
		if client.containerID == containerID {
			select {
			case client.send <- msg:
				wm.stats.mu.Lock()
				wm.stats.MessagesSent++
				wm.stats.mu.Unlock()
			default:
				log.Printf("[WS] Drop message for container %s: send buffer full", containerID)
			}
		}
	}
}

func (c *WSClient) readPump(wm *WSManager) {
	defer func() {
		wm.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(512 * 1024)
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, rawMsg, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("[WS] Read error from %s: %v", c.containerID, err)
			}
			break
		}

		wm.stats.mu.Lock()
		wm.stats.MessagesReceived++
		wm.stats.LastActivityTime = time.Now()
		wm.stats.mu.Unlock()

		var msg WSMessage
		if err := json.Unmarshal(rawMsg, &msg); err != nil {
			log.Printf("[WS] Invalid message format from %s: %v", c.containerID, err)
			continue
		}

		msg.Timestamp = time.Now()
		c.handleClientMessage(wm, msg)
	}
}

func (c *WSClient) handleClientMessage(wm *WSManager, msg WSMessage) {
	switch msg.Type {
	case "subscribe":
		log.Printf("[WS] Client %s subscribed to container %s", c.containerID, c.containerID)

	case "unsubscribe":
		log.Printf("[WS] Client %s unsubscribed", c.containerID)

	case "ping":
		pong := WSMessage{
			Type:      "pong",
			Timestamp: time.Now(),
			Data:      map[string]interface{}{"message": "pong"},
		}
		c.send <- pong

	case "request_stats":
		stats := wm.GetStats()
		response := WSMessage{
			Type:      "stats",
			Timestamp: time.Now(),
			Data:      stats,
		}
		c.send <- response

	default:
		log.Printf("[WS] Unknown message type from %s: %s", c.containerID, msg.Type)
	}
}

func (c *WSClient) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case msg, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}

			jsonBytes, err := json.Marshal(msg)
			if err != nil {
				log.Printf("[WS] Marshal error: %v", err)
				continue
			}

			if _, err := w.Write(jsonBytes); err != nil {
				return
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (wm *WSManager) sendSystemMessage(conn *websocket.Conn, msg string) {
	systemMsg := WSMessage{
		Type:      "system",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"message": msg,
		},
	}

	wm.mu.RLock()
	client, exists := wm.clients[conn]
	wm.mu.RUnlock()

	if exists {
		select {
		case client.send <- systemMsg:
		default:
			log.Printf("[WS] Failed to send system message: buffer full")
		}
	}
}

func (wm *WSManager) GetStats() map[string]interface{} {
	wm.mu.RLock()
	activeConns := len(wm.clients)
	wm.mu.RUnlock()

	wm.stats.mu.RLock()
	defer wm.stats.mu.RUnlock()

	return map[string]interface{}{
		"active_connections":  activeConns,
		"total_connections":   wm.stats.TotalConnections,
		"messages_sent":       wm.stats.MessagesSent,
		"messages_received":   wm.stats.MessagesReceived,
		"last_activity":       wm.stats.LastActivityTime.Format(time.RFC3339),
		"uptime_seconds":      int(time.Since(wm.stats.StartTime).Seconds()),
		"container_ids":       wm.getConnectedContainerIDs(),
	}
}

func (wm *WSManager) getConnectedContainerIDs() []string {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	ids := make([]string, 0, len(wm.clients))
	for _, client := range wm.clients {
		ids = append(ids, client.containerID)
	}
	return ids
}

func (wm *WSManager) IsContainerConnected(containerID string) bool {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	for _, client := range wm.clients {
		if client.containerID == containerID {
			return true
		}
	}
	return false
}

func (wm *WSManager) GetRecentEvents(containerID string, limit int) []WSMessage {
	events := make([]WSMessage, 0, limit)
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	for _, client := range wm.clients {
		if containerID != "" && client.containerID != containerID {
			continue
		}
		for msg := range client.send {
			events = append(events, msg)
			if len(events) >= limit {
				return events
			}
		}
	}
	return events
}

func (wm *WSManager) SendToAll(msg WSMessage) {
	wm.broadcast <- msg
}

func (wm *WSManager) ClientCount() int {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	return len(wm.clients)
}

func (wm *WSManager) Shutdown() {
	wm.mu.Lock()
	for conn, client := range wm.clients {
		close(client.send)
		delete(wm.clients, conn)
		conn.Close()
	}
	wm.mu.Unlock()
	log.Println("[WS] Manager shut down")
}
