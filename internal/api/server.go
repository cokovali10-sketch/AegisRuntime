//go:build linux

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cokovali10-sketch/AegisRuntime/internal/config"
	"github.com/cokovali10-sketch/AegisRuntime/internal/edr"
	"github.com/cokovali10-sketch/AegisRuntime/internal/sandbox"
)

type Server struct {
	cfg         *config.Config
	sandboxMgr  *sandbox.SandboxManager
	monitors    map[string]*edr.Monitor
	addr        string
	mux         *http.ServeMux
	monitorsMu  sync.RWMutex
}

type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Time    time.Time   `json:"time"`
}

type CreateSandboxRequest struct {
	Command    []string `json:"command"`
	Timeout    int      `json:"timeout"`
	CPUQuota   int64    `json:"cpu_quota"`
	MemoryMax  int64    `json:"memory_max"`
	PIDsMax    int      `json:"pids_max"`
	Network    string   `json:"network"`
	FileSystem string   `json:"filesystem"`
	Seccomp    string   `json:"seccomp"`
	AgentID    string   `json:"agent_id"`
	WorkingDir string   `json:"working_dir"`
	EnvVars    []string `json:"env_vars"`
	Snapshot   bool     `json:"snapshot"`
}

type SnapshotRequest struct {
	Description string `json:"description"`
}

type RollbackRequest struct {
	SnapshotID string `json:"snapshot_id"`
}

type Policy struct {
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Rules    int    `json:"rules"`
}

type Stats struct {
	ActiveSandboxes int        `json:"active_sandboxes"`
	TotalSandboxes  int        `json:"total_sandboxes"`
	TotalEvents     int        `json:"total_events"`
	Monitors        int        `json:"monitors"`
	Uptime          string     `json:"uptime"`
	Memory          MemStats   `json:"memory"`
}

type MemStats struct {
	Alloc      uint64 `json:"alloc"`
	TotalAlloc uint64 `json:"total_alloc"`
	Sys        uint64 `json:"sys"`
	NumGC      uint32 `json:"num_gc"`
}

var startTime = time.Now()

func NewServer(cfg *config.Config, sandboxMgr *sandbox.SandboxManager, addr string) *Server {
	return &Server{
		cfg:        cfg,
		sandboxMgr: sandboxMgr,
		monitors:   make(map[string]*edr.Monitor),
		addr:       addr,
		mux:        http.NewServeMux(),
	}
}

func (s *Server) SetupRoutes() {
	s.mux.HandleFunc("/api/health", s.handleHealth)
	s.mux.HandleFunc("/api/sandbox", s.routeSandbox)
	s.mux.HandleFunc("/api/sandbox/", s.routeSandboxID)
	s.mux.HandleFunc("/api/policies", s.routePolicies)
	s.mux.HandleFunc("/api/agents", s.handleListAgents)
	s.mux.HandleFunc("/api/stats", s.handleStats)
}

func (s *Server) routeSandbox(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.handleCreateSandbox(w, r)
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) routeSandboxID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/sandbox/")
	id = strings.TrimSuffix(id, "/")
	parts := strings.Split(id, "/")

	if len(parts) == 0 || parts[0] == "" {
		jsonError(w, http.StatusBadRequest, "sandbox id required")
		return
	}

	sandboxID := parts[0]

	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			s.handleGetSandbox(w, r, sandboxID)
		case http.MethodDelete:
			s.handleDestroySandbox(w, r, sandboxID)
		default:
			jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	}

	action := parts[1]
	switch action {
	case "stop":
		if r.Method != http.MethodPost {
			jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleStopSandbox(w, r, sandboxID)
	case "events":
		if r.Method != http.MethodGet {
			jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleGetEvents(w, r, sandboxID)
	case "snapshot":
		if r.Method != http.MethodPost {
			jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleSnapshot(w, r, sandboxID)
	case "rollback":
		if r.Method != http.MethodPost {
			jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleRollback(w, r, sandboxID)
	default:
		jsonError(w, http.StatusNotFound, "not found")
	}
}

func (s *Server) routePolicies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListPolicies(w, r)
	case http.MethodPost:
		s.handleCreatePolicy(w, r)
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonRespond(w, http.StatusOK, map[string]interface{}{
		"status":  "healthy",
		"version": "1.0.0",
		"uptime":  time.Since(startTime).String(),
	})
}

func (s *Server) handleCreateSandbox(w http.ResponseWriter, r *http.Request) {
	var req CreateSandboxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Command) == 0 {
		jsonError(w, http.StatusBadRequest, "command is required")
		return
	}

	if req.Timeout <= 0 {
		req.Timeout = s.cfg.DefaultTimeout
	}

	if req.Network == "" {
		req.Network = "restricted"
	}
	if req.FileSystem == "" {
		req.FileSystem = "read-only"
	}
	if req.Seccomp == "" {
		req.Seccomp = "default"
	}

	cfg := &sandbox.SandboxConfig{
		AgentID:    req.AgentID,
		Command:    req.Command,
		Timeout:    time.Duration(req.Timeout) * time.Second,
		CPUQuota:   req.CPUQuota,
		MemoryMax:  req.MemoryMax,
		PIDsMax:    req.PIDsMax,
		Network:    req.Network,
		FileSystem: req.FileSystem,
		Seccomp:    req.Seccomp,
		Snapshot:   req.Snapshot,
		WorkingDir: req.WorkingDir,
		EnvVars:    req.EnvVars,
	}

	sbx, err := s.sandboxMgr.Create(cfg)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	result, err := s.sandboxMgr.Run(sbx.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	monitorConfig := edr.MonitorConfig{
		ContainerID:    sbx.ID,
		RootfsPath:     sbx.RootfsPath,
		PID:            sbx.PID,
		WatchFiles:     true,
		WatchNetwork:   req.Network != "none",
		WatchProcess:   true,
		AlertOnCritical: true,
	}

	monitor := edr.NewMonitor(monitorConfig)
	monitor.Start()

	s.monitorsMu.Lock()
	s.monitors[sbx.ID] = monitor
	s.monitorsMu.Unlock()

	jsonRespond(w, http.StatusCreated, map[string]interface{}{
		"sandbox": sbx,
		"result":  result,
	})
}

func (s *Server) handleGetSandbox(w http.ResponseWriter, r *http.Request, id string) {
	sbx, err := s.sandboxMgr.Get(id)
	if err != nil {
		jsonError(w, http.StatusNotFound, err.Error())
		return
	}

	jsonRespond(w, http.StatusOK, sbx)
}

func (s *Server) handleStopSandbox(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.sandboxMgr.Stop(id); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.monitorsMu.RLock()
	monitor, ok := s.monitors[id]
	s.monitorsMu.RUnlock()

	if ok {
		monitor.Stop()
	}

	jsonRespond(w, http.StatusOK, map[string]string{"status": "stopped"})
}

func (s *Server) handleDestroySandbox(w http.ResponseWriter, r *http.Request, id string) {
	s.monitorsMu.RLock()
	monitor, ok := s.monitors[id]
	s.monitorsMu.RUnlock()

	if ok {
		monitor.Stop()
		s.monitorsMu.Lock()
		delete(s.monitors, id)
		s.monitorsMu.Unlock()
	}

	if err := s.sandboxMgr.Destroy(id); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	jsonRespond(w, http.StatusOK, map[string]string{"status": "destroyed"})
}

func (s *Server) handleGetEvents(w http.ResponseWriter, r *http.Request, id string) {
	s.monitorsMu.RLock()
	monitor, ok := s.monitors[id]
	s.monitorsMu.RUnlock()

	if !ok {
		jsonError(w, http.StatusNotFound, "monitor not found for sandbox")
		return
	}

	events := monitor.GetEvents()
	jsonRespond(w, http.StatusOK, events)
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request, id string) {
	snapshotID, err := s.sandboxMgr.Snapshot(id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	jsonRespond(w, http.StatusCreated, map[string]string{"snapshot_id": snapshotID})
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request, id string) {
	var req RollbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.SnapshotID == "" {
		jsonError(w, http.StatusBadRequest, "snapshot_id is required")
		return
	}

	if err := s.sandboxMgr.Rollback(id, req.SnapshotID); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	jsonRespond(w, http.StatusOK, map[string]string{"status": "rolled back"})
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	policies := []Policy{
		{Name: "default", Severity: "medium", Rules: 8},
		{Name: "aggressive", Severity: "high", Rules: 12},
		{Name: "minimal", Severity: "low", Rules: 3},
	}

	jsonRespond(w, http.StatusOK, policies)
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var policy Policy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	jsonRespond(w, http.StatusCreated, policy)
}

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	sandboxes := s.sandboxMgr.List()
	agents := make(map[string]bool)
	for _, sbx := range sandboxes {
		if sbx.AgentID != "" {
			agents[sbx.AgentID] = true
		}
	}

	agentList := make([]string, 0, len(agents))
	for agent := range agents {
		agentList = append(agentList, agent)
	}

	jsonRespond(w, http.StatusOK, agentList)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	sandboxes := s.sandboxMgr.List()
	active := 0
	totalEvents := 0

	s.monitorsMu.RLock()
	monitorCount := len(s.monitors)
	s.monitorsMu.RUnlock()

	for _, sbx := range sandboxes {
		if sbx.Status == "running" {
			active++
		}
	}

	s.monitorsMu.RLock()
	for _, monitor := range s.monitors {
		events := monitor.GetEvents()
		totalEvents += len(events)
	}
	s.monitorsMu.RUnlock()

	stats := Stats{
		ActiveSandboxes: active,
		TotalSandboxes:  len(sandboxes),
		TotalEvents:     totalEvents,
		Monitors:        monitorCount,
		Uptime:          time.Since(startTime).String(),
	}

	jsonRespond(w, http.StatusOK, stats)
}

func (s *Server) Start() error {
	s.SetupRoutes()

	server := &http.Server{
		Addr:         s.addr,
		Handler:      s.mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	fmt.Printf("AegisRuntime API server starting on %s\n", s.addr)
	return server.ListenAndServe()
}

func jsonRespond(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	resp := APIResponse{
		Success: status >= 200 && status < 300,
		Data:    data,
		Time:    time.Now(),
	}

	json.NewEncoder(w).Encode(resp)
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	resp := APIResponse{
		Success: false,
		Error:   msg,
		Time:    time.Now(),
	}

	json.NewEncoder(w).Encode(resp)
}
