//go:build linux

package edr

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type Monitor struct {
	containerID string
	rootfsPath  string
	pid         int
	events      []AuditEvent
	callbacks   []func(AuditEvent)
	mu          sync.RWMutex
	stopCh      chan struct{}
	config      MonitorConfig
	ruleEngine  *RuleEngine
}

type AuditEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	Type        string    `json:"type"`
	Action      string    `json:"action"`
	Target      string    `json:"target"`
	Details     string    `json:"details"`
	Severity    string    `json:"severity"`
	ContainerID string    `json:"container_id"`
}

type MonitorConfig struct {
	ContainerID    string
	RootfsPath     string
	PID            int
	WatchFiles     bool
	WatchNetwork   bool
	WatchProcess   bool
	AlertOnCritical bool
}

func NewMonitor(cfg MonitorConfig) *Monitor {
	return &Monitor{
		containerID: cfg.ContainerID,
		rootfsPath:  cfg.RootfsPath,
		pid:         cfg.PID,
		events:      make([]AuditEvent, 0),
		callbacks:   make([]func(AuditEvent), 0),
		stopCh:      make(chan struct{}),
		config:      cfg,
		ruleEngine:  NewRuleEngine(DefaultRules()),
	}
}

func (m *Monitor) Start() error {
	if m.config.WatchFiles {
		go m.monitorFilesystem()
	}

	if m.config.WatchNetwork {
		go m.monitorNetwork()
	}

	if m.config.WatchProcess {
		go m.monitorProcess()
	}

	return nil
}

func (m *Monitor) Stop() {
	close(m.stopCh)
}

func (m *Monitor) GetEvents() []AuditEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	events := make([]AuditEvent, len(m.events))
	copy(events, m.events)
	return events
}

func (m *Monitor) GetEventsByType(eventType string) []AuditEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []AuditEvent
	for _, event := range m.events {
		if event.Type == eventType {
			result = append(result, event)
		}
	}
	return result
}

func (m *Monitor) GetEventsBySeverity(severity string) []AuditEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []AuditEvent
	for _, event := range m.events {
		if event.Severity == severity {
			result = append(result, event)
		}
	}
	return result
}

func (m *Monitor) AddCallback(fn func(AuditEvent)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callbacks = append(m.callbacks, fn)
}

func (m *Monitor) emitEvent(event AuditEvent) {
	event.Timestamp = time.Now()
	event.ContainerID = m.containerID

	m.mu.Lock()
	m.events = append(m.events, event)
	callbacks := make([]func(AuditEvent), len(m.callbacks))
	copy(callbacks, m.callbacks)
	m.mu.Unlock()

	for _, cb := range callbacks {
		cb(event)
	}

	matches := m.ruleEngine.Evaluate(event)
	for _, match := range matches {
		switch match.Action {
		case "kill":
			m.killProcess()
		case "block":
			fmt.Fprintf(os.Stderr, "EDR BLOCKED: rule=%s target=%s\n", match.Rule.ID, event.Target)
		case "alert":
			fmt.Fprintf(os.Stderr, "EDR ALERT: rule=%s severity=%s target=%s\n", match.Rule.ID, event.Severity, event.Target)
		}
	}
}

func (m *Monitor) killProcess() {
	m.mu.RLock()
	pid := m.pid
	m.mu.RUnlock()

	if pid > 0 {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

func (m *Monitor) monitorFilesystem() {
	pathsToWatch := []string{
		m.rootfsPath,
	}

	for _, path := range pathsToWatch {
		if _, err := os.Stat(path); err == nil {
			go m.inotifyWatch(path)
		}
	}

	<-m.stopCh
}

func (m *Monitor) inotifyWatch(dir string) {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC)
	if err != nil {
		fmt.Fprintf(os.Stderr, "inotify init: %v\n", err)
		return
	}
	defer syscall.Close(fd)

	mask := syscall.IN_CREATE | syscall.IN_DELETE | syscall.IN_MODIFY | syscall.IN_MOVED_FROM | syscall.IN_MOVED_TO
	watchDescriptors := make(map[int]string)

	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			wd, err := syscall.InotifyAddWatch(fd, path, uint32(mask))
			if err == nil {
				watchDescriptors[wd] = path
			}
		}
		return nil
	})
	if err != nil {
		return
	}

	buf := make([]byte, 4096)
	for {
		select {
		case <-m.stopCh:
			return
		default:
		}

		n, err := syscall.Read(fd, buf)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return
		}

		if n < syscall.SizeofInotifyEvent {
			continue
		}

		offset := 0
		for offset < n-syscall.SizeofInotifyEvent {
			event := (*syscall.InotifyEvent)(unsafe.Pointer(&buf[offset]))

			wdPath := watchDescriptors[int(event.Wd)]
			if event.Len > 0 {
				name := strings.TrimRight(string(buf[offset+syscall.SizeofInotifyEvent:offset+syscall.SizeofInotifyEvent+int(event.Len)]), "\x00")
				fullPath := filepath.Join(wdPath, name)

				var action string
				switch {
				case event.Mask&syscall.IN_CREATE != 0:
					action = "create"
				case event.Mask&syscall.IN_MODIFY != 0:
					action = "modify"
				case event.Mask&syscall.IN_DELETE != 0:
					action = "delete"
				case event.Mask&(syscall.IN_MOVED_FROM|syscall.IN_MOVED_TO) != 0:
					action = "modify"
				default:
					action = "unknown"
				}

				severity := "low"
				for _, dangerous := range DangerousPaths {
					if strings.Contains(fullPath, dangerous) {
						severity = "high"
						break
					}
				}

				m.emitEvent(AuditEvent{
					Type:     "file",
					Action:   action,
					Target:   fullPath,
					Details:  fmt.Sprintf("mask=%d name=%s", event.Mask, name),
					Severity: severity,
				})
			}

			offset += syscall.SizeofInotifyEvent + int(event.Len)
		}
	}
}

func (m *Monitor) monitorNetwork() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var prevConns map[string]bool

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			conns := m.getNetworkConnections()

			currentConns := make(map[string]bool)
			for _, conn := range conns {
				key := fmt.Sprintf("%s:%s->%s:%s", conn.LocalAddr, conn.LocalPort, conn.RemoteAddr, conn.RemotePort)
				currentConns[key] = true

				if prevConns == nil || !prevConns[key] {
					severity := "low"
					for _, suspicious := range SuspiciousNetworkPatterns {
						if strings.Contains(conn.RemoteAddr, suspicious) {
							severity = "critical"
							break
						}
					}

					m.emitEvent(AuditEvent{
						Type:     "network",
						Action:   "connect",
						Target:   conn.RemoteAddr + ":" + conn.RemotePort,
						Details:  fmt.Sprintf("local=%s:%s proto=%s", conn.LocalAddr, conn.LocalPort, conn.Proto),
						Severity: severity,
					})
				}
			}

			if prevConns != nil {
				for key := range prevConns {
					if !currentConns[key] {
						parts := strings.SplitN(key, "->", 2)
						if len(parts) == 2 {
							m.emitEvent(AuditEvent{
								Type:     "network",
								Action:   "disconnect",
								Target:   parts[1],
								Details:  fmt.Sprintf("connection closed"),
								Severity: "low",
							})
						}
					}
				}
			}

			prevConns = currentConns
		}
	}
}

type networkConnection struct {
	LocalAddr  string
	LocalPort  string
	RemoteAddr string
	RemotePort string
	Proto      string
	State      string
}

func (m *Monitor) getNetworkConnections() []networkConnection {
	var conns []networkConnection

	protoFiles := map[string]string{
		"tcp":  "/proc/net/tcp",
		"udp":  "/proc/net/udp",
		"tcp6": "/proc/net/tcp6",
		"udp6": "/proc/net/udp6",
	}

	m.mu.RLock()
	pid := m.pid
	m.mu.RUnlock()

	for proto, procFile := range protoFiles {
		var data []byte
		if pid > 0 {
			path := fmt.Sprintf("/proc/%d/%s", pid, procFile)
			data, _ = os.ReadFile(path)
		} else {
			data, _ = os.ReadFile(procFile)
		}

		if data == nil {
			continue
		}

		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			if lineNum == 1 {
				continue
			}

			line := strings.Fields(scanner.Text())
			if len(line) < 4 {
				continue
			}

			localParts := strings.Split(line[1], ":")
			remoteParts := strings.Split(line[2], ":")

			if len(localParts) < 2 || len(remoteParts) < 2 {
				continue
			}

			localAddr := decodeIPv4(localParts[0])
			localPort := decodePort(localParts[1])
			remoteAddr := decodeIPv4(remoteParts[0])
			remotePort := decodePort(remoteParts[1])

			state := decodeTCPState(line[3])

			conns = append(conns, networkConnection{
				LocalAddr:  localAddr,
				LocalPort:  localPort,
				RemoteAddr: remoteAddr,
				RemotePort: remotePort,
				Proto:      proto,
				State:      state,
			})
		}
	}

	return conns
}

func decodeIPv4(hexIP string) string {
	if len(hexIP) != 8 {
		return hexIP
	}

	var bytes [4]byte
	for i := 0; i < 4; i++ {
		val, _ := strconv.ParseUint(hexIP[i*2:i*2+2], 16, 8)
		bytes[3-i] = byte(val)
	}

	return fmt.Sprintf("%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3])
}

func decodePort(hexPort string) string {
	val, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return hexPort
	}
	return fmt.Sprintf("%d", val)
}

func decodeTCPState(hexState string) string {
	states := map[string]string{
		"01": "ESTABLISHED",
		"02": "SYN_SENT",
		"03": "SYN_RECV",
		"04": "FIN_WAIT1",
		"05": "FIN_WAIT2",
		"06": "TIME_WAIT",
		"07": "CLOSE",
		"08": "CLOSE_WAIT",
		"09": "LAST_ACK",
		"0A": "LISTEN",
		"0B": "CLOSING",
	}
	if state, ok := states[hexState]; ok {
		return state
	}
	return hexState
}

func (m *Monitor) monitorProcess() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	previousProcs := make(map[int]bool)

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			procs := m.getProcessList()

			currentProcs := make(map[int]bool)
			for _, proc := range procs {
				currentProcs[proc.PID] = true

				if !previousProcs[proc.PID] {
					severity := "low"
					for _, cmd := range DangerousCommands {
						if strings.Contains(proc.Command, cmd) {
							severity = "critical"
							break
						}
					}

					m.emitEvent(AuditEvent{
						Type:     "process",
						Action:   "create",
						Target:   proc.Command,
						Details:  fmt.Sprintf("pid=%d ppid=%d uid=%d", proc.PID, proc.PPID, proc.UID),
						Severity: severity,
					})
				}
			}

			for pid := range previousProcs {
				if !currentProcs[pid] {
					m.emitEvent(AuditEvent{
						Type:     "process",
						Action:   "delete",
						Target:   fmt.Sprintf("pid=%d", pid),
						Details:  "process exited",
						Severity: "low",
					})
				}
			}

			previousProcs = currentProcs
		}
	}
}

type processInfo struct {
	PID     int
	PPID    int
	UID     int
	Command string
}

func (m *Monitor) getProcessList() []processInfo {
	var procs []processInfo

	m.mu.RLock()
	targetPID := m.pid
	m.mu.RUnlock()

	if targetPID > 0 {
		procPath := fmt.Sprintf("/proc/%d", targetPID)
		if info, err := os.Stat(procPath); err == nil && info.IsDir() {
			proc := m.readProcessInfo(targetPID)
			if proc != nil {
				procs = append(procs, *proc)
			}
		}
	}

	procDirs, err := os.ReadDir("/proc")
	if err != nil {
		return procs
	}

	for _, entry := range procDirs {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == 0 {
			continue
		}

		if targetPID > 0 && pid != targetPID {
			continue
		}

		proc := m.readProcessInfo(pid)
		if proc != nil {
			procs = append(procs, *proc)
		}
	}

	return procs
}

func (m *Monitor) readProcessInfo(pid int) *processInfo {
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return nil
	}

	proc := &processInfo{PID: pid}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "PPid":
			proc.PPID, _ = strconv.Atoi(val)
		case "Uid":
			uidParts := strings.Fields(val)
			if len(uidParts) > 0 {
				proc.UID, _ = strconv.Atoi(uidParts[0])
			}
		}
	}

	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	cmdline, err := os.ReadFile(cmdlinePath)
	if err == nil {
		proc.Command = strings.ReplaceAll(string(cmdline), "\x00", " ")
		proc.Command = strings.TrimSpace(proc.Command)
	}

	return proc
}

func (m *Monitor) checkSuspiciousActivity(event AuditEvent) {
	if event.Severity == "critical" && m.config.AlertOnCritical {
		fmt.Fprintf(os.Stderr, "CRITICAL ALERT: container=%s type=%s target=%s\n",
			m.containerID, event.Type, event.Target)
	}
}
