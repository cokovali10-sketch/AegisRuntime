//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cokovali10-sketch/AegisRuntime/internal/config"
	"github.com/cokovali10-sketch/AegisRuntime/internal/kernel"
)

type Sandbox struct {
	ID         string
	AgentID    string
	RootfsPath string
	CgroupPath string
	PID        int
	Status     string
	Config     *SandboxConfig
	CreatedAt  time.Time
	StartedAt  time.Time
	ExitCode   int
	Output     string
	Error      string
	mu         sync.RWMutex
}

type SandboxConfig struct {
	AgentID    string        `json:"agent_id"`
	Command    []string      `json:"command"`
	Timeout    time.Duration `json:"timeout"`
	CPUQuota   int64         `json:"cpu_quota"`
	MemoryMax  int64         `json:"memory_max"`
	PIDsMax    int           `json:"pids_max"`
	Network    string        `json:"network"`
	FileSystem string        `json:"filesystem"`
	Seccomp    string        `json:"seccomp"`
	Snapshot   bool          `json:"snapshot"`
	WorkingDir string        `json:"working_dir"`
	EnvVars    []string      `json:"env_vars"`
}

type SandboxResult struct {
	ID         string        `json:"id"`
	AgentID    string        `json:"agent_id"`
	ExitCode   int           `json:"exit_code"`
	Output     string        `json:"output"`
	Error      string        `json:"error"`
	Duration   time.Duration `json:"duration"`
	TimedOut   bool          `json:"timed_out"`
	Violations []string      `json:"violations"`
}

type SandboxManager struct {
	sandboxes map[string]*Sandbox
	rootfsMgr *kernel.RootfsManager
	cfg       *config.Config
	mu        sync.RWMutex
}

func NewManager(cfg *config.Config) *SandboxManager {
	rootfsMgr := kernel.NewRootfsManager(cfg.ImageDir, cfg.ContainerDir)
	return &SandboxManager{
		sandboxes: make(map[string]*Sandbox),
		rootfsMgr: rootfsMgr,
		cfg:       cfg,
	}
}

func (sm *SandboxManager) Create(config *SandboxConfig) (*Sandbox, error) {
	if len(config.Command) == 0 {
		return nil, fmt.Errorf("command is required")
	}

	sandboxID := fmt.Sprintf("sbx-%d-%d", time.Now().UnixNano(), os.Getpid())

	containerDir := filepath.Join(sm.cfg.ContainerDir, sandboxID)
	if err := os.MkdirAll(containerDir, 0o755); err != nil {
		return nil, fmt.Errorf("create container dir: %w", err)
	}

	rootfsDir := filepath.Join(containerDir, "rootfs")
	if err := os.MkdirAll(rootfsDir, 0o755); err != nil {
		return nil, fmt.Errorf("create rootfs dir: %w", err)
	}

	if config.WorkingDir == "" {
		config.WorkingDir = "/"
	}

	s := &Sandbox{
		ID:         sandboxID,
		AgentID:    config.AgentID,
		RootfsPath: rootfsDir,
		CgroupPath: filepath.Join(sm.cfg.CgroupRoot, "aegis-"+sandboxID),
		Status:     "created",
		Config:     config,
		CreatedAt:  time.Now(),
	}

	sm.mu.Lock()
	sm.sandboxes[sandboxID] = s
	sm.mu.Unlock()

	return s, nil
}

func (sm *SandboxManager) Run(sandboxID string) (*SandboxResult, error) {
	sm.mu.RLock()
	s, ok := sm.sandboxes[sandboxID]
	sm.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("sandbox %s not found", sandboxID)
	}

	s.mu.Lock()
	if s.Status == "running" {
		s.mu.Unlock()
		return nil, fmt.Errorf("sandbox %s is already running", sandboxID)
	}
	s.Status = "running"
	s.StartedAt = time.Now()
	s.mu.Unlock()

	if err := sm.setupCgroup(s); err != nil {
		s.mu.Lock()
		s.Status = "failed"
		s.Error = err.Error()
		s.mu.Unlock()
		return nil, fmt.Errorf("setup cgroup: %w", err)
	}

	result, err := sm.execInSandbox(s)
	if err != nil {
		s.mu.Lock()
		s.Status = "failed"
		s.Error = err.Error()
		s.mu.Unlock()
		return nil, fmt.Errorf("exec in sandbox: %w", err)
	}

	s.mu.Lock()
	s.ExitCode = result.ExitCode
	s.Output = result.Output
	s.Error = result.Error
	if result.ExitCode == 0 {
		s.Status = "completed"
	} else {
		s.Status = "failed"
	}
	s.mu.Unlock()

	if s.Config.Snapshot && result.ExitCode == 0 {
		if _, err := sm.Snapshot(sandboxID); err != nil {
			fmt.Fprintf(os.Stderr, "warning: snapshot failed: %v\n", err)
		}
	}

	return result, nil
}

func (sm *SandboxManager) Stop(sandboxID string) error {
	sm.mu.RLock()
	s, ok := sm.sandboxes[sandboxID]
	sm.mu.RUnlock()

	if !ok {
		return fmt.Errorf("sandbox %s not found", sandboxID)
	}

	s.mu.RLock()
	pid := s.PID
	running := s.Status == "running"
	s.mu.RUnlock()

	if !running {
		return nil
	}

	if pid > 0 {
		if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
			if err != syscall.ESRCH {
				if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
					return fmt.Errorf("kill process: %w", err)
				}
			}
		}

		deadline := time.After(5 * time.Second)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-deadline:
				syscall.Kill(pid, syscall.SIGKILL)
				return nil
			case <-ticker.C:
				var status syscall.WaitStatus
				wpid, err := syscall.Wait4(pid, &status, syscall.WNOHANG, nil)
				if err != nil || wpid == pid {
					return nil
				}
			}
		}
	}

	return nil
}

func (sm *SandboxManager) Destroy(sandboxID string) error {
	sm.mu.RLock()
	s, ok := sm.sandboxes[sandboxID]
	sm.mu.RUnlock()

	if !ok {
		return fmt.Errorf("sandbox %s not found", sandboxID)
	}

	if err := sm.Stop(sandboxID); err != nil {
		fmt.Fprintf(os.Stderr, "warning: stop sandbox: %v\n", err)
	}

	sm.cleanupSandbox(s)

	sm.mu.Lock()
	delete(sm.sandboxes, sandboxID)
	sm.mu.Unlock()

	return nil
}

func (sm *SandboxManager) Get(sandboxID string) (*Sandbox, error) {
	sm.mu.RLock()
	s, ok := sm.sandboxes[sandboxID]
	sm.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("sandbox %s not found", sandboxID)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	cp := *s
	return &cp, nil
}

func (sm *SandboxManager) List() []*Sandbox {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	result := make([]*Sandbox, 0, len(sm.sandboxes))
	for _, s := range sm.sandboxes {
		s.mu.RLock()
		cp := *s
		s.mu.RUnlock()
		result = append(result, &cp)
	}
	return result
}

func (sm *SandboxManager) Snapshot(sandboxID string) (string, error) {
	sm.mu.RLock()
	s, ok := sm.sandboxes[sandboxID]
	sm.mu.RUnlock()

	if !ok {
		return "", fmt.Errorf("sandbox %s not found", sandboxID)
	}

	s.mu.RLock()
	rootfsPath := s.RootfsPath
	s.mu.RUnlock()

	return CreateSnapshot(sandboxID, rootfsPath, sm.cfg.SnapshotDir)
}

func (sm *SandboxManager) Rollback(sandboxID, snapshotID string) error {
	sm.mu.RLock()
	s, ok := sm.sandboxes[sandboxID]
	sm.mu.RUnlock()

	if !ok {
		return fmt.Errorf("sandbox %s not found", sandboxID)
	}

	s.mu.RLock()
	rootfsPath := s.RootfsPath
	s.mu.RUnlock()

	snapshots, err := ListSnapshots(sm.cfg.SnapshotDir, sandboxID)
	if err != nil {
		return fmt.Errorf("list snapshots: %w", err)
	}

	for _, snap := range snapshots {
		if snap.ID == snapshotID {
			return RestoreSnapshot(snap, rootfsPath)
		}
	}

	return fmt.Errorf("snapshot %s not found", snapshotID)
}

func (sm *SandboxManager) setupCgroup(s *Sandbox) error {
	cfg := kernel.CgroupConfig{
		Name:       "aegis-" + s.ID,
		CgroupRoot: sm.cfg.CgroupRoot,
		CPUQuota:   s.Config.CPUQuota,
		MemoryMax:  s.Config.MemoryMax,
		PIDsMax:    s.Config.PIDsMax,
	}

	if err := kernel.Create(cfg); err != nil {
		return fmt.Errorf("create cgroup: %w", err)
	}

	if err := kernel.SetCPU(cfg); err != nil {
		return fmt.Errorf("set cpu: %w", err)
	}

	if err := kernel.SetMemory(cfg); err != nil {
		return fmt.Errorf("set memory: %w", err)
	}

	if err := kernel.SetPIDs(cfg); err != nil {
		return fmt.Errorf("set pids: %w", err)
	}

	return nil
}

func (sm *SandboxManager) execInSandbox(s *Sandbox) (*SandboxResult, error) {
	result := &SandboxResult{
		ID:      s.ID,
		AgentID: s.AgentID,
	}

	timeout := s.Config.Timeout
	if timeout == 0 {
		timeout = time.Duration(sm.cfg.DefaultTimeout) * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	args := s.Config.Command
	cmdName := args[0]
	var cmdArgs []string
	if len(args) > 1 {
		cmdArgs = args[1:]
	}

	cmd := exec.CommandContext(ctx, cmdName, cmdArgs...)
	cmd.Dir = s.Config.WorkingDir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	cmd.Env = append(os.Environ(), s.Config.EnvVars...)

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS | syscall.CLONE_NEWNET,
	}

	startTime := time.Now()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start command: %w", err)
	}

	s.mu.Lock()
	s.PID = cmd.Process.Pid
	s.mu.Unlock()

	sm.monitorProcess(ctx, s, result)

	err := cmd.Wait()
	result.Duration = time.Since(startTime)
	result.Output = stdout.String()
	result.Error = stderr.String()

	if ctx.Err() == context.DeadlineExceeded {
		result.TimedOut = true
		result.ExitCode = -1
		result.Error = "execution timed out"
	} else if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
			result.Error = err.Error()
		}
	}

	return result, nil
}

func (sm *SandboxManager) monitorProcess(ctx context.Context, s *Sandbox, result *SandboxResult) {
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sm.checkViolations(s, result)
			}
		}
	}()
}

func (sm *SandboxManager) checkViolations(s *Sandbox, result *SandboxResult) {
	if s.Config.Network == "none" {
		s.mu.RLock()
		pid := s.PID
		s.mu.RUnlock()

		if pid > 0 {
			netPath := fmt.Sprintf("/proc/%d/net", pid)
			if entries, err := os.ReadDir(netPath); err == nil {
				for _, entry := range entries {
					if entry.Name() == "tcp" || entry.Name() == "udp" {
						data, err := os.ReadFile(filepath.Join(netPath, entry.Name()))
						if err == nil {
							lines := strings.Split(string(data), "\n")
							for _, line := range lines[1:] {
								if strings.TrimSpace(line) != "" {
									result.Violations = append(result.Violations,
										fmt.Sprintf("network access detected: %s", strings.TrimSpace(line)))
								}
							}
						}
					}
				}
			}
		}
	}
}

func (sm *SandboxManager) cleanupSandbox(s *Sandbox) {
	sm.cleanupCgroup(s)

	containerDir := filepath.Join(sm.cfg.ContainerDir, s.ID)
	os.RemoveAll(containerDir)
}

func (sm *SandboxManager) cleanupCgroup(s *Sandbox) {
	cfg := kernel.CgroupConfig{
		Name:       "aegis-" + s.ID,
		CgroupRoot: sm.cfg.CgroupRoot,
	}
	if err := kernel.Destroy(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "warning: destroy cgroup: %v\n", err)
	}
}

func parseMountOptions(opts string) uintptr {
	var flags uintptr
	for _, opt := range strings.Split(opts, ",") {
		switch strings.TrimSpace(opt) {
		case "bind":
			flags |= syscall.MS_BIND
		case "ro":
			flags |= syscall.MS_RDONLY
		case "nosuid":
			flags |= syscall.MS_NOSUID
		case "nodev":
			flags |= syscall.MS_NODEV
		}
	}
	return flags
}

func parseUint(s string) uint64 {
	v, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	return v
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
