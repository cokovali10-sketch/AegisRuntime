//go:build linux

package kernel

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type CgroupConfig struct {
	Name       string
	CgroupRoot string
	CPUQuota   int64
	CPUPeriod  int64
	MemoryMax  int64
	PIDsMax    int
	IOReadBPS  int64
	IOWriteBPS int64
}

type CgroupStats struct {
	CPUUsage    uint64 `json:"cpu_usage_us"`
	MemoryUsage uint64 `json:"memory_usage_bytes"`
	MemoryMax   uint64 `json:"memory_max_bytes"`
	OOMKills    uint64 `json:"oom_kills"`
	Processes   int    `json:"processes"`
	IORead      uint64 `json:"io_read_bytes"`
	IOWrite     uint64 `json:"io_write_bytes"`
}

func defaultCgroupRoot() string {
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		return "/sys/fs/cgroup"
	}
	if _, err := os.Stat("/sys/fs/cgroup/unified"); err == nil {
		return "/sys/fs/cgroup/unified"
	}
	return "/sys/fs/cgroup"
}

func cgroupPath(cfg CgroupConfig) string {
	root := cfg.CgroupRoot
	if root == "" {
		root = defaultCgroupRoot()
	}
	return filepath.Join(root, cfg.Name)
}

func writeCgroupFile(cgroupDir, filename string, value interface{}) error {
	path := filepath.Join(cgroupDir, filename)
	var data string
	switch v := value.(type) {
	case int:
		data = strconv.Itoa(v)
	case int64:
		data = strconv.FormatInt(v, 10)
	case uint64:
		data = strconv.FormatUint(v, 10)
	case string:
		data = v
	default:
		data = fmt.Sprintf("%v", v)
	}

	if err := os.WriteFile(path, []byte(data+"\n"), 0o644); err != nil {
		return fmt.Errorf("write %s to %s: %w", filename, path, err)
	}

	return nil
}

func readCgroupFile(cgroupDir, filename string) (string, error) {
	path := filepath.Join(cgroupDir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return strings.TrimSpace(string(data)), nil
}

func Create(cfg CgroupConfig) error {
	dir := cgroupPath(cfg)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create cgroup %s: %w", dir, err)
	}

	controllers := []string{"cpu", "memory", "pids", "io"}
	for _, ctrl := range controllers {
		enablePath := filepath.Join(dir, "cgroup.subtree_control")
		if _, err := os.Stat(enablePath); err == nil {
			if err := writeCgroupFile(dir, "cgroup.subtree_control", "+"+ctrl); err != nil {
				fmt.Fprintf(os.Stderr, "warning: enable controller %s: %v\n", ctrl, err)
			}
		}
	}

	return nil
}

func Destroy(cfg CgroupConfig) error {
	dir := cgroupPath(cfg)

	procsPath := filepath.Join(dir, "cgroup.procs")
	if _, err := os.Stat(procsPath); err == nil {
		data, err := os.ReadFile(procsPath)
		if err == nil {
			pids := strings.Split(strings.TrimSpace(string(data)), "\n")
			for _, pidStr := range pids {
				if pidStr == "" {
					continue
				}
				pid, err := strconv.Atoi(pidStr)
				if err == nil {
					syscall.Kill(pid, 9)
				}
			}
		}
	}

	subdirs, err := os.ReadDir(dir)
	if err == nil {
		for _, entry := range subdirs {
			if entry.IsDir() {
				subCfg := cfg
				subCfg.Name = filepath.Join(cfg.Name, entry.Name())
				_ = Destroy(subCfg)
			}
		}
	}

	if err := os.Remove(dir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove cgroup %s: %w", dir, err)
	}

	return nil
}

func SetCPU(cfg CgroupConfig) error {
	dir := cgroupPath(cfg)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("cgroup %s does not exist", cfg.Name)
	}

	period := cfg.CPUPeriod
	if period == 0 {
		period = 100000
	}

	if cfg.CPUQuota > 0 {
		if err := writeCgroupFile(dir, "cpu.max", fmt.Sprintf("%d %d", cfg.CPUQuota, period)); err != nil {
			return fmt.Errorf("set cpu quota: %w", err)
		}
	}

	if err := writeCgroupFile(dir, "cpu.weight", "100"); err != nil {
		fmt.Fprintf(os.Stderr, "warning: set cpu.weight: %v\n", err)
	}

	return nil
}

func SetMemory(cfg CgroupConfig) error {
	dir := cgroupPath(cfg)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("cgroup %s does not exist", cfg.Name)
	}

	if cfg.MemoryMax > 0 {
		if err := writeCgroupFile(dir, "memory.max", cfg.MemoryMax); err != nil {
			return fmt.Errorf("set memory max: %w", err)
		}
	}

	if err := writeCgroupFile(dir, "memory.high", int64(float64(cfg.MemoryMax)*0.8)); err != nil {
		fmt.Fprintf(os.Stderr, "warning: set memory.high: %v\n", err)
	}

	if err := writeCgroupFile(dir, "memory.swap.max", 0); err != nil {
		fmt.Fprintf(os.Stderr, "warning: disable swap: %v\n", err)
	}

	return nil
}

func SetPIDs(cfg CgroupConfig) error {
	dir := cgroupPath(cfg)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("cgroup %s does not exist", cfg.Name)
	}

	if cfg.PIDsMax > 0 {
		if err := writeCgroupFile(dir, "pids.max", cfg.PIDsMax); err != nil {
			return fmt.Errorf("set pids max: %w", err)
		}
	}

	return nil
}

func SetIO(cfg CgroupConfig) error {
	dir := cgroupPath(cfg)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("cgroup %s does not exist", cfg.Name)
	}

	if cfg.IOReadBPS > 0 || cfg.IOWriteBPS > 0 {
		ioMaxPath := filepath.Join(dir, "io.max")
		if _, err := os.Stat(ioMaxPath); err == nil {
			devices, err := os.ReadDir("/sys/fs/cgroup")
			if err == nil {
				for _, dev := range devices {
					if dev.Name() == "." || dev.Name() == ".." {
						continue
					}
					var limits []string
					if cfg.IOReadBPS > 0 {
						limits = append(limits, fmt.Sprintf("rbps=%d", cfg.IOReadBPS))
					}
					if cfg.IOWriteBPS > 0 {
						limits = append(limits, fmt.Sprintf("wbps=%d", cfg.IOWriteBPS))
					}
					val := strings.Join(limits, " ")
					if err := writeCgroupFile(dir, "io.max", dev.Name()+" "+val); err != nil {
						fmt.Fprintf(os.Stderr, "warning: set io.max for %s: %v\n", dev.Name(), err)
					}
				}
			}
		}
	}

	return nil
}

func AddProcess(cfg CgroupConfig, pid int) error {
	dir := cgroupPath(cfg)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("cgroup %s does not exist", cfg.Name)
	}

	return writeCgroupFile(dir, "cgroup.procs", pid)
}

func GetStats(cfg CgroupConfig) (*CgroupStats, error) {
	dir := cgroupPath(cfg)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, fmt.Errorf("cgroup %s does not exist", cfg.Name)
	}

	stats := &CgroupStats{}

	if val, err := readCgroupFile(dir, "cpu.stat"); err == nil {
		lines := strings.Split(val, "\n")
		for _, line := range lines {
			parts := strings.Fields(line)
			if len(parts) == 2 {
				switch parts[0] {
				case "usage_usec":
					if v, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
						stats.CPUUsage = v
					}
				}
			}
		}
	}

	if val, err := readCgroupFile(dir, "memory.current"); err == nil {
		if v, err := strconv.ParseUint(val, 10, 64); err == nil {
			stats.MemoryUsage = v
		}
	}

	if val, err := readCgroupFile(dir, "memory.max"); err == nil {
		if val != "max" {
			if v, err := strconv.ParseUint(val, 10, 64); err == nil {
				stats.MemoryMax = v
			}
		}
	}

	if val, err := readCgroupFile(dir, "memory.oom.group"); err == nil {
		if v, err := strconv.ParseUint(val, 10, 64); err == nil {
			stats.OOMKills = v
		}
	}

	if val, err := readCgroupFile(dir, "cgroup.procs"); err == nil {
		pids := strings.Split(val, "\n")
		count := 0
		for _, p := range pids {
			if p != "" {
				count++
			}
		}
		stats.Processes = count
	}

	if val, err := readCgroupFile(dir, "io.stat"); err == nil {
		lines := strings.Split(val, "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				for _, part := range parts[1:] {
					kv := strings.SplitN(part, "=", 2)
					if len(kv) == 2 {
						switch kv[0] {
						case "rbytes":
							if v, err := strconv.ParseUint(kv[1], 10, 64); err == nil {
								stats.IORead += v
							}
						case "wbytes":
							if v, err := strconv.ParseUint(kv[1], 10, 64); err == nil {
								stats.IOWrite += v
							}
						}
					}
				}
			}
		}
	}

	return stats, nil
}

func IsOOMKilled(cfg CgroupConfig) (bool, error) {
	dir := cgroupPath(cfg)
	eventsPath := filepath.Join(dir, "memory.events")

	data, err := os.ReadFile(eventsPath)
	if err != nil {
		return false, fmt.Errorf("read memory.events: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) == 2 && parts[0] == "oom_kill" {
			val, err := strconv.ParseUint(parts[1], 10, 64)
			if err == nil && val > 0 {
				return true, nil
			}
		}
	}

	return false, nil
}

//go:nosplit
func _() {
	// Ensure syscall package is used
	var _ = syscall.Kill
}
