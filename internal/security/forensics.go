//go:build linux

package security

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	pollInterval          = 10 * time.Millisecond
	emergencyGrowthRatio  = 0.5
	emergencyTimeWindow   = 1 * time.Second
	warningThresholdRatio = 0.8
	forkBombWindow        = 3 * time.Second
	forkBombThreshold     = 15
	linearGrowthSamples   = 20
	linearGrowthTolerance = 0.05
	maxSamples            = 1000
)

type MemoryEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	ContainerID string    `json:"container_id"`
	PID         int       `json:"pid"`
	Type        string    `json:"type"`
	CurrentMB   float64   `json:"current_mb"`
	LimitMB     float64   `json:"limit_mb"`
	GrowthRate  float64   `json:"growth_rate_mb_per_sec"`
	Details     string    `json:"details"`
}

type MemoryProfile struct {
	ContainerID string
	CgroupPath  string
	LimitBytes  int64
	Samples     []MemorySample
	mu          sync.RWMutex
}

type MemorySample struct {
	Timestamp    time.Time
	CurrentBytes int64
}

type CrashReport struct {
	Timestamp     time.Time       `json:"timestamp"`
	ContainerID   string          `json:"container_id"`
	PID           int             `json:"pid"`
	ExitCode      int             `json:"exit_code"`
	Signal        string          `json:"signal"`
	MemoryAtCrash float64         `json:"memory_at_crash_mb"`
	MemoryPeak    float64         `json:"memory_peak_mb"`
	Stderr        string          `json:"stderr"`
	Syscalls      []string        `json:"last_syscalls"`
	LeakedBytes   int64           `json:"leaked_bytes"`
	Duration      time.Duration   `json:"duration"`
	DumpPath      string          `json:"dump_path,omitempty"`
	Analysis      string          `json:"analysis"`
}

type ForensicsEngine struct {
	dumpDir   string
	profiles  map[string]*MemoryProfile
	reports   map[string][]*CrashReport
	callbacks []func(MemoryEvent)
	mu        sync.RWMutex
	stopCh    chan struct{}
}

func NewForensicsEngine(dumpDir string) *ForensicsEngine {
	os.MkdirAll(dumpDir, 0700)
	return &ForensicsEngine{
		dumpDir:  dumpDir,
		profiles: make(map[string]*MemoryProfile),
		reports:  make(map[string][]*CrashReport),
		stopCh:   make(chan struct{}),
	}
}

func (fe *ForensicsEngine) StartMonitoring(containerID, cgroupPath string, limitBytes int64) error {
	memPath := filepath.Join(cgroupPath, "memory.current")
	if _, err := os.Stat(memPath); err != nil {
		return fmt.Errorf("cgroup v2 memory.current not found at %s: %w", memPath, err)
	}

	profile := &MemoryProfile{
		ContainerID: containerID,
		CgroupPath:  cgroupPath,
		LimitBytes:  limitBytes,
		Samples:     make([]MemorySample, 0, 256),
	}

	fe.mu.Lock()
	fe.profiles[containerID] = profile
	fe.mu.Unlock()

	stopCh := make(chan struct{})
	go fe.monitorLoop(profile, stopCh)

	fe.mu.Lock()
	fe.stopCh = stopCh
	fe.mu.Unlock()

	return nil
}

func (fe *ForensicsEngine) StopMonitoring(containerID string) {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	if _, ok := fe.profiles[containerID]; ok {
		close(fe.stopCh)
		delete(fe.profiles, containerID)
	}
}

func (fe *ForensicsEngine) monitorLoop(profile *MemoryProfile, stopCh chan struct{}) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	var lastCurrent int64
	var lastTime time.Time
	var peakBytes int64
	var forkTimestamps []time.Time
	var linearSamples []float64
	var firstSampleTime time.Time

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			currentBytes, err := fe.readMemoryCurrent(profile.CgroupPath)
			if err != nil {
				continue
			}

			now := time.Now()
			profile.mu.Lock()
			profile.Samples = append(profile.Samples, MemorySample{
				Timestamp:    now,
				CurrentBytes: currentBytes,
			})
			if len(profile.Samples) > maxSamples {
				profile.Samples = profile.Samples[len(profile.Samples)-maxSamples:]
			}
			profile.mu.Unlock()

			if currentBytes > peakBytes {
				peakBytes = currentBytes
			}

			currentMB := float64(currentBytes) / (1024 * 1024)
			limitMB := float64(profile.LimitBytes) / (1024 * 1024)

			var growthRate float64
			if !lastTime.IsZero() {
				elapsed := now.Sub(lastTime).Seconds()
				if elapsed > 0 {
					deltaBytes := currentBytes - lastCurrent
					growthRate = (float64(deltaBytes) / (1024 * 1024)) / elapsed
				}
			}

			if lastTime.IsZero() {
				lastTime = now
				lastCurrent = currentBytes
				firstSampleTime = now
				continue
			}

			forkTimestamps = append(forkTimestamps, now)
			if len(forkTimestamps) > forkBombThreshold*2 {
				forkTimestamps = forkTimestamps[len(forkTimestamps)-forkBombThreshold*2:]
			}

			forkCount := 0
			for _, ft := range forkTimestamps {
				if now.Sub(ft) <= forkBombWindow {
					forkCount++
				}
			}
			if forkCount >= forkBombThreshold {
				fe.emitEvent(MemoryEvent{
					Timestamp:   now,
					ContainerID: profile.ContainerID,
					Type:        "fork_bomb",
					CurrentMB:   currentMB,
					LimitMB:     limitMB,
					GrowthRate:  growthRate,
					Details:     fmt.Sprintf("detected %d rapid clones in %v", forkCount, forkBombWindow),
				})
				forkTimestamps = forkTimestamps[:0]
			}

			linearSamples = append(linearSamples, currentMB)
			if len(linearSamples) > linearGrowthSamples {
				linearSamples = linearSamples[len(linearSamples)-linearGrowthSamples:]
			}
			if len(linearSamples) >= linearGrowthSamples {
				if detectLinearGrowth(linearSamples, linearGrowthTolerance) {
					fe.emitEvent(MemoryEvent{
						Timestamp:   now,
						ContainerID: profile.ContainerID,
						Type:        "infinite_allocation_loop",
						CurrentMB:   currentMB,
						LimitMB:     limitMB,
						GrowthRate:  growthRate,
						Details:     "detected linear memory growth pattern suggesting infinite allocation loop",
					})
					linearSamples = linearSamples[:0]
				}
			}

			if profile.LimitBytes > 0 {
				ratio := float64(currentBytes) / float64(profile.LimitBytes)
				elapsedSinceFirst := now.Sub(firstSampleTime).Seconds()

				if ratio >= emergencyGrowthRatio && elapsedSinceFirst < emergencyTimeWindow.Seconds() && elapsedSinceFirst > 0 {
					fe.emitEvent(MemoryEvent{
						Timestamp:   now,
						ContainerID: profile.ContainerID,
						Type:        "emergency",
						CurrentMB:   currentMB,
						LimitMB:     limitMB,
						GrowthRate:  growthRate,
						Details:     fmt.Sprintf("memory reached %.1f%% of limit in %.2fs", ratio*100, elapsedSinceFirst),
					})

					if pid, err := fe.findContainerPID(profile.ContainerID); err == nil {
						dumpPath, dumpErr := fe.CreateDump(profile.ContainerID, pid)
						if dumpErr == nil {
							fe.emitEvent(MemoryEvent{
								Timestamp:   now,
								ContainerID: profile.ContainerID,
								PID:         pid,
								Type:        "dump",
								CurrentMB:   currentMB,
								LimitMB:     limitMB,
								Details:     fmt.Sprintf("emergency dump created at %s", dumpPath),
							})
						}
						unix.Kill(pid, syscall.SIGKILL)
						fe.AnalyzeCrash(profile.ContainerID, pid, 128+9, "", []string{"emergency_kill"})
						return
					}
				}

				if ratio >= warningThresholdRatio && growthRate > 0 {
					if anomaly := fe.detectAnomaly(profile); anomaly != nil {
						anomaly.CurrentMB = currentMB
						anomaly.LimitMB = limitMB
						anomaly.GrowthRate = growthRate
						fe.emitEvent(*anomaly)
					}
				}
			}

			if anomaly := fe.detectAnomaly(profile); anomaly != nil {
				anomaly.CurrentMB = currentMB
				anomaly.LimitMB = limitMB
				anomaly.GrowthRate = growthRate
				fe.emitEvent(*anomaly)
			}

			if profile.LimitBytes > 0 && currentBytes >= profile.LimitBytes {
				fe.emitEvent(MemoryEvent{
					Timestamp:   now,
					ContainerID: profile.ContainerID,
					Type:        "oom",
					CurrentMB:   currentMB,
					LimitMB:     limitMB,
					GrowthRate:  growthRate,
					Details:     "process hit memory limit, OOM kill likely",
				})

				if pid, err := fe.findContainerPID(profile.ContainerID); err == nil {
					dumpPath, dumpErr := fe.CreateDump(profile.ContainerID, pid)
					exitCode := 137
					stderr := fe.readProcStderr(pid)
					syscalls := fe.readLastSyscalls(pid)
					crash := fe.AnalyzeCrash(profile.ContainerID, pid, exitCode, stderr, syscalls)
					if dumpErr == nil {
						crash.DumpPath = dumpPath
					}
					crash.MemoryPeak = float64(peakBytes) / (1024 * 1024)
				}
				return
			}

			lastTime = now
			lastCurrent = currentBytes
		}
	}
}

func (fe *ForensicsEngine) readMemoryCurrent(cgroupPath string) (int64, error) {
	memPath := filepath.Join(cgroupPath, "memory.current")
	data, err := os.ReadFile(memPath)
	if err != nil {
		return 0, fmt.Errorf("failed to read %s: %w", memPath, err)
	}
	val, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse memory.current value %q: %w", string(data), err)
	}
	return val, nil
}

func (fe *ForensicsEngine) detectAnomaly(profile *MemoryProfile) *MemoryEvent {
	profile.mu.RLock()
	defer profile.mu.RUnlock()

	if len(profile.Samples) < 10 {
		return nil
	}

	recent := profile.Samples[len(profile.Samples)-10:]
	var totalDelta int64
	var totalTime float64
	for i := 1; i < len(recent); i++ {
		totalDelta += recent[i].CurrentBytes - recent[i-1].CurrentBytes
		totalTime += recent[i].Timestamp.Sub(recent[i-1].Timestamp).Seconds()
	}

	if totalTime <= 0 {
		return nil
	}

	avgGrowthRate := (float64(totalDelta) / (1024 * 1024)) / totalTime

	var varianceSum float64
	for i := 1; i < len(recent); i++ {
		delta := float64(recent[i].CurrentBytes-recent[i-1].CurrentBytes) / (1024 * 1024)
		elapsed := recent[i].Timestamp.Sub(recent[i-1].Timestamp).Seconds()
		if elapsed > 0 {
			rate := delta / elapsed
			varianceSum += (rate - avgGrowthRate) * (rate - avgGrowthRate)
		}
	}
	stdDev := math.Sqrt(varianceSum / float64(len(recent)-1))

	currentMB := float64(recent[len(recent)-1].CurrentBytes) / (1024 * 1024)
	limitMB := float64(profile.LimitBytes) / (1024 * 1024)

	if avgGrowthRate > 10 && stdDev < avgGrowthRate*0.3 {
		return &MemoryEvent{
			Timestamp:   time.Now(),
			ContainerID: profile.ContainerID,
			Type:        "sustained_growth",
			CurrentMB:   currentMB,
			LimitMB:     limitMB,
			GrowthRate:  avgGrowthRate,
			Details:     fmt.Sprintf("sustained memory growth at %.2f MB/s (stddev %.2f)", avgGrowthRate, stdDev),
		}
	}

	if avgGrowthRate > 100 {
		return &MemoryEvent{
			Timestamp:   time.Now(),
			ContainerID: profile.ContainerID,
			Type:        "rapid_growth",
			CurrentMB:   currentMB,
			LimitMB:     limitMB,
			GrowthRate:  avgGrowthRate,
			Details:     fmt.Sprintf("rapid memory growth detected: %.2f MB/s", avgGrowthRate),
		}
	}

	return nil
}

func (fe *ForensicsEngine) CreateDump(containerID string, pid int) (string, error) {
	dumpDir := filepath.Join(fe.dumpDir, containerID)
	if err := os.MkdirAll(dumpDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create dump directory: %w", err)
	}

	timestamp := time.Now().Format("20060102_150405.000000000")
	dumpPath := filepath.Join(dumpDir, fmt.Sprintf("memory_%s_%d.dump", timestamp, pid))

	if err := fe.createDumpFile(pid, dumpPath); err != nil {
		return "", fmt.Errorf("failed to create memory dump: %w", err)
	}

	return dumpPath, nil
}

func (fe *ForensicsEngine) createDumpFile(pid int, dumpPath string) error {
	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	memFile, err := os.Open(memPath)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", memPath, err)
	}
	defer memFile.Close()

	mapPath := fmt.Sprintf("/proc/%d/maps", pid)
	mapData, err := os.ReadFile(mapPath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", mapPath, err)
	}

	dumpFile, err := os.Create(dumpPath)
	if err != nil {
		return fmt.Errorf("failed to create dump file %s: %w", dumpPath, err)
	}
	defer dumpFile.Close()

	dumpFile.WriteString("MEMORY DUMP HEADER\n")
	dumpFile.WriteString(fmt.Sprintf("PID: %d\n", pid))
	dumpFile.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format(time.RFC3339Nano)))
	dumpFile.WriteString(fmt.Sprintf("Maps file: %s\n", mapPath))
	dumpFile.WriteString("END HEADER\n\n")

	scanner := bufio.NewScanner(strings.NewReader(string(mapData)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}

		addrRange := strings.Split(parts[0], "-")
		if len(addrRange) != 2 {
			continue
		}

		startAddr, err := strconv.ParseUint(addrRange[0], 16, 64)
		if err != nil {
			continue
		}
		endAddr, err := strconv.ParseUint(addrRange[1], 16, 64)
		if err != nil {
			continue
		}

		perms := parts[1]
		if !strings.Contains(perms, "r") {
			continue
		}

		regionSize := endAddr - startAddr
		if regionSize == 0 || regionSize > 128*1024*1024 {
			continue
		}

		dumpFile.WriteString(fmt.Sprintf("\n--- REGION: %s (%s) size=%d ---\n", parts[0], perms, regionSize))

		buf := make([]byte, regionSize)
		n, err := memFile.ReadAt(buf, int64(startAddr))
		if n > 0 {
			dumpFile.Write(buf[:n])
		}
		_ = err
	}

	smapsPath := fmt.Sprintf("/proc/%d/smaps", pid)
	if smapsData, err := os.ReadFile(smapsPath); err == nil {
		dumpFile.WriteString("\n--- SMAPS DATA ---\n")
		dumpFile.Write(smapsData)
	}

	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	if statusData, err := os.ReadFile(statusPath); err == nil {
		dumpFile.WriteString("\n--- STATUS DATA ---\n")
		dumpFile.Write(statusData)
	}

	dumpInfo, err := dumpFile.Stat()
	if err == nil {
		fmt.Fprintf(os.Stderr, "forensics: dump written: %s (%d bytes)\n", dumpPath, dumpInfo.Size())
	}

	return nil
}

func (fe *ForensicsEngine) AnalyzeCrash(containerID string, pid int, exitCode int, stderr string, syscalls []string) *CrashReport {
	report := &CrashReport{
		Timestamp:   time.Now(),
		ContainerID: containerID,
		PID:         pid,
		ExitCode:     exitCode,
		Stderr:       stderr,
		Syscalls:     syscalls,
	}

	if exitCode > 128 {
		sig := exitCode - 128
		report.Signal = signalName(sig)
	}

	memAtCrash, err := fe.readMemoryCurrentForPID(pid)
	if err == nil {
		report.MemoryAtCrash = float64(memAtCrash) / (1024 * 1024)
	}

	peakBytes := fe.findPeakMemory(containerID)
	report.MemoryPeak = float64(peakBytes) / (1024 * 1024)

	if report.MemoryPeak > 0 && report.MemoryAtCrash > 0 {
		report.LeakedBytes = int64(report.MemoryAtCrash * 1024 * 1024)
	}

	fe.mu.RLock()
	profiles := fe.profiles
	fe.mu.RUnlock()
	if profile, ok := profiles[containerID]; ok {
		profile.mu.RLock()
		if len(profile.Samples) > 1 {
			first := profile.Samples[0]
			last := profile.Samples[len(profile.Samples)-1]
			report.Duration = last.Timestamp.Sub(first.Timestamp)
		}
		profile.mu.RUnlock()
	}

	if len(syscalls) > 0 {
		report.Analysis = fe.analyzeSyscallPattern(syscalls, report)
	} else if exitCode == 137 {
		report.Analysis = "Process killed by OOM killer or external SIGKILL. Memory at time of death exceeded cgroup limit."
	} else {
		report.Analysis = fmt.Sprintf("Process exited with code %d. Signal: %s. No syscall data available.", exitCode, report.Signal)
	}

	fe.mu.Lock()
	fe.reports[containerID] = append(fe.reports[containerID], report)
	fe.mu.Unlock()

	return report
}

func (fe *ForensicsEngine) analyzeSyscallPattern(syscalls []string, report *CrashReport) string {
	var analysis []string

	mmapCount := 0
	brkCount := 0
	cloneCount := 0
	killCount := 0

	for _, sc := range syscalls {
		switch {
		case strings.Contains(sc, "mmap") || strings.Contains(sc, "mprotect"):
			mmapCount++
		case strings.Contains(sc, "brk") || strings.Contains(sc, "sbrk"):
			brkCount++
		case strings.Contains(sc, "clone") || strings.Contains(sc, "fork") || strings.Contains(sc, "vfork"):
			cloneCount++
		case strings.Contains(sc, "kill") || strings.Contains(sc, "tgkill"):
			killCount++
		}
	}

	if mmapCount > 5 {
		analysis = append(analysis, fmt.Sprintf("High mmap/mprotect activity (%d calls) suggests heavy memory mapping", mmapCount))
	}
	if brkCount > 3 {
		analysis = append(analysis, fmt.Sprintf("Repeated brk/sbrk calls (%d) indicating heap expansion", brkCount))
	}
	if cloneCount > 10 {
		analysis = append(analysis, fmt.Sprintf("Excessive clone/fork calls (%d) suggests possible fork bomb or thread explosion", cloneCount))
	}
	if killCount > 0 {
		analysis = append(analysis, fmt.Sprintf("Process sent %d kill signals before dying", killCount))
	}

	if report.ExitCode == 137 {
		analysis = append(analysis, "Process was OOM-killed (exit code 137 = SIGKILL)")
	}

	if len(analysis) == 0 {
		return fmt.Sprintf("Syscall pattern analysis inconclusive. Last syscalls: %s", strings.Join(syscalls, ", "))
	}

	return strings.Join(analysis, "; ")
}

func (fe *ForensicsEngine) readMemoryCurrentForPID(pid int) (int64, error) {
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return 0, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val, err := strconv.ParseInt(fields[1], 10, 64)
				if err == nil {
					return val * 1024, nil
				}
			}
		}
	}

	return 0, fmt.Errorf("VmRSS not found in /proc/%d/status", pid)
}

func (fe *ForensicsEngine) findPeakMemory(containerID string) int64 {
	fe.mu.RLock()
	profile, ok := fe.profiles[containerID]
	fe.mu.RUnlock()
	if !ok {
		return 0
	}

	profile.mu.RLock()
	defer profile.mu.RUnlock()

	var peak int64
	for _, s := range profile.Samples {
		if s.CurrentBytes > peak {
			peak = s.CurrentBytes
		}
	}
	return peak
}

func (fe *ForensicsEngine) findContainerPID(containerID string) (int, error) {
	cgroupPath := filepath.Join("/sys/fs/cgroup", containerID)
	procsPath := filepath.Join(cgroupPath, "cgroup.procs")

	data, err := os.ReadFile(procsPath)
	if err != nil {
		return 0, fmt.Errorf("failed to read cgroup.procs for %s: %w", containerID, err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return 0, fmt.Errorf("no processes found in cgroup %s", containerID)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(lines[0]))
	if err != nil {
		return 0, fmt.Errorf("failed to parse PID from cgroup.procs: %w", err)
	}

	return pid, nil
}

func (fe *ForensicsEngine) readProcStderr(pid int) string {
	fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return ""
	}

	for _, fd := range fds {
		link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name()))
		if err != nil {
			continue
		}
		if strings.Contains(link, "pipe:") {
			continue
		}
		if strings.Contains(link, "socket:") {
			continue
		}
	}

	logPath := fmt.Sprintf("/proc/%d/fd/2", pid)
	data, err := os.ReadFile(logPath)
	if err != nil {
		return ""
	}

	if len(data) > 4096 {
		data = data[len(data)-4096:]
	}
	return string(data)
}

func (fe *ForensicsEngine) readLastSyscalls(pid int) []string {
	syscallPath := fmt.Sprintf("/proc/%d/syscall", pid)
	data, err := os.ReadFile(syscallPath)
	if err != nil {
		return nil
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var syscalls []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			syscalls = append(syscalls, line)
		}
	}
	return syscalls
}

func (fe *ForensicsEngine) GetReport(containerID string) *CrashReport {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	reports, ok := fe.reports[containerID]
	if !ok || len(reports) == 0 {
		return nil
	}
	return reports[len(reports)-1]
}

func (fe *ForensicsEngine) GetAllReports() map[string][]*CrashReport {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	result := make(map[string][]*CrashReport, len(fe.reports))
	for k, v := range fe.reports {
		result[k] = v
	}
	return result
}

func (fe *ForensicsEngine) AddCallback(fn func(MemoryEvent)) {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	fe.callbacks = append(fe.callbacks, fn)
}

func (fe *ForensicsEngine) emitEvent(event MemoryEvent) {
	fe.mu.RLock()
	callbacks := make([]func(MemoryEvent), len(fe.callbacks))
	copy(callbacks, fe.callbacks)
	fe.mu.RUnlock()

	for _, cb := range callbacks {
		cb(event)
	}
}

func detectLinearGrowth(samples []float64, tolerance float64) bool {
	if len(samples) < 4 {
		return false
	}

	n := float64(len(samples))
	var sumX, sumY, sumXY, sumX2 float64
	for i, y := range samples {
		x := float64(i)
		sumX += x
		sumY += y
		sumXY += x * y
		sumX2 += x * x
	}

	denom := n*sumX2 - sumX*sumX
	if math.Abs(denom) < 1e-10 {
		return false
	}

	slope := (n*sumXY - sumX*sumY) / denom
	intercept := (sumY - slope*sumX) / n

	if slope <= 0 {
		return false
	}

	var ssRes, ssTot float64
	meanY := sumY / n
	for i, y := range samples {
		x := float64(i)
		predicted := slope*x + intercept
		ssRes += (y - predicted) * (y - predicted)
		ssTot += (y - meanY) * (y - meanY)
	}

	if ssTot < 1e-10 {
		return false
	}

	rSquared := 1.0 - ssRes/ssTot
	return rSquared >= (1.0-tolerance) && slope > 0.5
}

func signalName(sig int) string {
	signals := map[int]string{
		int(syscall.SIGHUP):    "SIGHUP",
		int(syscall.SIGINT):    "SIGINT",
		int(syscall.SIGQUIT):   "SIGQUIT",
		int(syscall.SIGILL):    "SIGILL",
		int(syscall.SIGTRAP):   "SIGTRAP",
		int(syscall.SIGABRT):   "SIGABRT",
		int(syscall.SIGBUS):    "SIGBUS",
		int(syscall.SIGFPE):    "SIGFPE",
		int(syscall.SIGKILL):   "SIGKILL",
		int(syscall.SIGUSR1):   "SIGUSR1",
		int(syscall.SIGSEGV):   "SIGSEGV",
		int(syscall.SIGUSR2):   "SIGUSR2",
		int(syscall.SIGPIPE):   "SIGPIPE",
		int(syscall.SIGALRM):   "SIGALRM",
		int(syscall.SIGTERM):   "SIGTERM",
		int(syscall.SIGSTKFLT): "SIGSTKFLT",
		int(syscall.SIGCHLD):   "SIGCHLD",
		int(syscall.SIGCONT):   "SIGCONT",
		int(syscall.SIGSTOP):   "SIGSTOP",
		int(syscall.SIGTSTP):   "SIGTSTP",
		int(syscall.SIGTTIN):   "SIGTTIN",
		int(syscall.SIGTTOU):   "SIGTTOU",
		int(syscall.SIGURG):    "SIGURG",
		int(syscall.SIGXCPU):   "SIGXCPU",
		int(syscall.SIGXFSZ):   "SIGXFSZ",
		int(syscall.SIGVTALRM): "SIGVTALRM",
		int(syscall.SIGPROF):   "SIGPROF",
		int(syscall.SIGWINCH):  "SIGWINCH",
		int(syscall.SIGIO):     "SIGIO",
		int(syscall.SIGPWR):    "SIGPWR",
		int(syscall.SIGSYS):    "SIGSYS",
	}

	if name, ok := signals[sig]; ok {
		return name
	}
	return fmt.Sprintf("SIG(%d)", sig)
}

func (fe *ForensicsEngine) ExportCrashReport(containerID string, path string) error {
	fe.mu.RLock()
	reports, ok := fe.reports[containerID]
	fe.mu.RUnlock()

	if !ok || len(reports) == 0 {
		return fmt.Errorf("no crash reports found for container %s", containerID)
	}

	sort.Slice(reports, func(i, j int) bool {
		return reports[i].Timestamp.After(reports[j].Timestamp)
	})

	data, err := json.MarshalIndent(reports, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal crash reports: %w", err)
	}

	return os.WriteFile(path, data, 0600)
}

func (fe *ForensicsEngine) GetMemoryProfile(containerID string) *MemoryProfile {
	fe.mu.RLock()
	defer fe.mu.RUnlock()
	return fe.profiles[containerID]
}

func (fe *ForensicsEngine) GetMemorySamples(containerID string) []MemorySample {
	profile := fe.GetMemoryProfile(containerID)
	if profile == nil {
		return nil
	}

	profile.mu.RLock()
	defer profile.mu.RUnlock()

	result := make([]MemorySample, len(profile.Samples))
	copy(result, profile.Samples)
	return result
}

func (fe *ForensicsEngine) GetGrowthRate(containerID string, windowSize int) float64 {
	profile := fe.GetMemoryProfile(containerID)
	if profile == nil {
		return 0
	}

	profile.mu.RLock()
	defer profile.mu.RUnlock()

	if len(profile.Samples) < 2 {
		return 0
	}

	if windowSize <= 0 || windowSize > len(profile.Samples) {
		windowSize = len(profile.Samples)
	}

	start := len(profile.Samples) - windowSize
	if start < 0 {
		start = 0
	}
	window := profile.Samples[start:]

	var totalDelta int64
	var totalTime float64
	for i := 1; i < len(window); i++ {
		totalDelta += window[i].CurrentBytes - window[i-1].CurrentBytes
		totalTime += window[i].Timestamp.Sub(window[i-1].Timestamp).Seconds()
	}

	if totalTime <= 0 {
		return 0
	}

	return (float64(totalDelta) / (1024 * 1024)) / totalTime
}

func (fe *ForensicsEngine) ForceDump(containerID string, pid int) (string, error) {
	return fe.CreateDump(containerID, pid)
}

func (fe *ForensicsEngine) ReadCgroupLimits(cgroupPath string) (limitBytes, usageBytes int64, err error) {
	limitPath := filepath.Join(cgroupPath, "memory.max")
	data, err := os.ReadFile(limitPath)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read memory.max: %w", err)
	}

	limitStr := strings.TrimSpace(string(data))
	if limitStr == "max" {
		limitBytes = math.MaxInt64
	} else {
		limitBytes, err = strconv.ParseInt(limitStr, 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("failed to parse memory.max: %w", err)
		}
	}

	usagePath := filepath.Join(cgroupPath, "memory.current")
	data, err = os.ReadFile(usagePath)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read memory.current: %w", err)
	}

	usageBytes, err = strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse memory.current: %w", err)
	}

	return limitBytes, usageBytes, nil
}

func (fe *ForensicsEngine) DetectMemoryStall(containerID string, stallThreshold time.Duration) bool {
	profile := fe.GetMemoryProfile(containerID)
	if profile == nil {
		return false
	}

	profile.mu.RLock()
	defer profile.mu.RUnlock()

	if len(profile.Samples) < 2 {
		return false
	}

	last := profile.Samples[len(profile.Samples)-1]
	return time.Since(last.Timestamp) > stallThreshold
}

func (fe *ForensicsEngine) GetProcessMemoryMap(pid int) (map[string]int64, error) {
	mapPath := fmt.Sprintf("/proc/%d/smaps", pid)
	data, err := os.ReadFile(mapPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", mapPath, err)
	}

	result := make(map[string]int64)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	var currentRegion string

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			parts := strings.Fields(line)
			if len(parts) >= 6 {
				currentRegion = strings.Join(parts[5:], " ")
				if _, exists := result[currentRegion]; !exists {
					result[currentRegion] = 0
				}
			}
		} else if strings.HasPrefix(line, "Size:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val, err := strconv.ParseInt(fields[1], 10, 64)
				if err == nil {
					result[currentRegion] += val * 1024
				}
			}
		}
	}

	return result, nil
}

func (fe *ForensicsEngine) IsProcessAlive(pid int) bool {
	return unix.Kill(pid, 0) == nil
}

func (fe *ForensicsEngine) GetProcessInfo(pid int) (map[string]string, error) {
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", statusPath, err)
	}

	result := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			result[key] = val
		}
	}

	return result, nil
}

func (fe *ForensicsEngine) MonitorAllContainers(cgroupRoot string) error {
	entries, err := os.ReadDir(cgroupRoot)
	if err != nil {
		return fmt.Errorf("failed to read cgroup root %s: %w", cgroupRoot, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		containerID := entry.Name()
		cgroupPath := filepath.Join(cgroupRoot, containerID)

		_, usage, err := fe.ReadCgroupLimits(cgroupPath)
		if err != nil {
			continue
		}

		limitPath := filepath.Join(cgroupPath, "memory.max")
		limitData, err := os.ReadFile(limitPath)
		if err != nil {
			continue
		}

		limitStr := strings.TrimSpace(string(limitData))
		var limitBytes int64
		if limitStr == "max" {
			limitBytes = usage * 2
		} else {
			limitBytes, err = strconv.ParseInt(limitStr, 10, 64)
			if err != nil {
				continue
			}
		}

		_ = fe.StartMonitoring(containerID, cgroupPath, limitBytes)
	}

	return nil
}

func (fe *ForensicsEngine) GetEngineStats() map[string]interface{} {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	stats := map[string]interface{}{
		"monitored_containers": len(fe.profiles),
		"total_crash_reports":  0,
		"callback_count":       len(fe.callbacks),
	}

	totalReports := 0
	for _, reports := range fe.reports {
		totalReports += len(reports)
	}
	stats["total_crash_reports"] = totalReports

	sampleCounts := make(map[string]int)
	for id, profile := range fe.profiles {
		profile.mu.RLock()
		sampleCounts[id] = len(profile.Samples)
		profile.mu.RUnlock()
	}
	stats["sample_counts"] = sampleCounts

	return stats
}

func (fe *ForensicsEngine) CleanupOldDumps(maxAge time.Duration) (int, error) {
	cutoff := time.Now().Add(-maxAge)
	removed := 0

	entries, err := os.ReadDir(fe.dumpDir)
	if err != nil {
		return 0, fmt.Errorf("failed to read dump directory: %w", err)
	}

	for _, entry := range entries {
		entryPath := filepath.Join(fe.dumpDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			if err := os.RemoveAll(entryPath); err == nil {
				removed++
			}
		}
	}

	return removed, nil
}

func (fe *ForensicsEngine) SetDumpDir(dumpDir string) {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	os.MkdirAll(dumpDir, 0700)
	fe.dumpDir = dumpDir
}

func (fe *ForensicsEngine) GenerateSummary(containerID string) string {
	fe.mu.RLock()
	profile, hasProfile := fe.profiles[containerID]
	reports, hasReports := fe.reports[containerID]
	fe.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Memory Forensics Summary: %s ===\n", containerID))
	sb.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().Format(time.RFC3339)))

	if hasProfile {
		profile.mu.RLock()
		sb.WriteString(fmt.Sprintf("Monitoring active: Yes\n"))
		sb.WriteString(fmt.Sprintf("Cgroup path: %s\n", profile.CgroupPath))
		sb.WriteString(fmt.Sprintf("Memory limit: %d MB\n", profile.LimitBytes/(1024*1024)))
		sb.WriteString(fmt.Sprintf("Total samples: %d\n", len(profile.Samples)))

		if len(profile.Samples) > 0 {
			var peak int64
			for _, s := range profile.Samples {
				if s.CurrentBytes > peak {
					peak = s.CurrentBytes
				}
			}
			first := profile.Samples[0]
			last := profile.Samples[len(profile.Samples)-1]
			sb.WriteString(fmt.Sprintf("First sample: %s (%d MB)\n", first.Timestamp.Format(time.RFC3339), first.CurrentBytes/(1024*1024)))
			sb.WriteString(fmt.Sprintf("Last sample: %s (%d MB)\n", last.Timestamp.Format(time.RFC3339), last.CurrentBytes/(1024*1024)))
			sb.WriteString(fmt.Sprintf("Peak usage: %d MB\n", peak/(1024*1024)))
			sb.WriteString(fmt.Sprintf("Monitoring duration: %s\n", last.Timestamp.Sub(first.Timestamp)))
		}
		profile.mu.RUnlock()
	} else {
		sb.WriteString("Monitoring active: No\n")
	}

	sb.WriteString("\n")

	if hasReports && len(reports) > 0 {
		sb.WriteString(fmt.Sprintf("Total crash reports: %d\n\n", len(reports)))
		for i, r := range reports {
			sb.WriteString(fmt.Sprintf("--- Report #%d ---\n", i+1))
			sb.WriteString(fmt.Sprintf("  Time: %s\n", r.Timestamp.Format(time.RFC3339)))
			sb.WriteString(fmt.Sprintf("  PID: %d\n", r.PID))
			sb.WriteString(fmt.Sprintf("  Exit code: %d\n", r.ExitCode))
			if r.Signal != "" {
				sb.WriteString(fmt.Sprintf("  Signal: %s\n", r.Signal))
			}
			sb.WriteString(fmt.Sprintf("  Memory at crash: %.2f MB\n", r.MemoryAtCrash))
			sb.WriteString(fmt.Sprintf("  Peak memory: %.2f MB\n", r.MemoryPeak))
			if r.DumpPath != "" {
				sb.WriteString(fmt.Sprintf("  Dump: %s\n", r.DumpPath))
			}
			sb.WriteString(fmt.Sprintf("  Duration: %s\n", r.Duration))
			sb.WriteString(fmt.Sprintf("  Analysis: %s\n\n", r.Analysis))
		}
	} else {
		sb.WriteString("No crash reports recorded.\n")
	}

	return sb.String()
}

func (fe *ForensicsEngine) RecordOOMKill(containerID string, pid int) *CrashReport {
	stderr := fe.readProcStderr(pid)
	syscalls := fe.readLastSyscalls(pid)
	report := fe.AnalyzeCrash(containerID, pid, 137, stderr, syscalls)

	fe.emitEvent(MemoryEvent{
		Timestamp:   time.Now(),
		ContainerID: containerID,
		PID:         pid,
		Type:        "oom",
		CurrentMB:   report.MemoryAtCrash,
		LimitMB:     float64(report.MemoryPeak),
		Details:     "OOM kill recorded",
	})

	return report
}

func (fe *ForensicsEngine) ReadProcMaps(pid int) ([]uintptr, error) {
	mapPath := fmt.Sprintf("/proc/%d/maps", pid)
	data, err := os.ReadFile(mapPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", mapPath, err)
	}

	var regions []uintptr
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) < 1 {
			continue
		}
		addrs := strings.Split(parts[0], "-")
		if len(addrs) != 2 {
			continue
		}
		addr, err := strconv.ParseUint(addrs[0], 16, 64)
		if err != nil {
			continue
		}
		regions = append(regions, uintptr(addr))
	}

	return regions, nil
}

func (fe *ForensicsEngine) GetMemoryUsagePercent(containerID string) float64 {
	fe.mu.RLock()
	profile, ok := fe.profiles[containerID]
	fe.mu.RUnlock()

	if !ok || profile.LimitBytes <= 0 {
		return 0
	}

	profile.mu.RLock()
	defer profile.mu.RUnlock()

	if len(profile.Samples) == 0 {
		return 0
	}

	last := profile.Samples[len(profile.Samples)-1]
	return (float64(last.CurrentBytes) / float64(profile.LimitBytes)) * 100
}

func (fe *ForensicsEngine) CheckMemoryHealth(containerID string) (string, float64) {
	profile := fe.GetMemoryProfile(containerID)
	if profile == nil {
		return "unknown", 0
	}

	percent := fe.GetMemoryUsagePercent(containerID)
	growthRate := fe.GetGrowthRate(containerID, 100)

	switch {
	case percent >= 95:
		return "critical", percent
	case percent >= 80:
		if growthRate > 10 {
			return "degraded", percent
		}
		return "warning", percent
	case percent >= 50:
		return "healthy", percent
	default:
		return "nominal", percent
	}
}
