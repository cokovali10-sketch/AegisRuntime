//go:build linux

package security

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// CrashAnalysis holds detailed crash analysis results
type CrashAnalysis struct {
	Timestamp        time.Time     `json:"timestamp"`
	ContainerID      string        `json:"container_id"`
	PID              int           `json:"pid"`
	ExitCode         int           `json:"exit_code"`
	Signal           string        `json:"signal"`
	ExitReason       string        `json:"exit_reason"`
	Stderr           string        `json:"stderr"`
	Stdout           string        `json:"stdout"`
	LastSyscalls     []string      `json:"last_syscalls"`
	SeccompViolations []string     `json:"seccomp_violations"`
	MemoryAtCrash    float64       `json:"memory_at_crash_mb"`
	CPUDuration      time.Duration `json:"cpu_duration"`
	Diagnosis        string        `json:"diagnosis"`
	FixSuggestions   []string      `json:"fix_suggestions"`
	Severity         string        `json:"severity"`
	Category         string        `json:"category"`
}

// DiagnosisRule defines a pattern matching rule for crash diagnosis
type DiagnosisRule struct {
	Name        string
	Pattern     string
	Category    string
	Severity    string
	Diagnosis   string
	Suggestions []string
}

// SelfHealer implements crash analysis and self-healing capabilities
type SelfHealer struct {
	dumpDir    string
	reportsDir string
	rules      []DiagnosisRule
	reports    map[string][]*CrashAnalysis
}

// NewSelfHealer creates a new self-healing engine
func NewSelfHealer(dumpDir, reportsDir string) *SelfHealer {
	os.MkdirAll(dumpDir, 0700)
	os.MkdirAll(reportsDir, 0700)

	sh := &SelfHealer{
		dumpDir:    dumpDir,
		reportsDir: reportsDir,
		rules:      initDiagnosisRules(),
		reports:    make(map[string][]*CrashAnalysis),
	}

	sh.loadExistingReports()
	return sh
}

// AnalyzeCrash performs full crash analysis
func (sh *SelfHealer) AnalyzeCrash(containerID string, pid int, exitCode int, stderr string, stdout string, syscalls []string) *CrashAnalysis {
	analysis := &CrashAnalysis{
		Timestamp:   time.Now().UTC(),
		ContainerID: containerID,
		PID:         pid,
		ExitCode:    exitCode,
		Stderr:      stderr,
		Stdout:      stdout,
		LastSyscalls: syscalls,
	}

	if sig := categorizeExitCode(exitCode); sig != "" {
		analysis.Signal = sig
	}

	analysis.Category, analysis.Severity, analysis.ExitReason = categorizeSignal(analysis.Signal)

	if isCompilationError(stderr) {
		analysis.Category = "compilation"
		analysis.Severity = "high"
		analysis.Diagnosis = "Compilation error detected"
		analysis.FixSuggestions = parseCompilationErrors(stderr)
	} else if isRuntimePanic(stderr) {
		analysis.Category = "panic"
		analysis.Severity = "critical"
		analysis.Diagnosis = "Runtime panic detected"
		analysis.FixSuggestions = parseRuntimePanic(stderr)
	} else if isPythonTraceback(stderr) {
		analysis.Category = "runtime"
		analysis.Severity = "high"
		analysis.Diagnosis = "Python runtime error detected"
		analysis.FixSuggestions = parsePythonTraceback(stderr)
	} else {
		analysis.Diagnosis, analysis.FixSuggestions = sh.DiagnoseError(stderr, syscalls)
	}

	analysis.SeccompViolations = extractSeccompViolations(stderr)

	sh.reports[containerID] = append(sh.reports[containerID], analysis)
	return analysis
}

// DiagnoseError runs diagnosis rules against stderr
func (sh *SelfHealer) DiagnoseError(stderr string, syscalls []string) (string, []string) {
	var diagnosis strings.Builder
	var suggestions []string

	for _, rule := range sh.rules {
		if matchRule(stderr, rule) {
			if diagnosis.Len() > 0 {
				diagnosis.WriteString("; ")
			}
			diagnosis.WriteString(rule.Diagnosis)
			suggestions = append(suggestions, rule.Suggestions...)
		}
	}

	if len(syscalls) > 0 {
		for _, sc := range syscalls {
			if strings.Contains(sc, "seccomp") || strings.Contains(sc, "EPERM") {
				diagnosis.WriteString("; Seccomp violation detected")
				suggestions = append(suggestions, "Add blocked syscall to seccomp allowlist", "Use alternative syscall")
				break
			}
		}
	}

	if diagnosis.Len() == 0 {
		diagnosis.WriteString("Unknown error")
		suggestions = append(suggestions, "Check application logs", "Review resource limits")
	}

	return diagnosis.String(), uniqueSuggestions(suggestions)
}

// GenerateReport generates a JSON report
func (sh *SelfHealer) GenerateReport(analysis *CrashAnalysis) (string, error) {
	data, err := json.MarshalIndent(analysis, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal analysis: %w", err)
	}
	return string(data), nil
}

// SaveReport saves report to disk
func (sh *SelfHealer) SaveReport(analysis *CrashAnalysis) error {
	report, err := sh.GenerateReport(analysis)
	if err != nil {
		return err
	}

	filename := fmt.Sprintf("%s_%s_%d.json",
		analysis.ContainerID,
		analysis.Timestamp.Format("20060102_150405"),
		analysis.PID)
	reportPath := filepath.Join(sh.reportsDir, filename)

	return os.WriteFile(reportPath, []byte(report), 0600)
}

// GetReport retrieves a report
func (sh *SelfHealer) GetReport(containerID string) *CrashAnalysis {
	reports := sh.reports[containerID]
	if len(reports) == 0 {
		return nil
	}
	return reports[len(reports)-1]
}

// GetAgentReport formats report for LLM consumption
func (sh *SelfHealer) GetAgentReport(analysis *CrashAnalysis) string {
	var sb strings.Builder

	sb.WriteString("## Crash Analysis Report\n\n")
	sb.WriteString(fmt.Sprintf("**Container:** %s\n", analysis.ContainerID))
	sb.WriteString(fmt.Sprintf("**PID:** %d\n", analysis.PID))
	sb.WriteString(fmt.Sprintf("**Exit Code:** %d\n", analysis.ExitCode))
	sb.WriteString(fmt.Sprintf("**Signal:** %s\n", analysis.Signal))
	sb.WriteString(fmt.Sprintf("**Category:** %s\n", analysis.Category))
	sb.WriteString(fmt.Sprintf("**Severity:** %s\n", analysis.Severity))
	sb.WriteString(fmt.Sprintf("**Timestamp:** %s\n\n", analysis.Timestamp.Format(time.RFC3339)))

	sb.WriteString("### Diagnosis\n")
	sb.WriteString(analysis.Diagnosis + "\n\n")

	if len(analysis.FixSuggestions) > 0 {
		sb.WriteString("### Suggested Fixes\n")
		for i, suggestion := range analysis.FixSuggestions {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, suggestion))
		}
		sb.WriteString("\n")
	}

	if len(analysis.SeccompViolations) > 0 {
		sb.WriteString("### Seccomp Violations\n")
		for _, v := range analysis.SeccompViolations {
			sb.WriteString(fmt.Sprintf("- %s\n", v))
		}
		sb.WriteString("\n")
	}

	if analysis.Stderr != "" {
		sb.WriteString("### Stderr (last 500 chars)\n```\n")
		if len(analysis.Stderr) > 500 {
			sb.WriteString(analysis.Stderr[len(analysis.Stderr)-500:])
		} else {
			sb.WriteString(analysis.Stderr)
		}
		sb.WriteString("\n```\n")
	}

	return sb.String()
}

// GetRetryHint generates retry instructions for the AI agent
func (sh *SelfHealer) GetRetryHint(analysis *CrashAnalysis) string {
	var hints []string

	switch analysis.Category {
	case "segfault":
		hints = append(hints,
			"Check for null pointer dereferences in the code",
			"Verify array bounds before access",
			"Ensure proper memory alignment for struct access",
			"Review pointer arithmetic for correctness")
	case "oom":
		hints = append(hints,
			"Reduce memory allocation in the application",
			"Increase container memory limit",
			"Check for memory leaks",
			"Use streaming processing for large datasets")
	case "seccomp":
		hints = append(hints,
			"Add blocked syscall to seccomp profile allowlist",
			"Find alternative syscall for the operation",
			"Check if the syscall is needed for the task")
	case "timeout":
		hints = append(hints,
			"Optimize algorithm complexity",
			"Reduce I/O operations",
			"Increase timeout value if operation is expected to be slow",
			"Add caching for repeated operations")
	case "panic":
		hints = append(hints,
			"Review panic message for specific error type",
			"Add proper error handling",
			"Check for nil pointer usage",
			"Verify slice/map bounds")
	case "compilation":
		hints = append(hints,
			"Fix syntax errors identified in the build output",
			"Ensure all dependencies are available",
			"Check for type mismatches",
			"Verify import paths")
	case "runtime":
		hints = append(hints,
			"Check application logs for runtime errors",
			"Verify runtime dependencies are installed",
			"Check for unhandled exceptions")
	default:
		hints = append(hints,
			"Review application logs",
			"Check resource limits",
			"Verify configuration")
	}

	if len(hints) == 0 {
		return "No specific retry hints available. Review logs and try again."
	}

	var sb strings.Builder
	sb.WriteString("### Retry Instructions\n\n")
	for i, hint := range hints {
		sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, hint))
	}

	return sb.String()
}

// initDiagnosisRules initializes the rule engine
func initDiagnosisRules() []DiagnosisRule {
	return []DiagnosisRule{
		{
			Name:     "segfault_null_pointer",
			Pattern:  `SIGSEGV.*NULL|signal 11.*NULL|segmentation fault.*0x0+`,
			Category: "segfault",
			Severity: "critical",
			Diagnosis: "Segmentation fault: null pointer dereference",
			Suggestions: []string{
				"Add null pointer check before dereferencing",
				"Verify pointer initialization",
				"Use optional chaining or nil guards",
			},
		},
		{
			Name:     "segfault_address",
			Pattern:  `SIGSEGV|signal 11|segmentation fault`,
			Category: "segfault",
			Severity: "critical",
			Diagnosis: "Segmentation fault at invalid memory address",
			Suggestions: []string{
				"Check array bounds before access",
				"Verify memory alignment for struct access",
				"Review pointer arithmetic for correctness",
				"Check for use-after-free bugs",
			},
		},
		{
			Name:     "sigabrt",
			Pattern:  `SIGABRT|signal 6|Aborted|abort\(\)`,
			Category: "segfault",
			Severity: "critical",
			Diagnosis: "Process aborted (assertion failure or double free)",
			Suggestions: []string{
				"Check for assertion failures in code",
				"Look for double-free memory bugs",
				"Verify heap memory integrity",
				"Check for stack overflow",
			},
		},
		{
			Name:     "sigbus",
			Pattern:  `SIGBUS|signal 7|Bus error`,
			Category: "segfault",
			Severity: "critical",
			Diagnosis: "Bus error: memory alignment or mmap failure",
			Suggestions: []string{
				"Ensure proper memory alignment",
				"Check if memory-mapped file is valid",
				"Verify file size matches mapped region",
				"Use aligned memory allocation",
			},
		},
		{
			Name:     "oom_killed",
			Pattern:  `Out of memory|OOM|oom-kill|memory cgroup|Cannot allocate memory`,
			Category: "oom",
			Severity: "critical",
			Diagnosis: "Out of memory: process killed by OOM killer",
			Suggestions: []string{
				"Reduce memory allocation in application",
				"Increase container memory limit",
				"Check for memory leaks",
				"Use streaming processing for large datasets",
				"Optimize data structures for memory efficiency",
			},
		},
		{
			Name:     "seccomp_violation",
			Pattern:  `Operation not permitted|seccomp|SECCOMP|EPERM|permission denied.*syscall`,
			Category: "seccomp",
			Severity: "high",
			Diagnosis: "Seccomp violation: blocked syscall",
			Suggestions: []string{
				"Add blocked syscall to seccomp allowlist",
				"Use alternative syscall for the operation",
				"Review seccomp profile for missing syscalls",
				"Check if the operation requires elevated privileges",
			},
		},
		{
			Name:     "timeout_deadline",
			Pattern:  `context deadline exceeded|timeout|deadline exceeded|ETIMEDOUT`,
			Category: "timeout",
			Severity: "medium",
			Diagnosis: "Operation timeout: context deadline exceeded",
			Suggestions: []string{
				"Optimize algorithm complexity",
				"Reduce I/O operations",
				"Increase timeout value if operation is expected to be slow",
				"Add caching for repeated operations",
				"Use async processing for long-running tasks",
			},
		},
		{
			Name:     "go_panic_index",
			Pattern:  `runtime error: index out of range`,
			Category: "panic",
			Severity: "critical",
			Diagnosis: "Go panic: index out of range",
			Suggestions: []string{
				"Check slice/map length before accessing",
				"Add bounds checking before index access",
				"Use safe index access patterns",
			},
		},
		{
			Name:     "go_panic_nil",
			Pattern:  `runtime error: nil pointer dereference`,
			Category: "panic",
			Severity: "critical",
			Diagnosis: "Go panic: nil pointer dereference",
			Suggestions: []string{
				"Add nil check before pointer dereference",
				"Verify pointer initialization",
				"Use error returns instead of nil pointers",
			},
		},
		{
			Name:     "go_panic_slice",
			Pattern:  `runtime error: slice bounds out of range`,
			Category: "panic",
			Severity: "critical",
			Diagnosis: "Go panic: slice bounds out of range",
			Suggestions: []string{
				"Check slice length before slicing",
				"Validate start and end indices",
				"Use safe slicing patterns",
			},
		},
		{
			Name:     "go_panic_map",
			Pattern:  `runtime error: assignment to entry in nil map`,
			Category: "panic",
			Severity: "critical",
			Diagnosis: "Go panic: nil map assignment",
			Suggestions: []string{
				"Initialize map before use",
				"Use make() to create maps",
				"Check for nil map before assignment",
			},
		},
		{
			Name:     "go_panic_overflow",
			Pattern:  `runtime error: integer divide by zero|overflow`,
			Category: "panic",
			Severity: "critical",
			Diagnosis: "Go panic: arithmetic error",
			Suggestions: []string{
				"Check for zero before division",
				"Add overflow checks for arithmetic operations",
				"Use safe math libraries",
			},
		},
		{
			Name:     "go_panic_generic",
			Pattern:  `goroutine.*panic|runtime:.*panic`,
			Category: "panic",
			Severity: "critical",
			Diagnosis: "Go runtime panic",
			Suggestions: []string{
				"Review panic message for specific error type",
				"Add proper error handling",
				"Check for nil pointer usage",
				"Verify slice/map bounds",
			},
		},
		{
			Name:     "gcc_error",
			Pattern:  `error:|undefined reference|ld returned|multiple definition`,
			Category: "compilation",
			Severity: "high",
			Diagnosis: "C/C++ compilation or linking error",
			Suggestions: []string{
				"Fix syntax errors identified in build output",
				"Ensure all dependencies are available",
				"Check for missing header files",
				"Verify library linking order",
			},
		},
		{
			Name:     "go_build_error",
			Pattern:  `cannot|undefined|imported and not used|syntax error`,
			Category: "compilation",
			Severity: "high",
			Diagnosis: "Go compilation error",
			Suggestions: []string{
				"Fix syntax errors identified in build output",
				"Remove unused imports",
				"Check for type mismatches",
				"Verify import paths",
			},
		},
	}
}

// matchRule matches stderr against rules
func matchRule(stderr string, rule DiagnosisRule) bool {
	re, err := regexp.Compile(rule.Pattern)
	if err != nil {
		return false
	}
	return re.MatchString(stderr)
}

// extractMemoryAddress extracts memory address from segfault
func extractMemoryAddress(stderr string) string {
	re := regexp.MustCompile(`(?:address|at)\s+(0x[0-9a-fA-F]+)`)
	matches := re.FindStringSubmatch(stderr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// categorizeSignal categorizes the signal
func categorizeSignal(sig string) (string, string, string) {
	switch sig {
	case "SIGSEGV", "signal 11":
		return "segfault", "critical", "Segmentation fault"
	case "SIGABRT", "signal 6":
		return "segfault", "critical", "Aborted"
	case "SIGBUS", "signal 7":
		return "segfault", "critical", "Bus error"
	case "SIGKILL", "signal 9":
		return "oom", "critical", "Out of memory or killed"
	case "SIGTERM", "signal 15":
		return "timeout", "medium", "Terminated"
	case "SIGXCPU", "signal 24":
		return "timeout", "high", "CPU time limit exceeded"
	case "SIGXFSZ", "signal 25":
		return "oom", "high", "File size limit exceeded"
	default:
		return "unknown", "low", "Unknown signal"
	}
}

// categorizeExitCode maps exit codes to signal names
func categorizeExitCode(exitCode int) string {
	switch {
	case exitCode == 137:
		return "SIGKILL"
	case exitCode == 139:
		return "SIGSEGV"
	case exitCode == 134:
		return "SIGABRT"
	case exitCode == 136:
		return "SIGBUS"
	case exitCode == 143:
		return "SIGTERM"
	case exitCode == 138:
		return "SIGBUS"
	case exitCode > 128:
		return fmt.Sprintf("signal %d", exitCode-128)
	default:
		return ""
	}
}

// isCompilationError checks if error is a compilation error
func isCompilationError(stderr string) bool {
	patterns := []string{
		"error:",
		"undefined reference",
		"ld returned",
		"cannot find package",
		"syntax error",
		"unexpected token",
		"command not found",
	}

	lower := strings.ToLower(stderr)
	for _, p := range patterns {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// isRuntimePanic checks if error is a Go panic
func isRuntimePanic(stderr string) bool {
	return strings.Contains(stderr, "panic:") ||
		strings.Contains(stderr, "runtime error:") ||
		strings.Contains(stderr, "goroutine") && strings.Contains(stderr, "panic")
}

// isPythonTraceback checks if error is a Python traceback
func isPythonTraceback(stderr string) bool {
	return strings.Contains(stderr, "Traceback (most recent call last):") ||
		strings.Contains(stderr, "Python Exception") ||
		strings.Contains(stderr, "ImportError") ||
		strings.Contains(stderr, "SyntaxError")
}

// parseCompilationErrors extracts specific compilation errors
func parseCompilationErrors(stderr string) []string {
	var suggestions []string
	lines := strings.Split(stderr, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "error:") || strings.Contains(line, "undefined reference") {
			if strings.Contains(line, "undefined reference") {
				suggestions = append(suggestions, "Add missing library to linker flags")
			} else if strings.Contains(line, "cannot find package") {
				suggestions = append(suggestions, "Run go mod tidy or install missing package")
			} else if strings.Contains(line, "syntax error") {
				suggestions = append(suggestions, "Fix syntax error at: "+line)
			} else {
				suggestions = append(suggestions, "Fix: "+line)
			}
		}
	}

	if len(suggestions) == 0 {
		suggestions = append(suggestions, "Review compilation output for specific errors")
	}

	return suggestions
}

// parseRuntimePanic parses Go panic messages
func parseRuntimePanic(stderr string) []string {
	var suggestions []string

	if strings.Contains(stderr, "index out of range") {
		suggestions = append(suggestions,
			"Check slice length before accessing by index",
			"Add bounds checking",
			"Use safe index access patterns")
	} else if strings.Contains(stderr, "nil pointer dereference") {
		suggestions = append(suggestions,
			"Add nil check before pointer dereference",
			"Verify pointer initialization",
			"Use error returns instead of nil pointers")
	} else if strings.Contains(stderr, "slice bounds out of range") {
		suggestions = append(suggestions,
			"Check slice length before slicing",
			"Validate start and end indices",
			"Use safe slicing patterns")
	} else if strings.Contains(stderr, "assignment to entry in nil map") {
		suggestions = append(suggestions,
			"Initialize map before use",
			"Use make() to create maps",
			"Check for nil map before assignment")
	} else if strings.Contains(stderr, "integer divide by zero") {
		suggestions = append(suggestions,
			"Check for zero before division",
			"Add overflow checks",
			"Use safe math libraries")
	} else {
		suggestions = append(suggestions,
			"Review panic message for specific error type",
			"Add proper error handling",
			"Check for nil pointer usage")
	}

	return suggestions
}

// parsePythonTraceback parses Python exception tracebacks
func parsePythonTraceback(stderr string) []string {
	var suggestions []string
	lines := strings.Split(stderr, "\n")

	for _, line := range lines {
		if strings.Contains(line, "ImportError") || strings.Contains(line, "ModuleNotFoundError") {
			suggestions = append(suggestions, "Install missing Python package")
		} else if strings.Contains(line, "SyntaxError") {
			suggestions = append(suggestions, "Fix Python syntax error")
		} else if strings.Contains(line, "TypeError") {
			suggestions = append(suggestions, "Check function argument types")
		} else if strings.Contains(line, "ValueError") {
			suggestions = append(suggestions, "Validate input values")
		} else if strings.Contains(line, "FileNotFoundError") {
			suggestions = append(suggestions, "Verify file path exists")
		} else if strings.Contains(line, "PermissionError") {
			suggestions = append(suggestions, "Check file permissions")
		} else if strings.Contains(line, "KeyError") {
			suggestions = append(suggestions, "Check dictionary key exists")
		} else if strings.Contains(line, "IndexError") {
			suggestions = append(suggestions, "Check list index bounds")
		}
	}

	if len(suggestions) == 0 {
		suggestions = append(suggestions, "Review Python traceback for specific error")
	}

	return suggestions
}

// extractSeccompViolations extracts seccomp violation details
func extractSeccompViolations(stderr string) []string {
	var violations []string
	lines := strings.Split(stderr, "\n")

	for _, line := range lines {
		if strings.Contains(line, "seccomp") || strings.Contains(line, "SECCOMP") {
			violations = append(violations, strings.TrimSpace(line))
		}
	}

	return violations
}

// uniqueSuggestions removes duplicate suggestions
func uniqueSuggestions(suggestions []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, s := range suggestions {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	return result
}

// loadExistingReports loads existing reports from disk
func (sh *SelfHealer) loadExistingReports() error {
	entries, err := os.ReadDir(sh.reportsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read reports directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		reportPath := filepath.Join(sh.reportsDir, entry.Name())
		data, err := os.ReadFile(reportPath)
		if err != nil {
			continue
		}

		var analysis CrashAnalysis
		if err := json.Unmarshal(data, &analysis); err != nil {
			continue
		}

		sh.reports[analysis.ContainerID] = append(sh.reports[analysis.ContainerID], &analysis)
	}

	return nil
}
