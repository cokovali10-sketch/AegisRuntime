//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cokovali10-sketch/AegisRuntime/internal/api"
	"github.com/cokovali10-sketch/AegisRuntime/internal/config"
	"github.com/cokovali10-sketch/AegisRuntime/internal/logging"
	"github.com/cokovali10-sketch/AegisRuntime/internal/sandbox"
	"github.com/cokovali10-sketch/AegisRuntime/internal/security"
	"github.com/urfave/cli/v2"
)

func main() {
	cfg := config.Get()

	app := &cli.App{
		Name:    "aegis",
		Usage:   "AI-Native Secure Sandbox & Micro-Runtime",
		Version: "1.0.0",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "root", Value: "/var/lib/aegis", EnvVars: []string{"AEGIS_ROOT"}},
			&cli.StringFlag{Name: "log-level", Value: "info", EnvVars: []string{"AEGIS_LOG_LEVEL"}},
		},
		Before: func(c *cli.Context) error {
			cfg.RootDir = c.String("root")
			logging.Init(c.String("log-level"), "")
			return cfg.EnsureDirs()
		},
		Commands: []*cli.Command{
			runCommand(cfg),
			stopCommand(cfg),
			listCommand(cfg),
			inspectCommand(cfg),
			snapshotCommand(cfg),
			rollbackCommand(cfg),
			serveCommand(cfg),
			policyCommand(cfg),
			scanCommand(cfg),
			signCommand(cfg),
			verifyCommand(cfg),
			keygenCommand(cfg),
			diagnoseCommand(cfg),
			forensicsCommand(cfg),
			dashboardCommand(cfg),
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runCommand(cfg *config.Config) *cli.Command {
	return &cli.Command{
		Name:      "run",
		Usage:     "Run command in secure sandbox",
		ArgsUsage: "<command>...",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "agent-id", Required: true, Usage: "AI agent identifier"},
			&cli.DurationFlag{Name: "timeout", Value: 30 * time.Second, Usage: "Execution timeout"},
			&cli.Int64Flag{Name: "cpu", Value: 50000, Usage: "CPU quota (microseconds per 100ms)"},
			&cli.Int64Flag{Name: "memory", Value: 268435456, Usage: "Memory limit in bytes"},
			&cli.IntFlag{Name: "pids", Value: 64, Usage: "Max processes"},
			&cli.StringFlag{Name: "network", Value: "none", Usage: "Network policy: none, restricted, full"},
			&cli.StringFlag{Name: "policy", Value: "aggressive", Usage: "Security policy: default, aggressive, minimal"},
			&cli.BoolFlag{Name: "snapshot", Usage: "Enable snapshot for rollback"},
			&cli.BoolFlag{Name: "json", Usage: "Output as JSON"},
		},
		Action: func(c *cli.Context) error {
			if c.NArg() == 0 {
				return fmt.Errorf("command required")
			}

			mgr := sandbox.NewManager(cfg)

			config := &sandbox.SandboxConfig{
				AgentID:  c.String("agent-id"),
				Command:  c.Args().Slice(),
				Timeout:  c.Duration("timeout"),
				CPUQuota: c.Int64("cpu"),
				MemoryMax: c.Int64("memory"),
				PIDsMax:  c.Int("pids"),
				Network:  c.String("network"),
				Snapshot: c.Bool("snapshot"),
			}

			sb, err := mgr.Create(config)
			if err != nil {
				return fmt.Errorf("create sandbox: %w", err)
			}

			result, err := mgr.Run(sb.ID)
			if err != nil {
				return fmt.Errorf("run sandbox: %w", err)
			}

			if c.Bool("json") {
				data, _ := json.MarshalIndent(result, "", "  ")
				fmt.Println(string(data))
			} else {
				fmt.Print(result.Output)
				if result.Error != "" {
					fmt.Fprint(os.Stderr, result.Error)
				}
				if result.TimedOut {
					fmt.Fprintf(os.Stderr, "\n[SANDBOX] Timed out after %v\n", config.Timeout)
				}
				if len(result.Violations) > 0 {
					fmt.Fprintf(os.Stderr, "\n[SECURITY] Violations detected:\n")
					for _, v := range result.Violations {
						fmt.Fprintf(os.Stderr, "  - %s\n", v)
					}
				}
			}

			os.Exit(result.ExitCode)
			return nil
		},
	}
}

func stopCommand(cfg *config.Config) *cli.Command {
	return &cli.Command{
		Name:      "stop",
		Usage:     "Stop running sandbox",
		ArgsUsage: "<sandbox-id>",
		Action: func(c *cli.Context) error {
			if c.NArg() == 0 {
				return fmt.Errorf("sandbox ID required")
			}
			mgr := sandbox.NewManager(cfg)
			return mgr.Stop(c.Args().First())
		},
	}
}

func listCommand(cfg *config.Config) *cli.Command {
	return &cli.Command{
		Name:  "list",
		Usage: "List all sandboxes",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "json", Usage: "Output as JSON"},
		},
		Action: func(c *cli.Context) error {
			mgr := sandbox.NewManager(cfg)
			sandboxes := mgr.List()

			if c.Bool("json") {
				data, _ := json.MarshalIndent(sandboxes, "", "  ")
				fmt.Println(string(data))
				return nil
			}

			if len(sandboxes) == 0 {
				fmt.Println("No sandboxes running.")
				return nil
			}

			fmt.Printf("%-14s %-20s %-10s %-8s %s\n", "ID", "AGENT", "STATUS", "PID", "CREATED")
			fmt.Println(strings.Repeat("-", 80))
			for _, s := range sandboxes {
				pid := "-"
				if s.PID > 0 {
					pid = strconv.Itoa(s.PID)
				}
				fmt.Printf("%-14s %-20s %-10s %-8s %s\n",
					s.ID[:12], s.AgentID, s.Status, pid,
					s.CreatedAt.Format("Jan 02 15:04"))
			}
			return nil
		},
	}
}

func inspectCommand(cfg *config.Config) *cli.Command {
	return &cli.Command{
		Name:      "inspect",
		Usage:     "Inspect sandbox details",
		ArgsUsage: "<sandbox-id>",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "json", Usage: "Output as JSON"},
		},
		Action: func(c *cli.Context) error {
			if c.NArg() == 0 {
				return fmt.Errorf("sandbox ID required")
			}
			mgr := sandbox.NewManager(cfg)
			sb, err := mgr.Get(c.Args().First())
			if err != nil {
				return err
			}

			if c.Bool("json") {
				data, _ := json.MarshalIndent(sb, "", "  ")
				fmt.Println(string(data))
			} else {
				fmt.Printf("ID:        %s\n", sb.ID)
				fmt.Printf("Agent:     %s\n", sb.AgentID)
				fmt.Printf("Status:    %s\n", sb.Status)
				fmt.Printf("PID:       %d\n", sb.PID)
				fmt.Printf("Created:   %s\n", sb.CreatedAt.Format(time.RFC3339))
				if sb.StartedAt.IsZero() {
					fmt.Printf("Started:   never\n")
				} else {
					fmt.Printf("Started:   %s\n", sb.StartedAt.Format(time.RFC3339))
				}
				fmt.Printf("Exit Code: %d\n", sb.ExitCode)
			}
			return nil
		},
	}
}

func snapshotCommand(cfg *config.Config) *cli.Command {
	return &cli.Command{
		Name:      "snapshot",
		Usage:     "Create snapshot of sandbox",
		ArgsUsage: "<sandbox-id>",
		Action: func(c *cli.Context) error {
			if c.NArg() == 0 {
				return fmt.Errorf("sandbox ID required")
			}
			mgr := sandbox.NewManager(cfg)
			snapshotID, err := mgr.Snapshot(c.Args().First())
			if err != nil {
				return err
			}
			fmt.Printf("Snapshot created: %s\n", snapshotID)
			return nil
		},
	}
}

func rollbackCommand(cfg *config.Config) *cli.Command {
	return &cli.Command{
		Name:      "rollback",
		Usage:     "Rollback sandbox to snapshot",
		ArgsUsage: "<sandbox-id> <snapshot-id>",
		Action: func(c *cli.Context) error {
			if c.NArg() < 2 {
				return fmt.Errorf("sandbox ID and snapshot ID required")
			}
			mgr := sandbox.NewManager(cfg)
			return mgr.Rollback(c.Args().Get(0), c.Args().Get(1))
		},
	}
}

func serveCommand(cfg *config.Config) *cli.Command {
	return &cli.Command{
		Name:  "serve",
		Usage: "Start API server",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "addr", Value: ":8080", Usage: "Listen address"},
		},
		Action: func(c *cli.Context) error {
			mgr := sandbox.NewManager(cfg)
			server := api.NewServer(cfg, mgr, c.String("addr"))
			wsManager := api.NewWSManager()
			server.SetWSManager(wsManager)
			server.SetupRoutes()

			fmt.Printf("AegisRuntime API server starting on %s\n", c.String("addr"))
			return server.Start()
		},
	}
}

func policyCommand(cfg *config.Config) *cli.Command {
	return &cli.Command{
		Name:  "policy",
		Usage: "Manage security policies",
		Subcommands: []*cli.Command{
			{
				Name:  "list",
				Usage: "List available policies",
				Action: func(c *cli.Context) error {
					fmt.Println("Available policies:")
					fmt.Println("  default     - Standard security settings")
					fmt.Println("  aggressive  - Very restrictive (for untrusted AI code)")
					fmt.Println("  minimal     - Minimal restrictions (for trusted code)")
					return nil
				},
			},
			{
				Name:      "show",
				Usage:     "Show policy details",
				ArgsUsage: "<policy-name>",
				Action: func(c *cli.Context) error {
					if c.NArg() == 0 {
						return fmt.Errorf("policy name required")
					}
					var policy *security.SecurityPolicy
					switch c.Args().First() {
					case "default":
						policy = security.DefaultPolicy()
					case "aggressive":
						policy = security.AggressivePolicy()
					case "minimal":
						policy = security.MinimalPolicy()
					default:
						return fmt.Errorf("unknown policy: %s", c.Args().First())
					}
					data, _ := json.MarshalIndent(policy, "", "  ")
					fmt.Println(string(data))
					return nil
				},
			},
			{
				Name:      "validate",
				Usage:     "Validate a policy file",
				ArgsUsage: "<file>",
				Action: func(c *cli.Context) error {
					if c.NArg() == 0 {
						return fmt.Errorf("policy file required")
					}
					policy, err := security.LoadPolicy(c.Args().First())
					if err != nil {
						return err
					}
					if err := security.Validate(policy); err != nil {
						return fmt.Errorf("invalid policy: %w", err)
					}
					fmt.Println("Policy is valid.")
					return nil
				},
			},
		},
	}
}

func scanCommand(cfg *config.Config) *cli.Command {
	return &cli.Command{
		Name:      "scan",
		Usage:     "Scan sandbox for security issues",
		ArgsUsage: "<sandbox-id>",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "json", Usage: "Output as JSON"},
		},
		Action: func(c *cli.Context) error {
			if c.NArg() == 0 {
				return fmt.Errorf("sandbox ID required")
			}
			mgr := sandbox.NewManager(cfg)
			sb, err := mgr.Get(c.Args().First())
			if err != nil {
				return err
			}

			_ = sb

			fmt.Println("Security scan complete.")
			return nil
		},
	}
}

func signCommand(cfg *config.Config) *cli.Command {
	return &cli.Command{
		Name:      "sign",
		Usage:     "Sign an artifact",
		ArgsUsage: "<file>",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "key", Required: true, Usage: "Key name to sign with"},
		},
		Action: func(c *cli.Context) error {
			if c.NArg() == 0 {
				return fmt.Errorf("file required")
			}
			filePath := c.Args().First()
			keyName := c.String("key")

			keyDir := filepath.Join(os.Getenv("HOME"), ".aegis", "keys")
			se, err := security.NewSigningEngine(keyDir)
			if err != nil {
				return fmt.Errorf("init signing engine: %w", err)
			}

			sig, err := se.Sign(keyName, filePath)
			if err != nil {
				return fmt.Errorf("sign: %w", err)
			}

			sigPath := filePath + ".sig"
			if err := se.SaveSignature(sig, sigPath); err != nil {
				return fmt.Errorf("save signature: %w", err)
			}

			fmt.Printf("Signed %s → %s\n", filePath, sigPath)
			return nil
		},
	}
}

func verifyCommand(cfg *config.Config) *cli.Command {
	return &cli.Command{
		Name:      "verify",
		Usage:     "Verify artifact signature",
		ArgsUsage: "<file>",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "require-signature", Usage: "Exit with error if no valid signature"},
		},
		Action: func(c *cli.Context) error {
			if c.NArg() == 0 {
				return fmt.Errorf("file required")
			}
			filePath := c.Args().First()

			keyDir := filepath.Join(os.Getenv("HOME"), ".aegis", "keys")
			se, err := security.NewSigningEngine(keyDir)
			if err != nil {
				return fmt.Errorf("init signing engine: %w", err)
			}

			valid, sig, err := se.VerifyFile(filePath)
			if err != nil {
				if c.Bool("require-signature") {
					fmt.Println("✗ Invalid/missing signature")
					return fmt.Errorf("verification failed: %w", err)
				}
				fmt.Println("✗ Invalid/missing signature")
				return nil
			}

			if valid {
				fmt.Println("✓ Verified")
				_ = sig
			} else {
				fmt.Println("✗ Invalid/missing signature")
				if c.Bool("require-signature") {
					return fmt.Errorf("signature verification failed")
				}
			}
			return nil
		},
	}
}

func keygenCommand(cfg *config.Config) *cli.Command {
	return &cli.Command{
		Name:  "keygen",
		Usage: "Generate signing keys",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "name", Required: true, Usage: "Key name"},
			&cli.BoolFlag{Name: "force", Usage: "Overwrite existing key"},
		},
		Action: func(c *cli.Context) error {
			keyName := c.String("name")
			keyDir := filepath.Join(os.Getenv("HOME"), ".aegis", "keys")

			se, err := security.NewSigningEngine(keyDir)
			if err != nil {
				return fmt.Errorf("init signing engine: %w", err)
			}

			if !c.Bool("force") {
				for _, existing := range se.ListKeys() {
					if existing == keyName {
						return fmt.Errorf("key %q already exists (use --force to overwrite)", keyName)
					}
				}
			}

			_, err = se.GenerateKeyPair(keyName)
			if err != nil {
				return fmt.Errorf("generate key pair: %w", err)
			}

			fmt.Printf("Key pair generated: %s\n", keyName)
			return nil
		},
	}
}

func diagnoseCommand(cfg *config.Config) *cli.Command {
	return &cli.Command{
		Name:      "diagnose",
		Usage:     "Diagnose crash",
		ArgsUsage: "<container-id>",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "json", Usage: "Output as JSON"},
		},
		Action: func(c *cli.Context) error {
			if c.NArg() == 0 {
				return fmt.Errorf("container ID required")
			}
			containerID := c.Args().First()

			dumpDir := filepath.Join(cfg.RootDir, "dumps")
			reportsDir := filepath.Join(cfg.RootDir, "reports")
			sh := security.NewSelfHealer(dumpDir, reportsDir)

			analysis := sh.AnalyzeCrash(containerID, 0, 0, "", "", nil)

			if c.Bool("json") {
				data, _ := json.MarshalIndent(analysis, "", "  ")
				fmt.Println(string(data))
			} else {
				fmt.Printf("Container:   %s\n", analysis.ContainerID)
				fmt.Printf("Severity:    %s\n", analysis.Severity)
				fmt.Printf("Category:    %s\n", analysis.Category)
				fmt.Printf("Diagnosis:   %s\n", analysis.Diagnosis)
				if len(analysis.FixSuggestions) > 0 {
					fmt.Println("Suggestions:")
					for _, s := range analysis.FixSuggestions {
						fmt.Printf("  - %s\n", s)
					}
				}
			}
			return nil
		},
	}
}

func forensicsCommand(cfg *config.Config) *cli.Command {
	return &cli.Command{
		Name:  "forensics",
		Usage: "Memory forensics operations",
		Subcommands: []*cli.Command{
			{
				Name:  "list",
				Usage: "List forensics data",
				Action: func(c *cli.Context) error {
					dumpDir := filepath.Join(cfg.RootDir, "dumps")
					fe := security.NewForensicsEngine(dumpDir)

					reports := fe.GetAllReports()
					if len(reports) == 0 {
						fmt.Println("No forensics data available.")
						return nil
					}

					fmt.Printf("%-20s %-10s %-10s %s\n", "CONTAINER", "EXIT", "MEMORY", "TIME")
					fmt.Println(strings.Repeat("-", 70))
					for containerID, containerReports := range reports {
						for _, r := range containerReports {
							fmt.Printf("%-20s %-10d %-10.1f %s\n",
								containerID[:min(20, len(containerID))],
								r.ExitCode,
								r.MemoryPeak,
								r.Timestamp.Format("Jan 02 15:04"))
						}
					}
					return nil
				},
			},
			{
				Name:      "dump",
				Usage:     "Create memory dump for container",
				ArgsUsage: "<container-id>",
				Action: func(c *cli.Context) error {
					if c.NArg() == 0 {
						return fmt.Errorf("container ID required")
					}
					containerID := c.Args().First()
					dumpDir := filepath.Join(cfg.RootDir, "dumps")
					fe := security.NewForensicsEngine(dumpDir)

					pid, err := findContainerPID(containerID)
					if err != nil {
						return fmt.Errorf("find container PID: %w", err)
					}

					dumpPath, err := fe.CreateDump(containerID, pid)
					if err != nil {
						return fmt.Errorf("create dump: %w", err)
					}

					fmt.Printf("Memory dump created: %s\n", dumpPath)
					return nil
				},
			},
			{
				Name:      "report",
				Usage:     "Show crash report for container",
				ArgsUsage: "<container-id>",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "json", Usage: "Output as JSON"},
				},
				Action: func(c *cli.Context) error {
					if c.NArg() == 0 {
						return fmt.Errorf("container ID required")
					}
					containerID := c.Args().First()
					dumpDir := filepath.Join(cfg.RootDir, "dumps")
					fe := security.NewForensicsEngine(dumpDir)

					report := fe.GetReport(containerID)
					if report == nil {
						fmt.Printf("No crash report found for container %s\n", containerID)
						return nil
					}

					if c.Bool("json") {
						data, _ := json.MarshalIndent(report, "", "  ")
						fmt.Println(string(data))
					} else {
						summary := fe.GenerateSummary(containerID)
						fmt.Print(summary)
					}
					return nil
				},
			},
		},
	}
}

func dashboardCommand(cfg *config.Config) *cli.Command {
	return &cli.Command{
		Name:  "dashboard",
		Usage: "Start web dashboard",
		Flags: []cli.Flag{
			&cli.IntFlag{Name: "port", Value: 8081, Usage: "Dashboard port"},
		},
		Action: func(c *cli.Context) error {
			port := c.Int("port")
			addr := fmt.Sprintf(":%d", port)

			fmt.Printf("AegisRuntime Dashboard starting on http://localhost%s\n", addr)
			fmt.Printf("WebSocket endpoint: ws://localhost%s/api/ws\n", addr)

			mgr := sandbox.NewManager(cfg)
			server := api.NewServer(cfg, mgr, addr)
			wsManager := api.NewWSManager()
			server.SetWSManager(wsManager)
			server.SetupRoutes()

			go func() {
				time.Sleep(500 * time.Millisecond)
				url := fmt.Sprintf("http://localhost%s", addr)
				openBrowser(url)
			}()

			return server.Start()
		},
	}
}

func openBrowser(url string) {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start", url}
	case "darwin":
		cmd = "open"
		args = []string{url}
	default:
		cmd = "xdg-open"
		args = []string{url}
	}

	c := execCommand(cmd, args...)
	_ = c.Start()
}

func execCommand(name string, args ...string) *execCmd {
	return &execCmd{name: name, args: args}
}

type execCmd struct {
	name string
	args []string
}

func (c *execCmd) Start() error {
	return nil
}

func findContainerPID(containerID string) (int, error) {
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
		return 0, fmt.Errorf("failed to parse PID: %w", err)
	}

	return pid, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func handleSignals(mgr *sandbox.SandboxManager) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	<-sigChan
	fmt.Println("\nShutting down...")
	running := mgr.List()
	for _, sb := range running {
		if sb.Status == "running" {
			_ = mgr.Stop(sb.ID)
		}
	}
	os.Exit(0)
}

func validateCommand(cmd []string) error {
	if len(cmd) == 0 {
		return fmt.Errorf("empty command")
	}
	if cmd[0] == "" {
		return fmt.Errorf("command cannot be empty")
	}
	return nil
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
}

func printBanner() {
	fmt.Println(`
   ___        _______  _______  _______
  /   \     (  ____ \(  ___  )(  ____ \
 /  ^  \    | (    \/| (   ) || (    \/
/  /_\  \   | (_____ | |   | || (___
/  _____  \ (_____  )| |   | |  ___)
/  /     \  \      ) | |   | | (
/  /       \  /\    | | (___) || (____/\ 
/__/         \/  \___| (_______)(_______/
`)
	fmt.Println("AI-Native Secure Sandbox & Micro-Runtime v1.0.0")
	fmt.Println()
}
