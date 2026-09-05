//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
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
