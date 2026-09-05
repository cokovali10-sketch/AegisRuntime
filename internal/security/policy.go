//go:build linux

package security

import (
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type SecurityPolicy struct {
	Name            string             `json:"name"`
	Seccomp         *SeccompProfile    `json:"seccomp"`
	Capabilities    CapabilitiesConfig `json:"capabilities"`
	ReadOnlyRootfs  bool               `json:"read_only_rootfs"`
	NoNewPrivileges bool               `json:"no_new_privileges"`
	Namespaces      NamespaceConfig    `json:"namespaces"`
	Cgroups         CgroupConfig       `json:"cgroups"`
	NetworkPolicy   string             `json:"network_policy"`
	FilePolicy      string             `json:"file_policy"`
}

type NamespaceConfig struct {
	PID   bool `json:"pid"`
	Mount bool `json:"mount"`
	UTS   bool `json:"uts"`
	Net   bool `json:"net"`
	User  bool `json:"user"`
}

type CgroupConfig struct {
	CPU    int64 `json:"cpu"`
	Memory int64 `json:"memory"`
	PIDs   int   `json:"pids"`
}

func DefaultPolicy() *SecurityPolicy {
	return &SecurityPolicy{
		Name:            "default",
		Seccomp:         DefaultProfile(),
		Capabilities:    *DefaultCapabilities(),
		ReadOnlyRootfs:  false,
		NoNewPrivileges: true,
		Namespaces: NamespaceConfig{
			PID: true, Mount: true, UTS: true, Net: true, User: false,
		},
		Cgroups:       CgroupConfig{CPU: 100000, Memory: 512 * 1024 * 1024, PIDs: 256},
		NetworkPolicy: "restricted",
		FilePolicy:    "none",
	}
}

func AggressivePolicy() *SecurityPolicy {
	return &SecurityPolicy{
		Name:            "aggressive",
		Seccomp:         AggressiveProfile(),
		Capabilities:    *AggressiveCapabilities(),
		ReadOnlyRootfs:  true,
		NoNewPrivileges: true,
		Namespaces: NamespaceConfig{
			PID: true, Mount: true, UTS: true, Net: true, User: true,
		},
		Cgroups:       CgroupConfig{CPU: 50000, Memory: 256 * 1024 * 1024, PIDs: 64},
		NetworkPolicy: "none",
		FilePolicy:    "read-only",
	}
}

func MinimalPolicy() *SecurityPolicy {
	return &SecurityPolicy{
		Name:            "minimal",
		Seccomp:         nil,
		Capabilities:    CapabilitiesConfig{},
		ReadOnlyRootfs:  false,
		NoNewPrivileges: false,
		Namespaces: NamespaceConfig{
			PID: false, Mount: false, UTS: false, Net: false, User: false,
		},
		Cgroups:       CgroupConfig{},
		NetworkPolicy: "full",
		FilePolicy:    "none",
	}
}

func Validate(p *SecurityPolicy) error {
	if p == nil {
		return fmt.Errorf("nil security policy")
	}

	if p.NetworkPolicy != "none" && p.NetworkPolicy != "restricted" && p.NetworkPolicy != "full" {
		return fmt.Errorf("invalid network_policy: %s", p.NetworkPolicy)
	}

	if p.FilePolicy != "none" && p.FilePolicy != "read-only" && p.FilePolicy != "restricted" {
		return fmt.Errorf("invalid file_policy: %s", p.FilePolicy)
	}

	if p.Cgroups.CPU < 0 {
		return fmt.Errorf("invalid CPU quota: %d", p.Cgroups.CPU)
	}

	if p.Cgroups.Memory < 0 {
		return fmt.Errorf("invalid memory limit: %d", p.Cgroups.Memory)
	}

	if p.Cgroups.PIDs < 0 {
		return fmt.Errorf("invalid PIDs limit: %d", p.Cgroups.PIDs)
	}

	if p.Seccomp != nil {
		validActions := map[string]bool{
			"SCMP_ACT_ALLOW": true, "SCMP_ACT_ERRNO": true,
			"SCMP_ACT_KILL": true, "SCMP_ACT_LOG": true, "SCMP_ACT_TRACE": true,
		}
		if !validActions[p.Seccomp.DefaultAction] {
			return fmt.Errorf("invalid seccomp default action: %s", p.Seccomp.DefaultAction)
		}
		for _, rule := range p.Seccomp.Syscalls {
			if !validActions[rule.Action] {
				return fmt.Errorf("invalid seccomp action: %s", rule.Action)
			}
		}
	}

	return nil
}

func Apply(p *SecurityPolicy) error {
	if err := Validate(p); err != nil {
		return fmt.Errorf("validate policy: %w", err)
	}

	if err := applyNoNewPrivileges(p.NoNewPrivileges); err != nil {
		return fmt.Errorf("set no_new_privileges: %w", err)
	}

	if p.Seccomp != nil {
		if err := ApplySeccomp(p.Seccomp); err != nil {
			return fmt.Errorf("apply seccomp: %w", err)
		}
	}

	if err := ApplyCapabilities(p.Capabilities); err != nil {
		return fmt.Errorf("apply capabilities: %w", err)
	}

	if p.ReadOnlyRootfs {
		if err := applyReadOnlyRootfs(); err != nil {
			return fmt.Errorf("apply read-only rootfs: %w", err)
		}
	}

	return nil
}

func applyNoNewPrivileges(enable bool) error {
	if !enable {
		return nil
	}

	_, _, errno := unix.Syscall6(
		unix.SYS_PRCTL,
		uintptr(unix.PR_SET_NO_NEW_PRIVS),
		1, 0, 0, 0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("prctl PR_SET_NO_NEW_PRIVS: %w", errno)
	}

	return nil
}

func applyReadOnlyRootfs() error {
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getwd: %w", err)
	}

	if err := unix.Mount("", wd, "", unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("remount read-only: %w", err)
	}

	return nil
}

func LoadPolicy(path string) (*SecurityPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}

	var policy SecurityPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}

	if err := Validate(&policy); err != nil {
		return nil, fmt.Errorf("validate policy: %w", err)
	}

	return &policy, nil
}

func SavePolicy(p *SecurityPolicy, path string) error {
	if err := Validate(p); err != nil {
		return fmt.Errorf("validate policy: %w", err)
	}

	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write policy: %w", err)
	}

	return nil
}
