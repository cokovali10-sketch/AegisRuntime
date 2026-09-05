//go:build linux

package edr

import (
	"regexp"
	"strings"
)

type Rule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	Patterns    []string `json:"patterns"`
	Action      string   `json:"action"`
}

type RuleEngine struct {
	rules []Rule
}

func DefaultRules() []Rule {
	return []Rule{
		{
			ID:          "RULE-001",
			Name:        "Sensitive File Access",
			Description: "Access to sensitive system files",
			Severity:    "high",
			Category:    "file",
			Patterns: []string{
				"/etc/passwd",
				"/etc/shadow",
				"/etc/sudoers",
				"/root/.ssh",
				"/proc/sys",
				"/sys/kernel",
				"/dev/mem",
				"/dev/kmem",
			},
			Action: "alert",
		},
		{
			ID:          "RULE-002",
			Name:        "Docker Socket Access",
			Description: "Access to Docker socket detected",
			Severity:    "critical",
			Category:    "file",
			Patterns: []string{
				"/var/run/docker.sock",
			},
			Action: "block",
		},
		{
			ID:          "RULE-003",
			Name:        "Metadata Service Access",
			Description: "Access to cloud metadata service",
			Severity:    "critical",
			Category:    "network",
			Patterns: []string{
				"169.254.169.254",
				"metadata.google.internal",
				"0.0.0.0",
			},
			Action: "block",
		},
		{
			ID:          "RULE-004",
			Name:        "Dangerous Command Execution",
			Description: "Execution of dangerous system commands",
			Severity:    "critical",
			Category:    "process",
			Patterns: []string{
				"rm -rf /",
				"dd if=/dev/zero",
				"mkfs",
				"curl | sh",
				"wget | sh",
				"chmod 777 /",
				"chown root",
				"mount /dev/sda",
				"insmod",
				"modprobe",
			},
			Action: "kill",
		},
		{
			ID:          "RULE-005",
			Name:        "Fork Bomb",
			Description: "Fork bomb pattern detected",
			Severity:    "critical",
			Category:    "process",
			Patterns: []string{
				":(){ :|:& };:",
				":(){ :|:& };",
			},
			Action: "kill",
		},
		{
			ID:          "RULE-006",
			Name:        "Suspicious Network Connection",
			Description: "Suspicious outbound network connection",
			Severity:    "medium",
			Category:    "network",
			Patterns: []string{
				":4444",
				":5555",
				":6666",
				":7777",
				":8888",
				":9999",
				":31337",
				":1234",
			},
			Action: "alert",
		},
		{
			ID:          "RULE-007",
			Name:        "Container Escape Attempt",
			Description: "Potential container escape detected",
			Severity:    "critical",
			Category:    "syscall",
			Patterns: []string{
				"mount",
				"pivot_root",
				"chroot",
				"reboot",
				"init_module",
				"delete_module",
			},
			Action: "kill",
		},
		{
			ID:          "RULE-008",
			Name:        "Process Injection",
			Description: "Process injection or ptrace detected",
			Severity:    "high",
			Category:    "syscall",
			Patterns: []string{
				"ptrace",
				"process_vm_readv",
				"process_vm_writev",
			},
			Action: "block",
		},
	}
}

func NewRuleEngine(rules []Rule) *RuleEngine {
	return &RuleEngine{
		rules: rules,
	}
}

func (re *RuleEngine) Evaluate(event AuditEvent) []RuleMatch {
	var matches []RuleMatch

	for _, rule := range re.rules {
		if rule.Category != event.Type {
			continue
		}

		for _, pattern := range rule.Patterns {
			if matched, _ := regexp.MatchString(quotePattern(pattern), event.Target+event.Details); matched {
				matches = append(matches, RuleMatch{
					Rule:   rule,
					Event:  event,
					Action: rule.Action,
				})
				break
			}

			if strings.Contains(event.Target, pattern) || strings.Contains(event.Details, pattern) {
				matches = append(matches, RuleMatch{
					Rule:   rule,
					Event:  event,
					Action: rule.Action,
				})
				break
			}
		}
	}

	return matches
}

func (re *RuleEngine) AddRule(rule Rule) {
	re.rules = append(re.rules, rule)
}

func (re *RuleEngine) RemoveRule(ruleID string) {
	for i, rule := range re.rules {
		if rule.ID == ruleID {
			re.rules = append(re.rules[:i], re.rules[i+1:]...)
			return
		}
	}
}

func quotePattern(pattern string) string {
	escaped := regexp.QuoteMeta(pattern)
	return "(?i)" + escaped
}

type RuleMatch struct {
	Rule   Rule       `json:"rule"`
	Event  AuditEvent `json:"event"`
	Action string     `json:"action"`
}

var DangerousPaths = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/sudoers",
	"/root/.ssh",
	"/proc/sys",
	"/sys/kernel",
	"/dev/mem",
	"/dev/kmem",
	"/var/run/docker.sock",
}

var SuspiciousNetworkPatterns = []string{
	"0.0.0.0",
	"169.254.169.254",
	"metadata.google.internal",
}

var DangerousCommands = []string{
	"rm -rf /",
	"dd if=/dev/zero of=/dev/sda",
	"mkfs",
	":(){ :|:& };:",
	"curl | sh",
	"wget | sh",
	"chmod 777 /",
	"chown root",
	"mount /dev/sda",
	"insmod",
	"modprobe",
}
