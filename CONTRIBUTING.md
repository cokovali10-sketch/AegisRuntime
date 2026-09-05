# Contributing to AegisRuntime

Thank you for your interest in contributing to AegisRuntime! This document provides guidelines and instructions for contributing.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Issue Guidelines](#issue-guidelines)
- [Security Policy](#security-policy)

---

## Code of Conduct

We are committed to providing a welcoming and inclusive experience for everyone. Please be respectful and constructive in all interactions.

---

## Getting Started

### Prerequisites

- **Go 1.22+** (`go version`)
- **Linux kernel 5.10+** (for seccomp-BPF, cgroups v2)
- **Git** (`git --version`)
- **Make** (optional, for convenience targets)

### Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/<your-username>/AegisRuntime.git
cd AegisRuntime
git remote add upstream https://github.com/cokovali10-sketch/AegisRuntime.git
```

### Build

```bash
# Standard build
go build -o aegis ./cmd/aegis/

# Cross-compile for Linux from any OS
GOOS=linux GOARCH=amd64 go build -o aegis ./cmd/aegis/

# Build with race detector (development only)
go build -race -o aegis ./cmd/aegis/
```

### Verify Build

```bash
# Run all unit tests
go test ./... -v

# Run with coverage
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out

# Run specific package tests
go test ./internal/security/... -v
go test ./internal/kernel/... -v
```

---

## Development Setup

### Directory Structure

```
AegisRuntime/
├── cmd/aegis/                    # CLI entry point
│   └── main.go                  # 15 commands, flag parsing
├── internal/
│   ├── api/                      # HTTP API + WebSocket + Dashboard
│   │   ├── server.go             # REST handlers, routing
│   │   ├── websocket.go          # WebSocket manager
│   │   └── dashboard.go          # Embedded HTML SPA
│   ├── config/                   # Configuration
│   │   └── config.go             # Load/save/defaults
│   ├── edr/                      # EDR monitoring
│   │   ├── monitor.go            # inotify + /proc monitor
│   │   └── rules.go              # Detection rules
│   ├── kernel/                   # Linux kernel interface
│   │   ├── namespaces.go         # clone(), pivot_root()
│   │   ├── cgroups.go            # cgroup v2 management
│   │   └── rootfs.go             # Rootfs + snapshots
│   ├── logging/                  # Structured logging
│   │   └── logger.go             # slog-based logger
│   ├── sandbox/                  # Sandbox lifecycle
│   │   ├── sandbox.go            # Manager + execution
│   │   ├── snapshot.go           # tar.gz snapshots
│   │   └── jsonutil.go           # JSON utilities
│   └── security/                 # Security subsystem
│       ├── seccomp.go            # BPF filter compiler
│       ├── capabilities.go       # capget/capset
│       ├── policy.go             # Policy engine
│       ├── forensics.go          # Memory forensics
│       ├── signing.go            # Ed25519 signing
│       └── selfheal.go           # Crash analysis
├── go.mod
├── go.sum
├── LICENSE
├── README.md
├── ARCHITECTURE.md
└── CONTRIBUTING.md
```

### Key Packages

| Package | Purpose | Key Files |
|---------|---------|-----------|
| `cmd/aegis` | CLI entry point, command definitions | `main.go` |
| `internal/sandbox` | Sandbox lifecycle management | `sandbox.go`, `snapshot.go` |
| `internal/kernel` | Linux kernel primitives | `namespaces.go`, `cgroups.go`, `rootfs.go` |
| `internal/security` | Security enforcement | `seccomp.go`, `capabilities.go`, `policy.go` |
| `internal/security` | Memory forensics | `forensics.go` |
| `internal/security` | Artifact signing | `signing.go` |
| `internal/security` | Crash analysis | `selfheal.go` |
| `internal/edr` | Runtime monitoring | `monitor.go`, `rules.go` |
| `internal/api` | REST API + WebSocket | `server.go`, `websocket.go` |
| `internal/config` | Configuration | `config.go` |

---

## Coding Standards

### Go Style

- Follow [Effective Go](https://go.dev/doc/effective_go) conventions
- Use `gofmt` / `goimports` for formatting
- Run `go vet ./...` before committing
- No unused imports or variables
- All exported functions must have doc comments

### Build Constraints

All files that use Linux-specific syscalls MUST have:

```go
//go:build linux

package <name>
```

This ensures proper cross-compilation from macOS/Windows.

### Error Handling

```go
// Always wrap errors with context
if err := doSomething(); err != nil {
    return fmt.Errorf("do something: %w", err)
}

// Never silently ignore errors
// BAD:
_ = doSomething()

// GOOD:
if err := doSomething(); err != nil {
    log.Printf("warning: do something: %v", err)
}
```

### Naming Conventions

- **Packages**: lowercase, single-word (`sandbox`, `security`, `kernel`)
- **Types**: PascalCase (`SandboxManager`, `CrashAnalysis`)
- **Functions**: camelCase (`readMemoryCurrent`, `detectAnomaly`)
- **Constants**: SCREAMING_SNAKE (`SECCOMP_RET_ALLOW`)
- **Interfaces**: -er suffix preferred (`io.Reader`, `io.Writer`)

### File Organization

- One primary type per file
- Related types in the same file
- Keep files under 500 lines when possible
- Use `_test.go` suffix for test files

---

## Testing

### Running Tests

```bash
# All tests
go test ./... -v

# Specific package
go test ./internal/security/... -v

# With race detector
go test -race ./... -v

# With coverage
go test ./... -coverprofile=coverage.out
go tool cover -func=coverage.out

# Benchmarks
go test -bench=. ./... -benchmem
```

### Writing Tests

```go
func TestReadMemoryCurrent(t *testing.T) {
    // Create temporary cgroup
    tmpDir := t.TempDir()
    cgroupPath := filepath.Join(tmpDir, "test")
    os.MkdirAll(cgroupPath, 0o755)
    os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte("268435456"), 0o644)
    os.WriteFile(filepath.Join(cgroupPath, "memory.current"), []byte("134217728"), 0o644)
    
    fe := NewForensicsEngine(t.TempDir())
    usage, err := fe.readMemoryCurrent(cgroupPath)
    if err != nil {
        t.Fatalf("readMemoryCurrent failed: %v", err)
    }
    
    if usage != 134217728 {
        t.Errorf("expected 134217728, got %d", usage)
    }
}
```

### Test Naming

```bash
# Unit tests
func TestSandboxCreate(t *testing.T) {}
func TestSandboxCreateInvalidConfig(t *testing.T) {}

# Table-driven tests
func TestSignalName(t *testing.T) {
    tests := []struct {
        input    int
        expected string
    }{
        {9, "SIGKILL"},
        {11, "SIGSEGV"},
        {15, "SIGTERM"},
    }
    for _, tt := range tests {
        t.Run(tt.expected, func(t *testing.T) {
            got := signalName(tt.input)
            if got != tt.expected {
                t.Errorf("signalName(%d) = %s, want %s", tt.input, got, tt.expected)
            }
        })
    }
}
```

### Integration Tests

Integration tests require Linux and root privileges:

```bash
# Run integration tests (requires root)
sudo go test ./tests/integration/... -v -tags=integration
```

---

## Pull Request Process

### 1. Create Feature Branch

```bash
git checkout -b feature/my-feature
# or
git checkout -b fix/my-bugfix
# or
git checkout -b docs/my-documentation
```

### 2. Make Changes

- Write code following coding standards
- Add tests for new functionality
- Update documentation if needed
- Ensure all tests pass

### 3. Commit

Write clear, concise commit messages:

```
<type>: <description>

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Formatting, no code change
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Build, CI, dependencies

Examples:
```
feat: add memory leak detection via linear regression
fix: resolve cgroup cleanup on timeout
docs: update API reference for /api/verify endpoint
test: add unit tests for signalName function
```

### 4. Push and Create PR

```bash
git push origin feature/my-feature
```

Then on GitHub:
1. Fill in PR template
2. Link related issues
3. Add screenshots for UI changes
4. Request review

### 5. Review Process

- All PRs require at least 1 review
- Security-related changes require 2 reviews
- CI must pass (build + tests)
- No merge conflicts

---

## Issue Guidelines

### Bug Reports

Include:
- AegisRuntime version (`aegis --version`)
- Linux kernel version (`uname -r`)
- Steps to reproduce
- Expected behavior
- Actual behavior
- Relevant logs

### Feature Requests

Include:
- Use case description
- Proposed API/CLI changes
- Security implications
- Performance impact

### Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

Email: security@aegisruntime.dev (or use GitHub Security Advisories)

Include:
- Description of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

---

## Security Policy

### Reporting Vulnerabilities

We take security seriously. If you discover a security vulnerability:

1. **Do NOT** open a public issue
2. Email security@aegisruntime.dev or use GitHub Security Advisories
3. Include detailed reproduction steps
4. We will respond within 48 hours
5. We will work with you on a fix before public disclosure

### Security Review Requirements

Changes to these packages require security review:
- `internal/security/*`
- `internal/kernel/*`
- `internal/sandbox/*`

### Threat Model

AegisRuntime assumes:
- The host kernel is trusted
- The root user is trusted
- AI-generated code is untrusted
- Network connections may be hostile

We protect against:
- Privilege escalation from sandbox
- Sandbox escape via syscalls
- Resource exhaustion (fork bombs, memory leaks)
- Code tampering (Ed25519 signing)
- Information leakage (EDR monitoring)

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

## Questions?

- Open a Discussion on GitHub
- Join our Discord (if available)
- Email: dev@aegisruntime.dev

Thank you for contributing!
