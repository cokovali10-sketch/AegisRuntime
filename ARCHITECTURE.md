# AegisRuntime Architecture

Deep technical documentation of the AegisRuntime internals.

---

## Table of Contents

- [System Overview](#system-overview)
- [Kernel Interface Layer](#kernel-interface-layer)
- [Namespace Isolation](#namespace-isolation)
- [Cgroup Resource Control](#cgroup-resource-control)
- [Seccomp-BPF Filtering](#seccomp-bpf-filtering)
- [Capability Management](#capability-management)
- [Sandbox Lifecycle](#sandbox-lifecycle)
- [Memory Forensics Engine](#memory-forensics-engine)
- [EDR Monitoring](#edr-monitoring)
- [Cryptographic Signing](#cryptographic-signing)
- [Self-Healing Crash Analysis](#self-healing-crash-analysis)
- [API & WebSocket Architecture](#api--websocket-architecture)
- [Filesystem Layout](#filesystem-layout)
- [Syscall Reference](#syscall-reference)

---

## System Overview

AegisRuntime is a zero-dependency, single-binary Linux runtime that creates isolated sandboxes using raw Linux kernel primitives. It does not use container runtimes (runc, crun) or require a daemon (dockerd, containerd).

### Component Interaction Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           USER SPACE                                      │
│                                                                           │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────────────┐  │
│  │  CLI       │  │  REST API  │  │ WebSocket  │  │  HTML Dashboard    │  │
│  │  (15 cmds) │  │ (23+ eps)  │  │  Stream    │  │  (embedded SPA)    │  │
│  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────────┬──────────┘  │
│        │               │               │                    │             │
│        └───────────────┴───────────────┴────────────────────┘             │
│                              │                                            │
│                    ┌─────────▼──────────┐                                 │
│                    │  SandboxManager    │                                 │
│                    │  (core orchestrator)│                                 │
│                    └──┬──────┬──────┬───┘                                 │
│                       │      │      │                                     │
│        ┌──────────────┘      │      └──────────────┐                     │
│        ▼                     ▼                      ▼                     │
│  ┌──────────┐        ┌──────────┐          ┌──────────────┐              │
│  │ Security │        │ Kernel   │          │  Forensics   │              │
│  │ Subsystem│        │ Subsystem│          │  Engine      │              │
│  └────┬─────┘        └────┬─────┘          └──────┬───────┘              │
│       │                   │                       │                       │
│       │         ┌─────────┼─────────┐             │                       │
│       │         │         │         │             │                       │
│       ▼         ▼         ▼         ▼             ▼                       │
│  ┌────────┐┌────────┐┌────────┐┌────────┐┌────────────┐                  │
│  │Seccomp ││Caps    ││Signing ││  EDR   ││ Memory     │                  │
│  │  BPF   ││ Drop   ││Ed25519 ││Monitor ││ Profiler   │                  │
│  └────────┘└────────┘└────────┘└────────┘└────────────┘                  │
│                                                                           │
└──────────────────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │    LINUX KERNEL     │
                    │  ────────────────  │
                    │  • clone3()        │
                    │  • pivot_root()    │
                    │  • cgroup v2       │
                    │  • seccomp(BPF)    │
                    │  • prctl()         │
                    │  • inotify         │
                    │  • /proc/*         │
                    └────────────────────┘
```

---

## Kernel Interface Layer

### Primitives Used

| Kernel Feature | Systemcall/Interface | Purpose |
|---------------|---------------------|---------|
| Process isolation | `clone(CLONE_NEWPID)` | PID namespace |
| Filesystem isolation | `clone(CLONE_NEWNS)` + `pivot_root()` | Mount namespace |
| Network isolation | `clone(CLONE_NEWNET)` | Network namespace |
| Hostname isolation | `clone(CLONE_NEWUTS)` + `sethostname()` | UTS namespace |
| Resource limits | cgroup v2 (`memory.max`, `cpu.max`, `pids.max`) | Resource control |
| Syscall filtering | `seccomp(SECCOMP_SET_MODE_FILTER)` | seccomp-BPF |
| Capability dropping | `capset()` + `prctl(PR_CAPBSET_DROP)` | Capability restriction |
| No new privileges | `prctl(PR_SET_NO_NEW_PRIVS)` | Privilege restriction |
| File monitoring | `inotify_init1(IN_MODIFY)` | EDR filesystem watch |
| Process info | `/proc/<pid>/status`, `/proc/<pid>/mem` | Forensics |

### Syscall Flow

```
User calls `aegis run --agent-id x -- python3 script.py`
    │
    ├─ 1. Parse CLI flags
    ├─ 2. Create SandboxConfig
    ├─ 3. SandboxManager.Create()
    │       ├─ Create cgroup: /sys/fs/cgroup/aegis-<id>/
    │       │   ├─ Write cpu.max: "50000 100000"
    │       │   ├─ Write memory.max: "268435456"
    │       │   └─ Write pids.max: "64"
    │       └─ Create rootfs directory structure
    │
    ├─ 4. SandboxManager.Run()
    │       ├─ Fork child process
    │       ├─ In child: unshare(CLONE_NEWPID|CLONE_NEWNS|CLONE_NEWNET|CLONE_NEWUTS)
    │       ├─ In child: setup_mount_namespace(rootfs)
    │       ├─ In child: pivot_root(rootfs, putold)
    │       ├─ In child: apply seccomp filter (BPF program)
    │       ├─ In child: drop capabilities (capset + PR_CAPBSET_DROP)
    │       ├─ In child: set PR_SET_NO_NEW_PRIVS
    │       ├─ In child: execve(command)
    │       └─ In parent: start monitoring goroutines
    │
    ├─ 5. Monitor (parent process)
    │       ├─ poll cgroup v2 memory.current (10ms)
    │       ├─ watch /proc/<pid>/net for connections
    │       ├─ watch filesystem via inotify
    │       └─ emit events to WebSocket stream
    │
    └─ 6. On exit
            ├─ Collect exit status + signal
            ├─ Run crash analysis (SelfHealer)
            ├─ Generate crash report JSON
            ├─ Cleanup cgroup
            └─ Return SandboxResult
```

---

## Namespace Isolation

### PID Namespace

When `CLONE_NEWPID` is specified, the child process becomes PID 1 inside the namespace. It cannot see processes outside the namespace.

```go
// internal/kernel/namespaces.go
func CloneFlags(cfg NamespaceConfig) uintptr {
    var flags uintptr
    if cfg.EnablePID   { flags |= unix.CLONE_NEWPID }
    if cfg.EnableMount { flags |= unix.CLONE_NEWNS }
    if cfg.EnableUTS   { flags |= unix.CLONE_NEWUTS }
    if cfg.EnableNet   { flags |= unix.CLONE_NEWNET }
    if cfg.EnableUser  { flags |= unix.CLONE_NEWUSER }
    return flags
}
```

### Mount Namespace + pivot_root

The sandbox creates a new mount namespace and uses `pivot_root()` to switch the root filesystem. This prevents the process from accessing the host filesystem.

```
Before pivot_root:
  /                    (host root)
  /var/lib/aegis/<id>/rootfs/   (sandbox rootfs)

After pivot_root:
  /                    (sandbox rootfs)
  /proc                (procfs mounted)
  /dev                 (devtmpfs mounted)
  /sys                 (sysfs mounted, read-only)
  /tmp                 (tmpfs, mode 01777)
```

### Network Namespace

Creates a completely isolated network stack. The sandbox gets:
- Its own loopback interface
- Its own routing table
- No access to host network unless explicitly configured

---

## Cgroup Resource Control

### cgroup v2 Hierarchy

```
/sys/fs/cgroup/
├── aegis-<sandbox-id>/
│   ├── cpu.max          # "50000 100000" (50ms per 100ms period)
│   ├── memory.max       # "268435456" (256MB)
│   ├── memory.current   # current usage (polled at 10ms)
│   ├── pids.max         # "64"
│   ├── io.max           # I/O limits
│   ├── cgroup.procs     # contains child PID
│   └── cgroup.kill      # write 1 to OOM-kill
```

### CPU Quota Format

```
cpu.max = "<quota> <period>"
  quota:   microseconds allowed per period
  period:  microseconds per period (default 100000 = 100ms)

Example: "50000 100000" = 50% of one CPU core
Example: "200000 100000" = 200% (2 cores)
```

### Memory Limits

```
memory.max = "<bytes>"

When usage exceeds memory.max:
  1. cgroup v2 triggers OOM
  2. Forensics engine captures memory.dump
  3. Crash report generated
  4. Process killed with SIGKILL
```

---

## Seccomp-BPF Filtering

### Filter Compilation Pipeline

```
SecurityPolicy JSON
       │
       ▼
┌──────────────────┐
│ compileFilter()  │
│  • Parse rules   │
│  • Map syscall   │
│    names to NR   │
│  • Generate BPF  │
│    instructions  │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ BPF Bytecode     │
│  • LD | ABS      │
│  • JEQ           │
│  • RET ALLOW/    │
│    ERRNO         │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ setsockopt()     │
│ SO_ATTACH_FILTER │
│ on fake socket   │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ prctl()          │
│ PR_SET_SECCOMP   │
│ SECCOMP_MODE_    │
│ FILTER           │
└──────────────────┘
```

### BPF Instruction Format

```c
struct sock_filter {
    __u16 code;   // Operation code (BPF_LD, BPF_JMP, BPF_RET)
    __u8  jt;     // Jump if true
    __u8  jf;     // Jump if false
    __u32 k;      // Constant/operand
};
```

### Example: Blocking mount() syscall

```
BPF_LD  | BPF_W | BPF_ABS   k=0          ; Load syscall number
BPF_JMP | BPF_JEQ | BPF_K   jf=1  k=165  ; If NR != 165 (mount), skip
BPF_RET | BPF_K              k=0x00050002  ; SECCOMP_RET_ERRNO | EPERM
BPF_RET | BPF_K              k=0x7fff0000  ; SECCOMP_RET_ALLOW
```

---

## Capability Management

### Default Capabilities

**Kept (13):**
- `CAP_CHOWN`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER`, `CAP_FSETID`
- `CAP_KILL`, `CAP_SETGID`, `CAP_SETUID`, `CAP_SETPCAP`
- `CAP_NET_BIND_SERVICE`, `CAP_SYS_CHROOT`, `CAP_MKNOD`
- `CAP_AUDIT_WRITE`, `CAP_SETFCAP`

**Dropped (18):**
- `CAP_SYS_MODULE`, `CAP_SYS_RAWIO`, `CAP_SYS_ADMIN`, `CAP_SYS_BOOT`
- `CAP_SYS_NICE`, `CAP_SYS_RESOURCE`, `CAP_SYS_TIME`, `CAP_SYS_TTY_CONFIG`
- `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_IPC_LOCK`, `CAP_IPC_OWNER`
- `CAP_SYS_PTRACE`, `CAP_SYS_PACCT`, `CAP_LINUX_IMMUTABLE`
- `CAP_DAC_READ_SEARCH`, `CAP_LEASE`, `CAP_AUDIT_CONTROL`

### Aggressive Mode

Only `CAP_SETUID` and `CAP_SETGID` are kept. All others dropped.

### Implementation

Uses raw `SYS_CAPGET`/`SYS_CAPSET` syscalls via `golang.org/x/sys/unix`:

```go
type capHeader struct {
    Version uint32  // 0x20080522
    Pid     int32   // getpid()
}

type capData struct {
    Effective   uint32
    Permitted   uint32
    Inheritable uint32
}
```

---

## Sandbox Lifecycle

### State Machine

```
CREATE ──▶ CONFIGURING ──▶ RUNNING ──▶ COMPLETED
                │               │
                │               ├──▶ SNAPSHOT ──▶ RUNNING (continued)
                │               │
                │               └──▶ ROLLBACK ──▶ RUNNING (restored)
                │
                └──▶ FAILED (on error)
```

### Snapshot Mechanism

Snapshots use `tar.gz` archives of the rootfs:

```go
func CreateSnapshot(containerID, rootfsPath, snapshotDir string) (*Snapshot, error) {
    // 1. Create tar.gz from rootfsPath
    // 2. Save metadata JSON alongside
    // 3. Return snapshot with ID
}

func RestoreSnapshot(snapshot *Snapshot, rootfsPath string) error {
    // 1. Remove current rootfs
    // 2. Extract tar.gz
    // 3. Verify permissions
}
```

---

## Memory Forensics Engine

### Monitoring Pipeline

```
cgroup v2 memory.current
    │
    ▼  (every 10ms via time.Ticker)
┌─────────────────────────┐
│  sampleMemoryUsage()    │
│  • Read memory.current  │
│  • Append to samples    │
│  • Calculate growth rate│
└────────────┬────────────┘
             │
    ┌────────┴────────────┐
    │                     │
    ▼                     ▼
┌──────────────┐   ┌──────────────┐
│ > 80% limit  │   │ > 50% in <1s │
│ → WARNING    │   │ → EMERGENCY  │
│ event        │   │ • Kill PID   │
└──────────────┘   │ • Dump /proc │
                   │ • Crash Rpt  │
                   └──────────────┘
```

### Fork Bomb Detection

```go
// Track clone count per container
cloneCount := map[string]int{}
lastCheck := time.Now()

func detectForkBomb(containerID string) bool {
    current := readCloneCount(containerID)
    if current - lastCount > 15 && time.Since(lastCheck) < 3*time.Second {
        return true  // Fork bomb detected
    }
    lastCount = current
    return false
}
```

### Memory Leak Detection (Linear Regression)

```go
// 20-sample sliding window
func detectMemoryLeak(samples []MemorySample) bool {
    if len(samples) < 20 { return false }
    
    n := len(samples)
    sumX, sumY, sumXY, sumX2, sumY2 := 0.0, 0.0, 0.0, 0.0, 0.0
    for i, s := range samples {
        x := float64(i)
        y := float64(s.CurrentBytes) / 1048576.0  // Convert to MB
        sumX += x; sumY += y
        sumXY += x * y; sumX2 += x * x; sumY2 += y * y
    }
    
    // Pearson correlation
    r := (n*sumXY - sumX*sumY) / math.Sqrt((n*sumX2-sumX*sumX)*(n*sumY2-sumY*sumY))
    rSquared := r * r
    slope := (n*sumXY - sumX*sumY) / (n*sumX2 - sumX*sumX)
    
    return rSquared > 0.95 && slope > 0.5  // Strong linear growth
}
```

---

## EDR Monitoring

### Three Watch Channels

| Channel | Method | What It Watches |
|---------|--------|-----------------|
| **Filesystem** | `inotify_init1()` + `IN_MODIFY` | File create/modify/delete in rootfs |
| **Network** | `/proc/<pid>/net/tcp`, `/proc/<pid>/net/udp` | New connections, binds |
| **Process** | `/proc/<pid>/status`, `/proc/<pid>/cmdline` | Process creation, exec |

### Event Structure

```go
type AuditEvent struct {
    Timestamp   time.Time  `json:"timestamp"`
    Type        string     `json:"type"`      // "file", "network", "process", "syscall"
    Action      string     `json:"action"`     // "create", "modify", "connect", "bind"
    Target      string     `json:"target"`     // file path or IP:port
    Details     string     `json:"details"`    // additional context
    Severity    string     `json:"severity"`   // "low", "medium", "high", "critical"
    ContainerID string     `json:"container_id"`
}
```

### Detection Rules

8 default rules in `internal/edr/rules.go`:

1. **Critical file access** — `/etc/passwd`, `/etc/shadow`, `/root/.ssh`
2. **Network to metadata** — `169.254.169.254` (AWS), `metadata.google.internal` (GCP)
3. **Dangerous commands** — `rm -rf /`, `dd if=/dev/zero`, fork bombs
4. **Container escape** — Access to `/proc/sys`, `/sys/kernel`, `/dev/mem`
5. **Socket manipulation** — Docker socket, raw sockets
6. **Capability abuse** — `capsh`, `setcap` usage
7. **Module loading** — `insmod`, `modprobe` attempts
8. **Privilege escalation** — `su`, `sudo`, `chown root` attempts

---

## Cryptographic Signing

### Ed25519 Key Management

```
~/.aegis/keys/
├── agent1.key     # Ed25519 private key (64 bytes)
├── agent1.pub     # Ed25519 public key (32 bytes)
├── agent2.key
└── agent2.pub
```

### Signing Flow

```
File → SHA-256 hash → Ed25519 sign(hash, privateKey) → .sig JSON file
```

### Signature Format

```json
{
  "version": 1,
  "algorithm": "Ed25519",
  "public_key": "hex-encoded-32-byte-public-key",
  "signature": "hex-encoded-64-byte-signature",
  "content_hash": "hex-encoded-sha256-of-file",
  "signed_at": "2026-09-05T12:00:00Z",
  "signed_by": "agent1",
  "file_path": "/path/to/script.py",
  "file_size": 1234
}
```

### Verification Flow

```
aegis verify script.py
    │
    ├─ 1. Load script.py.sig
    ├─ 2. Compute SHA-256(script.py)
    ├─ 3. Compare with signature.content_hash
    ├─ 4. Ed25519.Verify(publicKey, hash, signature)
    ├─ 5. Return valid/invalid
    │
    └─ If --require-signature and invalid → exit 1
```

---

## Self-Healing Crash Analysis

### Diagnosis Rule Engine

```
stderr + syscalls
    │
    ▼
┌──────────────────────────┐
│  matchRule() per rule    │
│  • regex pattern match   │
│  • signal categorization │
│  • compilation check     │
│  • Go panic parse        │
│  • Python traceback parse│
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│  CrashAnalysis JSON      │
│  • severity              │
│  • category              │
│  • diagnosis             │
│  • fix_suggestions[]     │
└──────────────────────────┘
```

### 14 Diagnosis Rules

| # | Pattern Match | Category | Severity | Suggestion |
|---|--------------|----------|----------|------------|
| 1 | `SIGSEGV` | segfault | critical | Null pointer check, array bounds, alignment |
| 2 | `SIGABRT` | abort | high | Assert failure, double-free, heap corruption |
| 3 | `SIGBUS` | bus error | high | Memory alignment, mmap failure |
| 4 | `SIGFPE` | float error | high | Division by zero check |
| 5 | `OOM\|out of memory` | oom | critical | Reduce allocation, increase --memory |
| 6 | `seccomp\|EPERM` | seccomp | high | Add syscall to allowlist or use alternative |
| 7 | `timeout\|deadline exceeded` | timeout | medium | Optimize algorithm, reduce I/O |
| 8 | `index out of range` | panic | high | Check array/slice bounds |
| 9 | `nil pointer dereference` | panic | high | Add nil check before use |
| 10 | `stack overflow` | panic | high | Reduce recursion depth |
| 11 | `fatal error: runtime goroutines` | panic | high | Check for goroutine leak |
| 12 | `SyntaxError` | compilation | medium | Fix syntax at reported line |
| 13 | `IndentationError` | compilation | medium | Fix indentation |
| 14 | `IndentationError\|TabError` | compilation | medium | Fix whitespace |

### Agent Retry Hint Generation

```json
{
  "retry_hints": {
    "fix_description": "Your script crashed with SIGSEGV at address 0x0",
    "suggested_fix": "Add null check before dereferencing pointer",
    "example_fix": "if ptr != nil { ptr.method() }",
    "resource_hint": "Consider increasing --memory if OOM",
    "can_retry": true
  }
}
```

---

## API & WebSocket Architecture

### HTTP Server

```
net/http server
    │
    ├─ /api/health          → JSON health response
    ├─ /api/sandbox         → POST: create sandbox
    ├─ /api/sandbox/:id     → GET: sandbox status
    ├─ /api/sandbox/:id/stop → POST: stop sandbox
    ├─ /api/sandbox/:id/events → GET: audit events
    ├─ /api/sandbox/:id/snapshot → POST: create snapshot
    ├─ /api/sandbox/:id/rollback → POST: rollback
    ├─ /api/policies        → GET/POST: policy management
    ├─ /api/agents          → GET: active agents
    ├─ /api/stats           → GET: system stats
    ├─ /api/ws              → WebSocket: audit stream
    ├─ /api/dashboard       → GET: HTML dashboard
    ├─ /api/sign            → POST: sign artifact
    ├─ /api/verify          → POST: verify artifact
    └─ /api/diagnose        → POST: crash analysis
```

### WebSocket Message Protocol

```json
// Server → Client
{
  "type": "syscall",
  "timestamp": "2026-09-05T12:00:00.123Z",
  "data": {
    "container_id": "sandbox-a1b2c3d4",
    "pid": 12345,
    "syscall": "write",
    "args": [1, "Hello", 5],
    "result": 5
  }
}

// Client → Server
{
  "type": "subscribe",
  "data": { "container_id": "sandbox-a1b2c3d4" }
}
```

### Dashboard Architecture

The dashboard is an embedded single-page application served from Go:

```go
// internal/api/dashboard.go
const DashboardHTML = `<!DOCTYPE html>
<html>
  <body>
    <!-- WebSocket connection to /api/ws -->
    <!-- Canvas chart for CPU/RAM -->
    <!-- Terminal panel for syscall stream -->
    <!-- Events panel for security events -->
  </body>
</html>`
```

---

## Filesystem Layout

### Host Filesystem

```
/var/lib/aegis/                          # AEGIS_ROOT
├── images/                              # Base images (future)
├── containers/
│   └── sandbox-<id>/
│       ├── rootfs/                       # Sandbox root filesystem
│       │   ├── bin/
│       │   ├── lib/
│       │   ├── usr/
│       │   ├── proc/                     # Mounted procfs
│       │   ├── dev/                      # Mounted devtmpfs
│       │   ├── sys/                      # Mounted sysfs (ro)
│       │   ├── tmp/                      # Mounted tmpfs
│       │   └── <application files>
│       ├── snapshots/                    # Snapshot archives
│       │   ├── snap-<timestamp>.tar.gz
│       │   └── snap-<timestamp>.meta.json
│       └── state.json                    # Sandbox metadata
├── dumps/                               # Memory dumps
│   └── <container-id>-<timestamp>.dump
├── keys/                                # Ed25519 key pairs
│   ├── <name>.key                       # Private key
│   └── <name>.pub                       # Public key
└── reports/                             # Crash reports
    └── <container-id>.json
```

### cgroup Hierarchy

```
/sys/fs/cgroup/
└── aegis-<sandbox-id>/
    ├── cpu.max                           # CPU quota
    ├── cpu.stat                          # CPU statistics
    ├── memory.max                        # Memory limit
    ├── memory.current                    # Current usage
    ├── memory.stat                       # Memory statistics
    ├── pids.max                          # PID limit
    ├── pids.current                      # Current PID count
    ├── io.max                            # I/O limits
    ├── io.stat                           # I/O statistics
    ├── cgroup.procs                      # Member PIDs
    ├── cgroup.kill                       # Kill all members
    └── cgroup.events                     #/populated, frozen
```

---

## Syscall Reference

### Linux Syscalls Used by AegisRuntime

| Syscall | Constant | Purpose | Package |
|---------|----------|---------|---------|
| `clone3` | `SYS_CLONE` | Create child process with namespaces | kernel |
| `pivot_root` | — | Switch root filesystem | kernel |
| `mount` | — | Mount procfs, devtmpfs, sysfs, tmpfs | kernel |
| `umount2` | — | Unmount filesystems on cleanup | kernel |
| `sethostname` | — | Set UTS namespace hostname | kernel |
| `prctl` | `SYS_PRCTL` | PR_SET_NO_NEW_PRIVS, PR_CAPBSET_DROP, PR_SET_SECCOMP | security |
| `capget` | `SYS_CAPGET` | Read capability state | security |
| `capset` | `SYS_CAPSET` | Modify capability state | security |
| `setsockopt` | `SYS_SETSOCKOPT` | Attach seccomp filter | security |
| `kill` | `SYS_KILL` | Send SIGKILL to sandboxed process | sandbox |
| `wait4` | `SYS_WAIT4` | Collect exit status | sandbox |
| `inotify_init1` | — | Create inotify instance | edr |
| `inotify_add_watch` | — | Add filesystem watch | edr |
| `read` | `SYS_READ` | Read inotify events, /proc entries | edr |
| `write` | `SYS_WRITE` | Write cgroup controls | kernel |
| `openat` | `SYS_OPENAT` | Open /proc, /sys files | kernel |

### BPF Instructions Used

| Opcode | Value | Purpose |
|--------|-------|---------|
| `BPF_LD` | 0x00 | Load from packet/data |
| `BPF_W` | 0x00 | Word (4 bytes) |
| `BPF_ABS` | 0x20 | Absolute offset |
| `BPF_JMP` | 0x05 | Jump instruction |
| `BPF_JEQ` | 0x10 | Jump if equal |
| `BPF_K` | 0x00 | Use constant |
| `BPF_RET` | 0x06 | Return value |

### Seccomp Return Values

| Value | Constant | Meaning |
|-------|----------|---------|
| `0x00000000` | `SECCOMP_RET_KILL` | Kill process immediately |
| `0x00050000` | `SECCOMP_RET_ERRNO` | Return errno (EPERM) |
| `0x7fff0000` | `SECCOMP_RET_ALLOW` | Allow syscall |
| `0x7ffc0000` | `SECCOMP_RET_LOG` | Allow but log |
| `0x7ff00000` | `SECCOMP_RET_TRACE` | Notify tracer |

---

## Binary Footprint

```
$ ls -lh aegis
-rwxr-xr-x 1 user user 14M Sep  5 12:00 aegis

$ go version
go version go1.22.0 linux/amd64

$ file aegis
aegis: ELF 64-bit LSB executable, x86-64, Go Thumb, statically linked
```

The single binary contains:
- All kernel interaction code
- seccomp-BPF compiler
- Ed25519 cryptography
- WebSocket server
- Embedded HTML dashboard
- Memory forensics engine
- Self-healing crash analyzer
- 14 diagnosis rules
- 8 default EDR detection rules

No external dependencies at runtime. No shared libraries. No daemon. Just the binary and the Linux kernel.
