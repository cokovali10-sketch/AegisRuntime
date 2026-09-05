//go:build linux

package security

import (
	"encoding/json"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

type SeccompProfile struct {
	DefaultAction string        `json:"defaultAction"`
	Architectures []string      `json:"architectures"`
	Syscalls      []SyscallRule `json:"syscalls"`
}

type SyscallRule struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
	Args   []Arg    `json:"args,omitempty"`
}

type Arg struct {
	Index    uint   `json:"index"`
	Value    uint64 `json:"value"`
	ValueTwo uint64 `json:"valueTwo"`
	Op       string `json:"op"`
}

// BPF instruction
type bpfInstr struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

// BPF opcodes
const (
	BPF_LD   = 0x00
	BPF_W    = 0x00
	BPF_ABS  = 0x20
	BPF_JMP  = 0x05
	BPF_JEQ  = 0x10
	BPF_K    = 0x00
	BPF_RET  = 0x06
)

// Seccomp return values
const (
	SECCOMP_RET_ALLOW  = 0x7fff0000
	SECCOMP_RET_ERRNO  = 0x00050000
	SECCOMP_RET_KILL   = 0x00000000
	SECCOMP_RET_LOG    = 0x7ffc0000
	SECCOMP_RET_TRACE  = 0x7ff00000
)

// SockProg for seccomp
type sockProg struct {
	Len    uint16
	Filter *bpfInstr
}

const offsetof_seccomp_data_nr = 0

var BlockedByDefault = []string{
	"mount", "umount2", "pivot_root",
	"reboot", "kexec_load", "kexec_file_load",
	"init_module", "finit_module", "delete_module",
	"swapon", "swapoff",
	"sethostname", "setdomainname",
	"iopl", "ioperm",
	"pciconfig_read", "pciconfig_write",
	"usbdevfs",
	"kcmp", "process_vm_readv", "process_vm_writev",
	"ptrace",
	"keyctl",
	"add_key", "request_key",
	"uselib", "acct", "modify_ldt",
	"chroot",
	"sync", "syncfs",
	"syslog",
	"personality",
}

func DefaultProfile() *SeccompProfile {
	return &SeccompProfile{
		DefaultAction: "SCMP_ACT_ALLOW",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []SyscallRule{
			{Names: BlockedByDefault, Action: "SCMP_ACT_ERRNO"},
		},
	}
}

func AggressiveProfile() *SeccompProfile {
	allowed := []string{
		"read", "write", "open", "close", "stat", "fstat", "lstat",
		"poll", "lseek", "mmap", "mprotect", "munmap", "brk",
		"ioctl", "access", "pipe", "select", "sched_yield",
		"mremap", "msync", "mincore", "madvise",
		"dup", "dup2", "nanosleep",
		"getpid", "getuid", "getgid", "geteuid", "getegid",
		"getppid", "getpgrp", "setsid",
		"rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
		"clone", "fork", "vfork", "execve", "exit", "exit_group",
		"wait4", "kill", "uname", "fcntl", "flock",
		"getcwd", "chdir", "fchdir",
		"rename", "mkdir", "rmdir", "link", "unlink", "symlink", "readlink",
		"chmod", "fchmod", "chown", "fchown", "lchown",
		"umask", "gettimeofday", "getrlimit", "getrusage",
		"sysinfo", "times",
	}

	return &SeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []SyscallRule{
			{Names: allowed, Action: "SCMP_ACT_ALLOW"},
		},
	}
}

func MinimalProfile() *SeccompProfile {
	return &SeccompProfile{
		DefaultAction: "SCMP_ACT_ALLOW",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls:      nil,
	}
}

func ApplySeccomp(profile *SeccompProfile) error {
	if profile == nil {
		return nil
	}

	filter, err := compileFilter(profile)
	if err != nil {
		return fmt.Errorf("compile filter: %w", err)
	}

	if err := seccompSetAttr(filter); err != nil {
		return fmt.Errorf("set seccomp attr: %w", err)
	}

	if err := seccompLoad(); err != nil {
		return fmt.Errorf("load seccomp: %w", err)
	}

	return nil
}

func compileFilter(profile *SeccompProfile) ([]bpfInstr, error) {
	allowedSyscalls := make(map[string]bool)
	blockedSyscalls := make(map[string]bool)

	for _, rule := range profile.Syscalls {
		for _, name := range rule.Names {
			switch rule.Action {
			case "SCMP_ACT_ALLOW":
				allowedSyscalls[name] = true
			case "SCMP_ACT_ERRNO":
				blockedSyscalls[name] = true
			}
		}
	}

	if profile.DefaultAction == "SCMP_ACT_ALLOW" {
		return createAllowFilter(allowedSyscalls, blockedSyscalls), nil
	}
	return createDenyFilter(allowedSyscalls, blockedSyscalls), nil
}

func createDenyFilter(allowed, blocked map[string]bool) []bpfInstr {
	filter := []bpfInstr{
		{Code: BPF_LD | BPF_W | BPF_ABS, K: uint32(offsetof_seccomp_data_nr)},
	}

	for name := range blocked {
		if nr, ok := syscallToNr[name]; ok {
			filter = append(filter,
				bpfInstr{Code: BPF_LD | BPF_W | BPF_ABS, K: uint32(offsetof_seccomp_data_nr)},
				bpfInstr{Code: BPF_JMP | BPF_JEQ | BPF_K, Jt: 0, Jf: 1, K: uint32(nr)},
				bpfInstr{Code: BPF_RET | BPF_K, K: uint32(SECCOMP_RET_ERRNO | unix.EPERM)},
			)
		}
	}

	filter = append(filter,
		bpfInstr{Code: BPF_RET | BPF_K, K: uint32(SECCOMP_RET_ALLOW)},
	)

	return filter
}

func createAllowFilter(allowed, blocked map[string]bool) []bpfInstr {
	filter := []bpfInstr{
		{Code: BPF_LD | BPF_W | BPF_ABS, K: uint32(offsetof_seccomp_data_nr)},
	}

	for name := range blocked {
		if nr, ok := syscallToNr[name]; ok {
			filter = append(filter,
				bpfInstr{Code: BPF_LD | BPF_W | BPF_ABS, K: uint32(offsetof_seccomp_data_nr)},
				bpfInstr{Code: BPF_JMP | BPF_JEQ | BPF_K, Jt: 0, Jf: 1, K: uint32(nr)},
				bpfInstr{Code: BPF_RET | BPF_K, K: uint32(SECCOMP_RET_ERRNO | unix.EPERM)},
			)
		}
	}

	filter = append(filter,
		bpfInstr{Code: BPF_RET | BPF_K, K: uint32(SECCOMP_RET_ALLOW)},
	)

	return filter
}

func seccompSetAttr(filter []bpfInstr) error {
	prog := &sockProg{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}

	sockFD, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("create socket: %w", err)
	}
	defer unix.Close(sockFD)

	_, _, errno := unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(sockFD),
		uintptr(unix.SOL_SOCKET),
		uintptr(unix.SO_ATTACH_FILTER),
		uintptr(unsafe.Pointer(prog)),
		uintptr(unsafe.Sizeof(*prog)),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("setsockopt: %w", errno)
	}

	return nil
}

func seccompLoad() error {
	_, _, errno := unix.Syscall6(
		unix.SYS_PRCTL,
		uintptr(unix.PR_SET_SECCOMP),
		uintptr(unix.SECCOMP_MODE_FILTER),
		0, 0, 0, 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func LoadProfile(path string) (*SeccompProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}

	var profile SeccompProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("parse profile: %w", err)
	}

	return &profile, nil
}

func SaveProfile(profile *SeccompProfile, path string) error {
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal profile: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write profile: %w", err)
	}

	return nil
}

var syscallToNr = map[string]int{
	"read": 0, "write": 1, "open": 2, "close": 3, "stat": 4, "fstat": 5,
	"lstat": 6, "poll": 7, "lseek": 8, "mmap": 9, "mprotect": 10, "munmap": 11,
	"brk": 12, "ioctl": 16, "access": 21, "pipe": 22, "select": 23,
	"sched_yield": 24, "mremap": 25, "msync": 26, "mincore": 27, "madvise": 28,
	"shmget": 29, "shmat": 30, "shmctl": 31, "dup": 32, "dup2": 33,
	"pause": 34, "nanosleep": 35, "getitimer": 36, "alarm": 37, "setitimer": 38,
	"getpid": 39, "sendfile": 40, "socket": 41, "connect": 42, "accept": 43,
	"sendto": 44, "recvfrom": 45, "sendmsg": 46, "recvmsg": 47, "shutdown": 48,
	"bind": 49, "listen": 50, "getsockname": 51, "getpeername": 52,
	"socketpair": 53, "setsockopt": 54, "getsockopt": 55, "clone": 56,
	"fork": 57, "vfork": 58, "execve": 59, "exit": 60, "wait4": 61,
	"kill": 62, "uname": 63, "semget": 64, "semop": 65, "semctl": 66,
	"shmdt": 67, "msgget": 68, "msgsnd": 69, "msgrcv": 70, "msgctl": 71,
	"fcntl": 72, "flock": 73, "fsync": 74, "fdatasync": 75, "truncate": 76,
	"ftruncate": 77, "getdents": 78, "getcwd": 79, "chdir": 80, "fchdir": 81,
	"rename": 82, "mkdir": 83, "rmdir": 84, "creat": 85, "link": 86,
	"unlink": 87, "symlink": 88, "readlink": 89, "chmod": 90, "fchmod": 91,
	"chown": 92, "fchown": 93, "lchown": 94, "umask": 95, "gettimeofday": 96,
	"getrlimit": 97, "getrusage": 98, "sysinfo": 99, "times": 100,
	"ptrace": 101, "getuid": 102, "syslog": 103, "getgid": 104,
	"setuid": 105, "setgid": 106, "geteuid": 107, "getegid": 108,
	"setpgid": 109, "getppid": 110, "getpgrp": 111, "setsid": 112,
	"setreuid": 113, "setregid": 114, "getgroups": 115, "setgroups": 116,
	"setresuid": 117, "getresuid": 118, "setresgid": 119, "getresgid": 120,
	"getpgid": 121, "setfsuid": 122, "setfsgid": 123, "getsid": 124,
	"capget": 125, "capset": 126, "rt_sigpending": 127, "rt_sigtimedwait": 128,
	"rt_sigqueueinfo": 129, "rt_sigsuspend": 130, "sigaltstack": 131,
	"utime": 132, "mount": 165, "umount2": 166, "swapon": 167, "swapoff": 168,
	"reboot": 169, "sethostname": 170, "setdomainname": 171, "iopl": 172,
	"ioperm": 173, "create_module": 174, "init_module": 175, "delete_module": 176,
	"get_kernel_syms": 177, "query_module": 178, "quotactl": 179, "nfsservctl": 180,
	"pivot_root": 155, "_sysctl": 156, "prctl": 157, "arch_prctl": 158,
	"adjtimex": 159, "setrlimit": 160, "chroot": 161, "sync": 162, "acct": 163,
	"settimeofday": 164, "getdents64": 217, "personality": 136, "uselib": 134,
	"modify_ldt": 154, "mlock": 149, "munlock": 150, "mlockall": 151,
	"munlockall": 152, "vhangup": 153, "keyctl": 250, "add_key": 248,
	"request_key": 249, "syncfs": 306, "process_vm_readv": 310,
	"process_vm_writev": 311, "kcmp": 312,
}
