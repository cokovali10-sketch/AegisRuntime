//go:build linux

package security

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	CAP_CHOWN = iota
	CAP_DAC_OVERRIDE
	CAP_DAC_READ_SEARCH
	CAP_FOWNER
	CAP_FSETID
	CAP_KILL
	CAP_SETGID
	CAP_SETUID
	CAP_SETPCAP
	CAP_LINUX_IMMUTABLE
	CAP_NET_BIND_SERVICE
	CAP_NET_BROADCAST
	CAP_NET_ADMIN
	CAP_NET_RAW
	CAP_IPC_LOCK
	CAP_IPC_OWNER
	CAP_SYS_MODULE
	CAP_SYS_RAWIO
	CAP_SYS_CHROOT
	CAP_SYS_PTRACE
	CAP_SYS_PACCT
	CAP_SYS_ADMIN
	CAP_SYS_BOOT
	CAP_SYS_NICE
	CAP_SYS_RESOURCE
	CAP_SYS_TIME
	CAP_SYS_TTY_CONFIG
	CAP_MKNOD
	CAP_LEASE
	CAP_AUDIT_WRITE
	CAP_AUDIT_CONTROL
	CAP_SETFCAP
)

type CapabilitiesConfig struct {
	Keep []string `json:"keep"`
	Drop []string `json:"drop"`
}

func DefaultCapabilities() *CapabilitiesConfig {
	return &CapabilitiesConfig{
		Keep: []string{
			"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID",
			"CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP",
			"CAP_NET_BIND_SERVICE", "CAP_SYS_CHROOT", "CAP_MKNOD",
			"CAP_AUDIT_WRITE", "CAP_SETFCAP",
		},
		Drop: []string{
			"CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_ADMIN", "CAP_SYS_BOOT",
			"CAP_SYS_NICE", "CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG",
			"CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER",
			"CAP_SYS_PTRACE", "CAP_SYS_PACCT", "CAP_LINUX_IMMUTABLE",
			"CAP_DAC_READ_SEARCH", "CAP_LEASE", "CAP_AUDIT_CONTROL",
		},
	}
}

func AggressiveCapabilities() *CapabilitiesConfig {
	return &CapabilitiesConfig{
		Keep: []string{"CAP_SETUID", "CAP_SETGID"},
		Drop: []string{
			"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER",
			"CAP_FSETID", "CAP_KILL", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
			"CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW",
			"CAP_IPC_LOCK", "CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO",
			"CAP_SYS_CHROOT", "CAP_SYS_PTRACE", "CAP_SYS_PACCT", "CAP_SYS_ADMIN",
			"CAP_SYS_BOOT", "CAP_SYS_NICE", "CAP_SYS_RESOURCE", "CAP_SYS_TIME",
			"CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE", "CAP_AUDIT_WRITE",
			"CAP_AUDIT_CONTROL", "CAP_SETFCAP",
		},
	}
}

type capHeader struct {
	Version uint32
	Pid     int32
}

type capData struct {
	Effective   uint32
	Permitted   uint32
	Inheritable uint32
}

func capGet(hdr *capHeader, data *capData) error {
	_, _, errno := unix.Syscall(unix.SYS_CAPGET, uintptr(unsafe.Pointer(hdr)), uintptr(unsafe.Pointer(data)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func capSet(hdr *capHeader, data *capData) error {
	_, _, errno := unix.Syscall(unix.SYS_CAPSET, uintptr(unsafe.Pointer(hdr)), uintptr(unsafe.Pointer(data)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func ApplyCapabilities(cfg CapabilitiesConfig) error {
	capsToDrop := make(map[int]bool)
	for _, name := range cfg.Drop {
		num, err := CapNumber(name)
		if err != nil {
			return fmt.Errorf("invalid capability %s: %w", name, err)
		}
		capsToDrop[num] = true
	}

	if err := dropBoundingSet(capsToDrop); err != nil {
		return fmt.Errorf("drop bounding set: %w", err)
	}

	if err := modifyCapSet(capsToDrop, func(d *capData, bit uint) { d.Inheritable &^= (1 << bit) }); err != nil {
		return fmt.Errorf("drop inheritable set: %w", err)
	}

	if err := modifyCapSet(capsToDrop, func(d *capData, bit uint) { d.Permitted &^= (1 << bit) }); err != nil {
		return fmt.Errorf("drop permitted set: %w", err)
	}

	if err := modifyCapSet(capsToDrop, func(d *capData, bit uint) { d.Effective &^= (1 << bit) }); err != nil {
		return fmt.Errorf("drop effective set: %w", err)
	}

	return nil
}

func dropBoundingSet(capsToDrop map[int]bool) error {
	for cap := range capsToDrop {
		_, _, errno := unix.Syscall6(
			unix.SYS_PRCTL,
			uintptr(unix.PR_CAPBSET_DROP),
			uintptr(cap),
			0, 0, 0, 0,
		)
		if errno != 0 {
			return fmt.Errorf("drop bounding set cap %d: %w", cap, errno)
		}
	}
	return nil
}

func modifyCapSet(capsToDrop map[int]bool, modifier func(*capData, uint)) error {
	var hdr capHeader
	var data [2]capData

	hdr.Version = 0x20080522
	hdr.Pid = int32(os.Getpid())

	if err := capGet(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capget: %w", err)
	}

	for cap := range capsToDrop {
		word := cap / 32
		bit := uint(cap % 32)
		if word < 2 {
			modifier(&data[word], bit)
		}
	}

	if err := capSet(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}

	return nil
}

func DropCapability(cap int) error {
	var hdr capHeader
	var data [2]capData

	hdr.Version = 0x20080522
	hdr.Pid = int32(os.Getpid())

	if err := capGet(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capget: %w", err)
	}

	word := cap / 32
	bit := uint(cap % 32)

	if word >= 2 {
		return fmt.Errorf("capability %d out of range", cap)
	}

	data[word].Effective &^= (1 << bit)
	data[word].Permitted &^= (1 << bit)
	data[word].Inheritable &^= (1 << bit)

	if err := capSet(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}

	return nil
}

func HasCapability(cap int) (bool, error) {
	var hdr capHeader
	var data [2]capData

	hdr.Version = 0x20080522
	hdr.Pid = int32(os.Getpid())

	if err := capGet(&hdr, &data[0]); err != nil {
		return false, fmt.Errorf("capget: %w", err)
	}

	word := cap / 32
	bit := uint(cap % 32)

	if word >= 2 {
		return false, nil
	}

	return (data[word].Effective & (1 << bit)) != 0, nil
}

func CapName(cap int) string {
	names := map[int]string{
		CAP_CHOWN: "CAP_CHOWN", CAP_DAC_OVERRIDE: "CAP_DAC_OVERRIDE",
		CAP_DAC_READ_SEARCH: "CAP_DAC_READ_SEARCH", CAP_FOWNER: "CAP_FOWNER",
		CAP_FSETID: "CAP_FSETID", CAP_KILL: "CAP_KILL", CAP_SETGID: "CAP_SETGID",
		CAP_SETUID: "CAP_SETUID", CAP_SETPCAP: "CAP_SETPCAP",
		CAP_LINUX_IMMUTABLE: "CAP_LINUX_IMMUTABLE", CAP_NET_BIND_SERVICE: "CAP_NET_BIND_SERVICE",
		CAP_NET_BROADCAST: "CAP_NET_BROADCAST", CAP_NET_ADMIN: "CAP_NET_ADMIN",
		CAP_NET_RAW: "CAP_NET_RAW", CAP_IPC_LOCK: "CAP_IPC_LOCK",
		CAP_IPC_OWNER: "CAP_IPC_OWNER", CAP_SYS_MODULE: "CAP_SYS_MODULE",
		CAP_SYS_RAWIO: "CAP_SYS_RAWIO", CAP_SYS_CHROOT: "CAP_SYS_CHROOT",
		CAP_SYS_PTRACE: "CAP_SYS_PTRACE", CAP_SYS_PACCT: "CAP_SYS_PACCT",
		CAP_SYS_ADMIN: "CAP_SYS_ADMIN", CAP_SYS_BOOT: "CAP_SYS_BOOT",
		CAP_SYS_NICE: "CAP_SYS_NICE", CAP_SYS_RESOURCE: "CAP_SYS_RESOURCE",
		CAP_SYS_TIME: "CAP_SYS_TIME", CAP_SYS_TTY_CONFIG: "CAP_SYS_TTY_CONFIG",
		CAP_MKNOD: "CAP_MKNOD", CAP_LEASE: "CAP_LEASE",
		CAP_AUDIT_WRITE: "CAP_AUDIT_WRITE", CAP_AUDIT_CONTROL: "CAP_AUDIT_CONTROL",
		CAP_SETFCAP: "CAP_SETFCAP",
	}
	if name, ok := names[cap]; ok {
		return name
	}
	return fmt.Sprintf("CAP_%d", cap)
}

func CapNumber(name string) (int, error) {
	name = strings.ToUpper(name)
	if !strings.HasPrefix(name, "CAP_") {
		name = "CAP_" + name
	}

	numbers := map[string]int{
		"CAP_CHOWN": CAP_CHOWN, "CAP_DAC_OVERRIDE": CAP_DAC_OVERRIDE,
		"CAP_DAC_READ_SEARCH": CAP_DAC_READ_SEARCH, "CAP_FOWNER": CAP_FOWNER,
		"CAP_FSETID": CAP_FSETID, "CAP_KILL": CAP_KILL, "CAP_SETGID": CAP_SETGID,
		"CAP_SETUID": CAP_SETUID, "CAP_SETPCAP": CAP_SETPCAP,
		"CAP_LINUX_IMMUTABLE": CAP_LINUX_IMMUTABLE, "CAP_NET_BIND_SERVICE": CAP_NET_BIND_SERVICE,
		"CAP_NET_BROADCAST": CAP_NET_BROADCAST, "CAP_NET_ADMIN": CAP_NET_ADMIN,
		"CAP_NET_RAW": CAP_NET_RAW, "CAP_IPC_LOCK": CAP_IPC_LOCK,
		"CAP_IPC_OWNER": CAP_IPC_OWNER, "CAP_SYS_MODULE": CAP_SYS_MODULE,
		"CAP_SYS_RAWIO": CAP_SYS_RAWIO, "CAP_SYS_CHROOT": CAP_SYS_CHROOT,
		"CAP_SYS_PTRACE": CAP_SYS_PTRACE, "CAP_SYS_PACCT": CAP_SYS_PACCT,
		"CAP_SYS_ADMIN": CAP_SYS_ADMIN, "CAP_SYS_BOOT": CAP_SYS_BOOT,
		"CAP_SYS_NICE": CAP_SYS_NICE, "CAP_SYS_RESOURCE": CAP_SYS_RESOURCE,
		"CAP_SYS_TIME": CAP_SYS_TIME, "CAP_SYS_TTY_CONFIG": CAP_SYS_TTY_CONFIG,
		"CAP_MKNOD": CAP_MKNOD, "CAP_LEASE": CAP_LEASE,
		"CAP_AUDIT_WRITE": CAP_AUDIT_WRITE, "CAP_AUDIT_CONTROL": CAP_AUDIT_CONTROL,
		"CAP_SETFCAP": CAP_SETFCAP,
	}

	if num, ok := numbers[name]; ok {
		return num, nil
	}

	if strings.HasPrefix(name, "CAP_") {
		numStr := strings.TrimPrefix(name, "CAP_")
		if num, err := strconv.Atoi(numStr); err == nil {
			if num >= 0 && num <= CAP_SETFCAP {
				return num, nil
			}
		}
	}

	return -1, fmt.Errorf("unknown capability: %s", name)
}
