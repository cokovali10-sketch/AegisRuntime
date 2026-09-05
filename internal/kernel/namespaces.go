//go:build linux

package kernel

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)

type NamespaceConfig struct {
	EnablePID   bool
	EnableMount bool
	EnableUTS   bool
	EnableNet   bool
	EnableUser  bool
	Hostname    string
	RootfsPath  string
}

func CloneFlags(cfg NamespaceConfig) uintptr {
	var flags uintptr
	if cfg.EnablePID {
		flags |= unix.CLONE_NEWPID
	}
	if cfg.EnableMount {
		flags |= unix.CLONE_NEWNS
	}
	if cfg.EnableUTS {
		flags |= unix.CLONE_NEWUTS
	}
	if cfg.EnableNet {
		flags |= unix.CLONE_NEWNET
	}
	if cfg.EnableUser {
		flags |= unix.CLONE_NEWUSER
	}
	return flags
}

func SetupMountNamespace(rootfs string) error {
	if err := unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("make / private: %w", err)
	}

	tmpDir := filepath.Join(rootfs, "tmp")
	if err := os.MkdirAll(tmpDir, 0o1777); err != nil {
		return fmt.Errorf("create tmp dir: %w", err)
	}
	if err := unix.Mount("tmpfs", tmpDir, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=01777"); err != nil {
		return fmt.Errorf("mount tmpfs: %w", err)
	}

	procDir := filepath.Join(rootfs, "proc")
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		return fmt.Errorf("create proc dir: %w", err)
	}
	if err := unix.Mount("proc", procDir, "proc", 0, ""); err != nil {
		return fmt.Errorf("mount proc: %w", err)
	}

	devDir := filepath.Join(rootfs, "dev")
	if err := os.MkdirAll(devDir, 0o755); err != nil {
		return fmt.Errorf("create dev dir: %w", err)
	}
	if err := unix.Mount("devtmpfs", devDir, "devtmpfs", 0, "mode=0755"); err != nil {
		return fmt.Errorf("mount devtmpfs: %w", err)
	}

	sysDir := filepath.Join(rootfs, "sys")
	if err := os.MkdirAll(sysDir, 0o755); err != nil {
		return fmt.Errorf("create sys dir: %w", err)
	}
	if err := unix.Mount("sysfs", sysDir, "sysfs", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		return fmt.Errorf("mount sysfs: %w", err)
	}

	return nil
}

func SetupUTSNamespace(hostname string) error {
	if hostname != "" {
		if err := unix.Sethostname([]byte(hostname)); err != nil {
			return fmt.Errorf("set hostname: %w", err)
		}
	}
	return nil
}

type DeviceNode struct {
	path string
	mode uint32
	maj  uint32
	min  uint32
}

func CreateDevNodes(rootfs string) error {
	return SetupDevNodes(rootfs)
}

func SetupDevNodes(rootfs string) error {
	devDir := filepath.Join(rootfs, "dev")
	nodes := []DeviceNode{
		{path: filepath.Join(devDir, "null"), mode: 0o666, maj: 1, min: 3},
		{path: filepath.Join(devDir, "zero"), mode: 0o666, maj: 1, min: 5},
		{path: filepath.Join(devDir, "full"), mode: 0o666, maj: 1, min: 7},
		{path: filepath.Join(devDir, "random"), mode: 0o666, maj: 1, min: 8},
		{path: filepath.Join(devDir, "urandom"), mode: 0o666, maj: 1, min: 9},
		{path: filepath.Join(devDir, "tty"), mode: 0o666, maj: 5, min: 0},
		{path: filepath.Join(devDir, "ptmx"), mode: 0o666, maj: 5, min: 2},
	}

	for _, n := range nodes {
		dev := makedev(n.maj, n.min)
		if err := unix.Mknod(n.path, unix.S_IFCHR|n.mode, int(dev)); err != nil {
			return fmt.Errorf("mknod %s: %w", n.path, err)
		}
	}

	return nil
}

func makedev(major, minor uint32) uint64 {
	return (uint64(major) << 20) | uint64(minor)
}

func PivotRoot(newRoot, putOld string) error {
	if err := os.MkdirAll(putOld, 0o700); err != nil {
		return fmt.Errorf("create putold dir: %w", err)
	}

	if err := unix.PivotRoot(newRoot, putOld); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}

	if err := unix.Unmount(putOld, unix.MNT_DETACH); err != nil {
		return fmt.Errorf("unmount putold: %w", err)
	}

	if err := os.RemoveAll(putOld); err != nil {
		return fmt.Errorf("remove putold: %w", err)
	}

	return nil
}

func MountBind(source, target string) error {
	if err := unix.Mount(source, target, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind mount %s -> %s: %w", source, target, err)
	}
	return nil
}

func MountTmpfs(target, opts string) error {
	var flags uintptr = unix.MS_NOSUID | unix.MS_NODEV
	if err := unix.Mount("tmpfs", target, "tmpfs", flags, opts); err != nil {
		return fmt.Errorf("mount tmpfs %s: %w", target, err)
	}
	return nil
}

func UnmountAll(rootfs string) error {
	mountPoints := []string{
		filepath.Join(rootfs, "sys"),
		filepath.Join(rootfs, "proc"),
		filepath.Join(rootfs, "dev"),
		filepath.Join(rootfs, "tmp"),
	}

	for _, mp := range mountPoints {
		if err := unix.Unmount(mp, unix.MNT_DETACH); err != nil {
			fmt.Fprintf(os.Stderr, "warning: unmount %s: %v\n", mp, err)
		}
	}

	return nil
}

var _ = unsafe.Pointer(nil)
