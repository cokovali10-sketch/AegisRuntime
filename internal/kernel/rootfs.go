//go:build linux

package kernel

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type RootfsManager struct {
	ImageDir     string
	ContainerDir string
}

func NewRootfsManager(imageDir, containerDir string) *RootfsManager {
	os.MkdirAll(imageDir, 0o755)
	os.MkdirAll(containerDir, 0o755)
	return &RootfsManager{
		ImageDir:     imageDir,
		ContainerDir: containerDir,
	}
}

func (rm *RootfsManager) ListImages() ([]string, error) {
	entries, err := os.ReadDir(rm.ImageDir)
	if err != nil {
		return nil, fmt.Errorf("read image dir: %w", err)
	}

	var images []string
	for _, entry := range entries {
		if entry.IsDir() {
			images = append(images, entry.Name())
		}
	}

	return images, nil
}

func (rm *RootfsManager) ImageExists(name string) bool {
	_, err := os.Stat(filepath.Join(rm.ImageDir, name))
	return err == nil
}

func (rm *RootfsManager) PullImage(name, url string) error {
	if rm.ImageExists(name) {
		return nil
	}

	tmpPath := filepath.Join(rm.ImageDir, name+".tmp")
	finalPath := filepath.Join(rm.ImageDir, name)

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("download image: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: status %d", resp.StatusCode)
	}

	out, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer func() {
		out.Close()
		os.Remove(tmpPath)
	}()

	size := resp.ContentLength
	if size > 0 {
		buf := make([]byte, 32*1024)
		written := int64(0)
		for {
			n, readErr := resp.Body.Read(buf)
			if n > 0 {
				nw, writeErr := out.Write(buf[:n])
				if writeErr != nil {
					return fmt.Errorf("write image: %w", writeErr)
				}
				written += int64(nw)
			}
			if readErr != nil {
				if readErr == io.EOF {
					break
				}
				return fmt.Errorf("read response: %w", readErr)
			}
		}
	} else {
		if _, err := io.Copy(out, resp.Body); err != nil {
			return fmt.Errorf("write image: %w", err)
		}
	}

	if err := out.Close(); err != nil {
		return fmt.Errorf("close file: %w", err)
	}

	if err := os.Rename(tmpPath, finalPath); err != nil {
		return fmt.Errorf("rename image: %w", err)
	}

	return nil
}

func (rm *RootfsManager) UnpackImage(name, dest string) error {
	imagePath := filepath.Join(rm.ImageDir, name)
	info, err := os.Stat(imagePath)
	if err != nil {
		return fmt.Errorf("stat image: %w", err)
	}

	var reader io.Reader
	if info.IsDir() {
		return rm.unpackTarDir(imagePath, dest)
	}

	f, err := os.Open(imagePath)
	if err != nil {
		return fmt.Errorf("open image: %w", err)
	}
	defer f.Close()

	if strings.HasSuffix(name, ".gz") || strings.HasSuffix(name, ".tar.gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("gzip reader: %w", err)
		}
		defer gz.Close()
		reader = gz
	} else {
		reader = f
	}

	return rm.extractTar(reader, dest)
}

func (rm *RootfsManager) unpackTarDir(dirPath, dest string) error {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return fmt.Errorf("read image dir: %w", err)
	}

	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tar") || strings.HasSuffix(entry.Name(), ".tar.gz") {
			srcPath := filepath.Join(dirPath, entry.Name())
			f, err := os.Open(srcPath)
			if err != nil {
				return fmt.Errorf("open %s: %w", srcPath, err)
			}
			defer f.Close()

			var reader io.Reader
			if strings.HasSuffix(entry.Name(), ".gz") {
				gz, err := gzip.NewReader(f)
				if err != nil {
					return fmt.Errorf("gzip reader: %w", err)
				}
				defer gz.Close()
				reader = gz
			} else {
				reader = f
			}

			if err := rm.extractTar(reader, dest); err != nil {
				return fmt.Errorf("extract %s: %w", entry.Name(), err)
			}
			return nil
		}
	}

	return fmt.Errorf("no tar archive found in %s", dirPath)
}

func (rm *RootfsManager) extractTar(reader io.Reader, dest string) error {
	tr := tar.NewReader(reader)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}

		target := filepath.Join(dest, filepath.Clean(header.Name))

		if !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("tar entry escapes root: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("mkdir %s: %w", target, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("mkdir parent %s: %w", filepath.Dir(target), err)
			}
			outFile, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("create file %s: %w", target, err)
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return fmt.Errorf("write file %s: %w", target, err)
			}
			outFile.Close()
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("mkdir parent for symlink: %w", err)
			}
			if err := os.Symlink(header.Linkname, target); err != nil {
				return fmt.Errorf("symlink %s: %w", target, err)
			}
		case tar.TypeLink:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("mkdir parent for hardlink: %w", err)
			}
			linkTarget := filepath.Join(dest, filepath.Clean(header.Linkname))
			if err := os.Link(linkTarget, target); err != nil {
				return fmt.Errorf("hardlink %s: %w", target, err)
			}
		}
	}

	return nil
}

func (rm *RootfsManager) PrepareRootfs(imageName, containerID string) (string, error) {
	containerDir := filepath.Join(rm.ContainerDir, containerID)
	if err := os.MkdirAll(containerDir, 0o755); err != nil {
		return "", fmt.Errorf("create container dir: %w", err)
	}

	rootfsDir := filepath.Join(containerDir, "rootfs")
	if err := os.MkdirAll(rootfsDir, 0o755); err != nil {
		return "", fmt.Errorf("create rootfs dir: %w", err)
	}

	if err := rm.UnpackImage(imageName, rootfsDir); err != nil {
		return "", fmt.Errorf("unpack image: %w", err)
	}

	workDir := filepath.Join(containerDir, "work")
	mergedDir := filepath.Join(containerDir, "merged")

	for _, dir := range []string{workDir, mergedDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", fmt.Errorf("create dir %s: %w", dir, err)
		}
	}

	if err := SetupMountNamespace(rootfsDir); err != nil {
		return "", fmt.Errorf("setup mount namespace: %w", err)
	}

	if err := CreateDevNodes(rootfsDir); err != nil {
		return "", fmt.Errorf("create dev nodes: %w", err)
	}

	return rootfsDir, nil
}

func (rm *RootfsManager) CreateSnapshot(containerID string) (string, error) {
	containerDir := filepath.Join(rm.ContainerDir, containerID)
	rootfsDir := filepath.Join(containerDir, "rootfs")

	if _, err := os.Stat(rootfsDir); err != nil {
		return "", fmt.Errorf("rootfs not found: %w", err)
	}

	snapshotID := fmt.Sprintf("snap-%d", os.Getpid())
	snapshotsDir := filepath.Join(containerDir, "snapshots")
	if err := os.MkdirAll(snapshotsDir, 0o755); err != nil {
		return "", fmt.Errorf("create snapshots dir: %w", err)
	}

	snapshotDir := filepath.Join(snapshotsDir, snapshotID)
	if err := copyDir(rootfsDir, snapshotDir); err != nil {
		return "", fmt.Errorf("create snapshot: %w", err)
	}

	return snapshotID, nil
}

func (rm *RootfsManager) RestoreSnapshot(containerID, snapshotID string) error {
	containerDir := filepath.Join(rm.ContainerDir, containerID)
	snapshotDir := filepath.Join(containerDir, "snapshots", snapshotID)
	rootfsDir := filepath.Join(containerDir, "rootfs")

	if _, err := os.Stat(snapshotDir); err != nil {
		return fmt.Errorf("snapshot not found: %w", err)
	}

	if err := os.RemoveAll(rootfsDir); err != nil {
		return fmt.Errorf("remove current rootfs: %w", err)
	}

	if err := copyDir(snapshotDir, rootfsDir); err != nil {
		return fmt.Errorf("restore snapshot: %w", err)
	}

	return nil
}

func (rm *RootfsManager) CleanupSnapshot(containerID, snapshotID string) error {
	snapshotDir := filepath.Join(rm.ContainerDir, containerID, "snapshots", snapshotID)
	if err := os.RemoveAll(snapshotDir); err != nil {
		return fmt.Errorf("remove snapshot: %w", err)
	}
	return nil
}

func (rm *RootfsManager) GetDiskUsage(containerID string) (int64, error) {
	rootfsDir := filepath.Join(rm.ContainerDir, containerID, "rootfs")
	var size int64

	err := filepath.Walk(rootfsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})

	if err != nil {
		return 0, fmt.Errorf("walk rootfs: %w", err)
	}

	return size, nil
}

func copyDir(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("stat source: %w", err)
	}

	if err := os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		return fmt.Errorf("create destination: %w", err)
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return fmt.Errorf("read source: %w", err)
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else if entry.Type()&os.ModeSymlink != 0 {
			link, err := os.Readlink(srcPath)
			if err != nil {
				return fmt.Errorf("readlink: %w", err)
			}
			if err := os.Symlink(link, dstPath); err != nil {
				return fmt.Errorf("symlink: %w", err)
			}
		} else {
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer srcFile.Close()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("stat source: %w", err)
	}

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return fmt.Errorf("create destination: %w", err)
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return fmt.Errorf("copy: %w", err)
	}

	return dstFile.Close()
}
