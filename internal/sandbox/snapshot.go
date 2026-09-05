//go:build linux

package sandbox

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type Snapshot struct {
	ID          string    `json:"id"`
	ContainerID string    `json:"container_id"`
	RootfsPath  string    `json:"rootfs_path"`
	Size        int64     `json:"size"`
	CreatedAt   time.Time `json:"created_at"`
	Description string    `json:"description"`
}

func CreateSnapshot(containerID, rootfsPath, snapshotDir string) (string, error) {
	if _, err := os.Stat(rootfsPath); err != nil {
		return "", fmt.Errorf("rootfs path does not exist: %w", err)
	}

	containerSnapDir := filepath.Join(snapshotDir, containerID)
	if err := os.MkdirAll(containerSnapDir, 0o755); err != nil {
		return "", fmt.Errorf("create snapshot dir: %w", err)
	}

	snapshotID := fmt.Sprintf("snap-%d", time.Now().UnixNano())
	snapshotFile := filepath.Join(containerSnapDir, snapshotID+".tar.gz")

	size, err := createTarGz(rootfsPath, snapshotFile)
	if err != nil {
		os.Remove(snapshotFile)
		return "", fmt.Errorf("create tar.gz: %w", err)
	}

	snap := &Snapshot{
		ID:          snapshotID,
		ContainerID: containerID,
		RootfsPath:  snapshotFile,
		Size:        size,
		CreatedAt:   time.Now(),
		Description: fmt.Sprintf("snapshot of %s", containerID),
	}

	metaFile := filepath.Join(containerSnapDir, snapshotID+".json")
	if err := writeSnapshotMeta(metaFile, snap); err != nil {
		fmt.Fprintf(os.Stderr, "warning: write snapshot meta: %v\n", err)
	}

	return snapshotID, nil
}

func RestoreSnapshot(snapshot *Snapshot, rootfsPath string) error {
	if _, err := os.Stat(snapshot.RootfsPath); err != nil {
		return fmt.Errorf("snapshot file does not exist: %w", err)
	}

	if err := os.RemoveAll(rootfsPath); err != nil {
		return fmt.Errorf("remove current rootfs: %w", err)
	}

	if err := os.MkdirAll(rootfsPath, 0o755); err != nil {
		return fmt.Errorf("create rootfs dir: %w", err)
	}

	if err := extractTarGz(snapshot.RootfsPath, rootfsPath); err != nil {
		return fmt.Errorf("extract snapshot: %w", err)
	}

	return nil
}

func DeleteSnapshot(snapshotDir, snapshotID string) error {
	containerDir := filepath.Join(snapshotDir)
	entries, err := os.ReadDir(containerDir)
	if err != nil {
		return fmt.Errorf("read snapshot dir: %w", err)
	}

	removed := false
	for _, entry := range entries {
		if entry.IsDir() {
			snapFile := filepath.Join(containerDir, entry.Name(), snapshotID+".tar.gz")
			if _, err := os.Stat(snapFile); err == nil {
				os.Remove(snapFile)
				metaFile := filepath.Join(containerDir, entry.Name(), snapshotID+".json")
				os.Remove(metaFile)
				removed = true
			}
		}
	}

	if !removed {
		return fmt.Errorf("snapshot %s not found", snapshotID)
	}

	return nil
}

func ListSnapshots(snapshotDir, containerID string) ([]*Snapshot, error) {
	containerSnapDir := filepath.Join(snapshotDir, containerID)
	entries, err := os.ReadDir(containerSnapDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read snapshot dir: %w", err)
	}

	var snapshots []*Snapshot
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if filepath.Ext(name) == ".json" {
			metaFile := filepath.Join(containerSnapDir, name)
			snap, err := readSnapshotMeta(metaFile)
			if err != nil {
				continue
			}
			snapshots = append(snapshots, snap)
		}
	}

	return snapshots, nil
}

func createTarGz(src string, dest string) (int64, error) {
	f, err := os.Create(dest)
	if err != nil {
		return 0, fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	gzWriter := gzip.NewWriter(f)
	defer gzWriter.Close()

	tw := tar.NewWriter(gzWriter)
	defer tw.Close()

	var totalSize int64

	err = filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		if relPath == "." {
			return nil
		}

		link := ""
		if info.Mode()&os.ModeSymlink != 0 {
			link, err = os.Readlink(path)
			if err != nil {
				return err
			}
		}

		header, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return err
		}
		header.Name = relPath

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if !info.Mode().IsRegular() {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		n, err := io.Copy(tw, f)
		totalSize += n
		return err
	})

	if err != nil {
		return 0, err
	}

	return totalSize, nil
}

func extractTarGz(src, dest string) error {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	gzReader, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gzReader.Close()

	tr := tar.NewReader(gzReader)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}

		target := filepath.Join(dest, filepath.Clean(header.Name))

		if !isInPath(target, dest) {
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

func isInPath(path, root string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	return absPath == absRoot || len(absPath) > len(absRoot) && absPath[:len(absRoot)] == absRoot && (absPath[len(absRoot)] == '/' || absPath[len(absRoot)-1] == '/')
}

func writeSnapshotMeta(path string, snap *Snapshot) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := newJSONEncoder(f)
	return enc.Encode(snap)
}

func readSnapshotMeta(path string) (*Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var snap Snapshot
	dec := newJSONDecoder(f)
	if err := dec.Decode(&snap); err != nil {
		return nil, err
	}
	return &snap, nil
}
