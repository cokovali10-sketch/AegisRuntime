package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type Config struct {
	RootDir       string `json:"root_dir"`
	ImageDir      string `json:"image_dir"`
	ContainerDir  string `json:"container_dir"`
	SnapshotDir   string `json:"snapshot_dir"`
	LogDir        string `json:"log_dir"`
	CgroupRoot    string `json:"cgroup_root"`
	APIAddr       string `json:"api_addr"`
	DefaultTimeout int   `json:"default_timeout"`
}

var (
	globalConfig *Config
	configOnce   sync.Once
)

func DefaultConfig() *Config {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/var"
	}
	rootDir := filepath.Join(home, ".aegis")

	return &Config{
		RootDir:        rootDir,
		ImageDir:       filepath.Join(rootDir, "images"),
		ContainerDir:   filepath.Join(rootDir, "containers"),
		SnapshotDir:    filepath.Join(rootDir, "snapshots"),
		LogDir:         filepath.Join(rootDir, "logs"),
		CgroupRoot:     "/sys/fs/cgroup",
		APIAddr:        ":8080",
		DefaultTimeout: 30,
	}
}

func Get() *Config {
	configOnce.Do(func() {
		globalConfig = DefaultConfig()
	})
	return globalConfig
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	globalConfig = cfg
	return cfg, nil
}

func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	return nil
}

func (c *Config) EnsureDirs() error {
	dirs := []string{
		c.RootDir,
		c.ImageDir,
		c.ContainerDir,
		c.SnapshotDir,
		c.LogDir,
	}

	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create dir %s: %w", dir, err)
		}
	}

	return nil
}
