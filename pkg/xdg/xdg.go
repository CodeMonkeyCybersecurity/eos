// pkg/xdg/xdg.go

package xdg

import (
	"errors"
	"os"
	"path/filepath"
)

func GetEnvOrDefault(envVar, fallback string) string {
	if val := os.Getenv(envVar); val != "" {
		return val
	}
	return fallback
}

func XDGConfigPath(app, file string) string {
	base := GetEnvOrDefault("XDG_CONFIG_HOME", filepath.Join(os.Getenv("HOME"), ".config"))
	return filepath.Join(base, app, file)
}

func XDGDataPath(app, file string) string {
	base := GetEnvOrDefault("XDG_DATA_HOME", filepath.Join(os.Getenv("HOME"), ".local", "share"))
	return filepath.Join(base, app, file)
}

func XDGCachePath(app, file string) string {
	base := GetEnvOrDefault("XDG_CACHE_HOME", filepath.Join(os.Getenv("HOME"), ".cache"))
	return filepath.Join(base, app, file)
}

func XDGStatePath(app, file string) string {
	base := GetEnvOrDefault("XDG_STATE_HOME", filepath.Join(os.Getenv("HOME"), ".local", "state"))
	return filepath.Join(base, app, file)
}

func XDGRuntimePath(app, file string) (string, error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		return "", errors.New("XDG_RUNTIME_DIR not set (this is expected on systems without systemd)")
	}
	return filepath.Join(base, app, file), nil
}

// Optional utility for creating paths on demand
func EnsureDir(path string) error {
	return os.MkdirAll(filepath.Dir(path), DirPermStandard)
}
