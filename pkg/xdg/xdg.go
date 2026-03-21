// pkg/xdg/xdg.go

package xdg

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func GetEnvOrDefault(envVar, fallback string) string {
	if val := os.Getenv(envVar); val != "" {
		return val
	}
	return fallback
}

func XDGConfigPath(app, file string) string {
	base := GetEnvOrDefault("XDG_CONFIG_HOME", filepath.Join(os.Getenv("HOME"), ".config"))
	return safeXDGJoin(base, app, file)
}

func XDGDataPath(app, file string) string {
	base := GetEnvOrDefault("XDG_DATA_HOME", filepath.Join(os.Getenv("HOME"), ".local", "share"))
	return safeXDGJoin(base, app, file)
}

func XDGCachePath(app, file string) string {
	base := GetEnvOrDefault("XDG_CACHE_HOME", filepath.Join(os.Getenv("HOME"), ".cache"))
	return safeXDGJoin(base, app, file)
}

func XDGStatePath(app, file string) string {
	base := GetEnvOrDefault("XDG_STATE_HOME", filepath.Join(os.Getenv("HOME"), ".local", "state"))
	return safeXDGJoin(base, app, file)
}

func XDGRuntimePath(app, file string) (string, error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		return "", errors.New("XDG_RUNTIME_DIR not set (this is expected on systems without systemd)")
	}
	return safeXDGJoin(base, app, file), nil
}

func safeXDGJoin(base string, parts ...string) string {
	sanitized := make([]string, 0, len(parts))
	for _, part := range parts {
		sanitized = append(sanitized, sanitizeXDGPart(part))
	}
	return filepath.Join(append([]string{base}, sanitized...)...)
}

func sanitizeXDGPart(part string) string {
	part = strings.ReplaceAll(part, "\x00", "")
	part = filepath.ToSlash(part)
	segments := strings.Split(part, "/")
	cleaned := make([]string, 0, len(segments))
	for _, segment := range segments {
		switch segment {
		case "", ".", "..":
			continue
		default:
			cleaned = append(cleaned, segment)
		}
	}
	if len(cleaned) == 0 {
		return ""
	}
	return filepath.Join(cleaned...)
}
