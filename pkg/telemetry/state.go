// pkg/telemetry/state.go

package telemetry

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

func IsEnabled() bool {
	// TODO: replace with Vault-backed config once available
	path := filepath.Join(os.Getenv("HOME"), ".eos", "telemetry_on")
	if _, err := os.Stat(path); err == nil {
		return true
	}
	return false
}

func AnonTelemetryID() string {
	path := filepath.Join(os.Getenv("HOME"), ".eos", "telemetry_id")

	if data, err := os.ReadFile(path); err == nil {
		return strings.TrimSpace(string(data))
	}

	id := "anon-" + uuid.New().String()
	_ = os.MkdirAll(filepath.Dir(path), 0700)
	_ = os.WriteFile(path, []byte(id), 0600)

	return id
}

func TruncateOrHashArgs(args []string) string {
	full := strings.Join(args, " ")
	if len(full) > 256 {
		return full[:256] + "..."
	}
	return full
}
