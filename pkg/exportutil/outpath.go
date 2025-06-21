// pkg/exportutil/outpath.go

package exportutil

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// EnsureDir ensures /opt/exports exists with 0700 perms.
func EnsureDir() error { return os.MkdirAll("/opt/exports", 0o700) }

// Build returns /opt/exports/20250621_224559_host_keycloak_config.json
func Build(app, ext string) (string, error) {
	host, _ := os.Hostname()
	ts := time.Now().Format("20060102_150405")
	fn := fmt.Sprintf("%s_%s_%s_config.%s", ts, host, app, ext)
	return filepath.Abs(filepath.Join("/opt/exports", fn))
}
