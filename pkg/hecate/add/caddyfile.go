// pkg/hecate/add/caddyfile.go

package add

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NOTE: Constants moved to pkg/hecate/constants.go (CLAUDE.md Rule #12 - Single Source of Truth)
// Use hecate.CaddyfilePath and hecate.BackupDir instead
const (
	// CaddyfilePath references the centralized constant from pkg/hecate
	CaddyfilePath = hecate.CaddyfilePath
	// BackupDir references the centralized constant from pkg/hecate
	BackupDir = hecate.BackupDir
)

// Route templates
const (
	basicRouteTemplate = `
# Service: {{.Service}}
{{.DNS}} {
    import common

    # Additional logging for this service
    log {
        output file {{.LogFile}}
        format json
        level DEBUG
    }
{{range .CustomDirectives}}
    {{.}}
{{end}}
    # Reverse proxy to backend
    reverse_proxy http://{{.Backend}}
}
`

	ssoRouteTemplate = `
# Service: {{.Service}} (with SSO)
{{.DNS}} {
    import common

    # Forward auth to {{.SSOProvider}}
    forward_auth http://server:9000 {
        uri /outpost.goauthentik.io/auth/caddy
        copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Email X-Authentik-Name X-Authentik-Uid
    }

    # Additional logging for this service
    log {
        output file {{.LogFile}}
        format json
        level DEBUG
    }
{{range .CustomDirectives}}
    {{.}}
{{end}}
    # Reverse proxy to backend
    reverse_proxy http://{{.Backend}}
}
`

	bionicgptForwardAuthTemplate = `
# Service: {{.Service}} (BionicGPT with Authentik Forward Auth)
{{.DNS}} {
    import common

    # CRITICAL: Proxy Authentik outpost paths for forward auth to work
    # Without this, forward_auth validation will fail
    handle /outpost.goauthentik.io/* {
        reverse_proxy http://localhost:9000
    }

    # Forward auth to Authentik for authentication
    # Authentik validates session and returns X-Authentik-* headers
    forward_auth http://localhost:9000 {
        uri /outpost.goauthentik.io/auth/caddy
        copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Email X-Authentik-Name X-Authentik-Uid
    }

    # Additional logging for this service
    log {
        output file {{.LogFile}}
        format json
        level DEBUG
    }
{{range .CustomDirectives}}
    {{.}}
{{end}}
    # Reverse proxy to BionicGPT backend
    # Headers from forward_auth are automatically passed to backend
    reverse_proxy http://{{.Backend}}
}
`
)

// GenerateRouteConfig generates the Caddyfile configuration for a new route
func GenerateRouteConfig(opts *ServiceOptions) (string, error) {
	// SECURITY P2 #20: Sanitize service name to prevent directory traversal
	// filepath.Base removes directory components (../../../etc/passwd → passwd)
	sanitizedService := filepath.Base(opts.Service)

	config := &RouteConfig{
		Service:          sanitizedService,
		DNS:              opts.DNS,
		Backend:          opts.Backend,
		SSO:              opts.SSO,
		SSOProvider:      opts.SSOProvider,
		CustomDirectives: opts.CustomDirectives,
		LogFile:          fmt.Sprintf("/var/log/caddy/%s.log", sanitizedService),
	}

	// Choose template based on service type and SSO
	var tmplStr string
	if sanitizedService == "bionicgpt" && opts.SSO {
		// BionicGPT requires special forward auth configuration
		// CRITICAL: Must include /outpost.goauthentik.io/* proxy for forward auth to work
		tmplStr = bionicgptForwardAuthTemplate
	} else if opts.SSO {
		// Generic SSO template for other services
		tmplStr = ssoRouteTemplate
	} else {
		// Basic reverse proxy without authentication
		tmplStr = basicRouteTemplate
	}

	// Parse and execute template
	tmpl, err := template.New("route").Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var builder strings.Builder
	if err := tmpl.Execute(&builder, config); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return builder.String(), nil
}

// BackupCaddyfile creates a timestamped backup of the Caddyfile
func BackupCaddyfile(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Ensure backup directory exists
	if err := os.MkdirAll(BackupDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Generate backup filename with timestamp
	timestamp := time.Now().Format("20060102-150405")
	backupPath := filepath.Join(BackupDir, fmt.Sprintf("Caddyfile.backup.%s", timestamp))

	// Read current Caddyfile
	content, err := os.ReadFile(CaddyfilePath)
	if err != nil {
		return "", fmt.Errorf("failed to read Caddyfile: %w", err)
	}

	// Write backup
	if err := os.WriteFile(backupPath, content, 0644); err != nil {
		return "", fmt.Errorf("failed to write backup: %w", err)
	}

	// Get file info for logging
	info, _ := os.Stat(backupPath)
	logger.Info("Created Caddyfile backup",
		zap.String("backup_path", backupPath),
		zap.Int64("size_bytes", info.Size()))

	return backupPath, nil
}

// RestoreBackup restores a backup Caddyfile
func RestoreBackup(rc *eos_io.RuntimeContext, backupPath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Read backup
	content, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup: %w", err)
	}

	// Restore to original location
	if err := os.WriteFile(CaddyfilePath, content, 0644); err != nil {
		return fmt.Errorf("failed to restore Caddyfile: %w", err)
	}

	logger.Info("Restored Caddyfile from backup",
		zap.String("backup_path", backupPath))

	return nil
}

// AppendRoute appends a new route to the Caddyfile
func AppendRoute(rc *eos_io.RuntimeContext, routeConfig string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Read current Caddyfile
	content, err := os.ReadFile(CaddyfilePath)
	if err != nil {
		return fmt.Errorf("failed to read Caddyfile: %w", err)
	}

	// Append new route with proper spacing
	updatedContent := string(content)
	if !strings.HasSuffix(updatedContent, "\n") {
		updatedContent += "\n"
	}
	updatedContent += "\n" + routeConfig

	// Write updated Caddyfile
	if err := os.WriteFile(CaddyfilePath, []byte(updatedContent), 0644); err != nil {
		return fmt.Errorf("failed to write Caddyfile: %w", err)
	}

	logger.Info("Appended new route to Caddyfile",
		zap.String("caddyfile", CaddyfilePath))

	return nil
}

// CleanupOldBackups removes backups older than retentionDays
func CleanupOldBackups(rc *eos_io.RuntimeContext, retentionDays int) error {
	logger := otelzap.Ctx(rc.Ctx)

	// If retention is 0, keep all backups
	if retentionDays == 0 {
		logger.Debug("Backup retention set to 0, keeping all backups")
		return nil
	}

	// Get all backup files
	files, err := filepath.Glob(filepath.Join(BackupDir, "Caddyfile.backup.*"))
	if err != nil {
		return fmt.Errorf("failed to list backups: %w", err)
	}

	cutoffTime := time.Now().AddDate(0, 0, -retentionDays)
	removedCount := 0

	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			logger.Warn("Failed to stat backup file", zap.String("file", file), zap.Error(err))
			continue
		}

		// Check if file is older than retention period
		if info.ModTime().Before(cutoffTime) {
			if err := os.Remove(file); err != nil {
				logger.Warn("Failed to remove old backup",
					zap.String("file", file),
					zap.Error(err))
				continue
			}
			removedCount++
			logger.Debug("Removed old backup",
				zap.String("file", file),
				zap.Time("mod_time", info.ModTime()))
		}
	}

	if removedCount > 0 {
		logger.Info("Cleaned up old backups",
			zap.Int("removed_count", removedCount),
			zap.Int("retention_days", retentionDays))
	}

	return nil
}

// ListBackups returns information about all available backups
func ListBackups() ([]BackupInfo, error) {
	files, err := filepath.Glob(filepath.Join(BackupDir, "Caddyfile.backup.*"))
	if err != nil {
		return nil, fmt.Errorf("failed to list backups: %w", err)
	}

	backups := make([]BackupInfo, 0, len(files))
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}

		backups = append(backups, BackupInfo{
			Path:      file,
			Timestamp: info.ModTime(),
			Size:      info.Size(),
		})
	}

	return backups, nil
}
