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
    import cybermonkey_common

    log {
        output file {{.LogFile}}
        format json
        level DEBUG
    }


    handle /outpost.goauthentik.io/* {
        reverse_proxy http://hecate-server-1:9000
    }

    handle {
        # 2. Forward authentication to Authentik
        forward_auth http://hecate-server-1:9000 {
            uri /outpost.goauthentik.io/auth/caddy

            # Copy headers from Authentik response
            copy_headers X-Authentik-Email X-Authentik-Username X-Authentik-Groups X-Authentik-Name X-Authentik-Uid
        }

        # 3. Proxy to BionicGPT with explicit header mapping
        reverse_proxy http://{{.Backend}} {
            # Map Authentik headers to BionicGPT expected headers
            header_up X-Auth-Request-Email {http.request.header.X-Authentik-Email}
            header_up X-Auth-Request-User {http.request.header.X-Authentik-Username}
            header_up X-Auth-Request-Groups {http.request.header.X-Authentik-Groups}
            header_up X-Forwarded-User {http.request.header.X-Authentik-Username}
            header_up X-Forwarded-Email {http.request.header.X-Authentik-Email}

            # Ensure proper handling of redirects
            header_up X-Forwarded-Proto {scheme}
            header_up X-Forwarded-Host {host}
        }
    }
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
	if sanitizedService == "bionicgpt" {
		// BionicGPT ALWAYS uses forward auth configuration (sane default for this service)
		// ARCHITECTURE NOTE: BionicGPT is a "default module" with automatic Authentik integration.
		// This aligns with the service integration logic (pkg/hecate/add/bionicgpt.go) which
		// ALWAYS attempts Authentik setup regardless of --sso flag.
		//
		// Rationale:
		// 1. BionicGPT requires authentication (no public access mode)
		// 2. Authentik forward auth is the production-ready pattern
		// 3. Graceful degradation if Authentik unavailable (warns but proceeds)
		// 4. Reduces operator cognitive load (one way to deploy BionicGPT)
		//
		// CRITICAL: Must include /outpost.goauthentik.io/* proxy for forward auth to work
		tmplStr = bionicgptForwardAuthTemplate
	} else if opts.SSO {
		// Generic SSO template for other services (when --sso flag provided)
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

// RestoreBackup restores a backup Caddyfile with integrity verification
// This function performs comprehensive validation before restore to prevent
// cascading failures from corrupted backup files.
func RestoreBackup(rc *eos_io.RuntimeContext, backupPath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Verify backup file exists and is not empty
	info, err := os.Stat(backupPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("backup file does not exist: %s", backupPath)
		}
		return fmt.Errorf("failed to stat backup file: %w", err)
	}

	if info.Size() == 0 {
		return fmt.Errorf("backup file is empty (0 bytes): %s\n\n"+
			"This backup cannot be restored.\n"+
			"Check for other backups: ls -lh %s/", backupPath, BackupDir)
	}

	if info.Size() < 50 {
		logger.Warn("Backup file is suspiciously small",
			zap.String("backup_path", backupPath),
			zap.Int64("size_bytes", info.Size()))
	}

	// ASSESS: Read backup content
	content, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup: %w", err)
	}

	// ASSESS: Validate Caddyfile syntax
	if err := validateCaddyfileSyntax(string(content)); err != nil {
		return fmt.Errorf("backup file has invalid Caddyfile syntax: %w\n\n"+
			"Backup location: %s\n"+
			"This backup cannot be restored safely.\n"+
			"Check for other backups: ls -lh %s/", err, backupPath, BackupDir)
	}

	// INTERVENE: Write to temp file first (atomic operation pattern)
	tempPath := CaddyfilePath + ".restore.tmp"
	if err := os.WriteFile(tempPath, content, hecate.TempFilePerm); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Ensure temp file is cleaned up on failure
	defer func() {
		if _, err := os.Stat(tempPath); err == nil {
			_ = os.Remove(tempPath)
		}
	}()

	// INTERVENE: Atomic rename (replaces target file in single syscall)
	if err := os.Rename(tempPath, CaddyfilePath); err != nil {
		return fmt.Errorf("failed to restore Caddyfile (atomic rename failed): %w", err)
	}

	// INTERVENE: Set correct permissions on restored file
	if err := os.Chmod(CaddyfilePath, hecate.CaddyfilePerm); err != nil {
		logger.Warn("Failed to set Caddyfile permissions after restore",
			zap.Error(err))
	}

	// EVALUATE: Verify restore succeeded
	restoredContent, err := os.ReadFile(CaddyfilePath)
	if err != nil {
		return fmt.Errorf("failed to verify restored file: %w", err)
	}

	if len(restoredContent) != len(content) {
		return fmt.Errorf("restore verification failed: size mismatch\n"+
			"Expected: %d bytes\n"+
			"Actual: %d bytes\n\n"+
			"The Caddyfile may be corrupted.",
			len(content), len(restoredContent))
	}

	logger.Info("Restored Caddyfile from backup",
		zap.String("backup_path", backupPath),
		zap.Int64("backup_size_bytes", info.Size()),
		zap.Int("restored_size_bytes", len(restoredContent)))

	return nil
}

// validateCaddyfileSyntax performs basic syntax validation on Caddyfile content
// This is NOT a complete parser, but catches common corruption issues:
// - Unbalanced braces
// - Missing required snippets (common block)
// - Empty file
func validateCaddyfileSyntax(content string) error {
	if len(content) == 0 {
		return fmt.Errorf("Caddyfile is empty")
	}

	// Check for balanced braces
	openBraces := 0
	for i, char := range content {
		if char == '{' {
			openBraces++
		} else if char == '}' {
			openBraces--
			if openBraces < 0 {
				return fmt.Errorf("unbalanced braces: extra '}' at position %d", i)
			}
		}
	}

	if openBraces > 0 {
		return fmt.Errorf("unbalanced braces: %d unclosed '{'", openBraces)
	}

	// Check for required common snippet (all Hecate Caddyfiles should have this)
	if !strings.Contains(content, "(common)") {
		return fmt.Errorf("missing required (common) snippet\n\n" +
			"This may not be a valid Hecate Caddyfile.\n" +
			"Expected snippet:\n" +
			"  (common) {\n" +
			"    ...\n" +
			"  }")
	}

	// Validation passed
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
// CRITICAL P0.7: This function protects against race conditions where operation A's backup
// is deleted by operation B's cleanup before operation A completes.
//
// Protection mechanism:
// 1. Only delete backups older than BackupMinimumAgeBeforeCleanup (1 hour)
// 2. AND older than retention period
// 3. This ensures concurrent operations have time to use their backups
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
	// CRITICAL P0.7: Minimum age before cleanup prevents race condition
	// RATIONALE: Concurrent operation may have just created backup and is still using it
	// THREAT MODEL: Operation A creates backup at T+0, Operation B's cleanup runs at T+1
	//               and deletes backup before Operation A can restore it (if needed)
	minimumAge := time.Now().Add(-hecate.BackupMinimumAgeBeforeCleanup)
	removedCount := 0
	skippedTooNew := 0

	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			logger.Warn("Failed to stat backup file", zap.String("file", file), zap.Error(err))
			continue
		}

		// CRITICAL P0.7: Check BOTH conditions:
		// 1. File is older than retention period (user's policy)
		// 2. File is older than minimum age (race condition protection)
		if info.ModTime().Before(cutoffTime) {
			// File is old enough for retention policy
			if info.ModTime().After(minimumAge) {
				// But NOT old enough for safe deletion (might be in use)
				skippedTooNew++
				logger.Debug("Skipping backup deletion: too new, may be in use",
					zap.String("file", file),
					zap.Time("mod_time", info.ModTime()),
					zap.Duration("age", time.Since(info.ModTime())),
					zap.Duration("minimum_age", hecate.BackupMinimumAgeBeforeCleanup))
				continue
			}

			// Safe to delete: old enough AND past minimum age
			if err := os.Remove(file); err != nil {
				logger.Warn("Failed to remove old backup",
					zap.String("file", file),
					zap.Error(err))
				continue
			}
			removedCount++
			logger.Debug("Removed old backup",
				zap.String("file", file),
				zap.Time("mod_time", info.ModTime()),
				zap.Duration("age", time.Since(info.ModTime())))
		}
	}

	if removedCount > 0 || skippedTooNew > 0 {
		logger.Info("Cleaned up old backups",
			zap.Int("removed_count", removedCount),
			zap.Int("skipped_too_new", skippedTooNew),
			zap.Int("retention_days", retentionDays),
			zap.Duration("minimum_age_protection", hecate.BackupMinimumAgeBeforeCleanup))
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
