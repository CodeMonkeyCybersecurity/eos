package webhook

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CheckWebhookStatus checks the current webhook deployment status
// Migrated from cmd/read/pipeline_webhook_status.go checkWebhookStatus
func CheckWebhookStatus(rc *eos_io.RuntimeContext, verbose bool) *WebhookStatus {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Prepare webhook status check
	logger.Info("Assessing webhook deployment status",
		zap.Bool("verbose", verbose))
	
	status := &WebhookStatus{
		Timestamp:       time.Now(),
		FilesPresent:    make(map[string]bool),
		Permissions:     make(map[string]string),
		EnvironmentVars: make(map[string]bool),
		Issues:          make([]string, 0),
	}

	// INTERVENE - Check webhook deployment components
	logger.Debug("Checking webhook files deployment")
	
	// Check if webhook files are deployed
	integrationDir := "/var/ossec/integrations"
	requiredFiles := []string{
		"custom-delphi-webhook",
		"custom-delphi-webhook.py",
	}

	for _, file := range requiredFiles {
		fullPath := filepath.Join(integrationDir, file)
		if info, err := os.Stat(fullPath); err == nil {
			status.FilesPresent[file] = true
			status.Permissions[file] = fmt.Sprintf("%o", info.Mode().Perm())
			logger.Debug("Webhook file found",
				zap.String("file", file),
				zap.String("path", fullPath),
				zap.String("permissions", status.Permissions[file]))
		} else {
			status.FilesPresent[file] = false
			issue := fmt.Sprintf("Missing file: %s", fullPath)
			status.Issues = append(status.Issues, issue)
			logger.Warn("Webhook file missing",
				zap.String("file", file),
				zap.String("path", fullPath),
				zap.Error(err))
		}
	}

	// Check environment configuration
	logger.Debug("Checking environment configuration")
	
	envFile := filepath.Join(integrationDir, ".env")
	if _, err := os.Stat(envFile); err == nil {
		status.ConfigPresent = true
		logger.Debug("Environment file found", zap.String("file", envFile))
		
		// Check for required environment variables
		status.EnvironmentVars["HOOK_URL"] = CheckEnvVar(rc, envFile, "HOOK_URL")
		status.EnvironmentVars["WEBHOOK_TOKEN"] = CheckEnvVar(rc, envFile, "WEBHOOK_TOKEN")
	} else {
		status.ConfigPresent = false
		issue := "Environment configuration file missing: " + envFile
		status.Issues = append(status.Issues, issue)
		logger.Warn("Environment file missing",
			zap.String("file", envFile),
			zap.Error(err))
	}

	// Set deployment status
	status.Deployed = len(status.FilesPresent) > 0 && AllFilesPresent(status.FilesPresent)

	// EVALUATE - Log assessment results
	logger.Info("Webhook status check completed",
		zap.Bool("deployed", status.Deployed),
		zap.Bool("config_present", status.ConfigPresent),
		zap.Int("files_checked", len(status.FilesPresent)),
		zap.Int("issues_found", len(status.Issues)))

	return status
}