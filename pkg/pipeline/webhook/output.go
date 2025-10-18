package webhook

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// OutputStatusJSON outputs webhook status in JSON format
// Migrated from cmd/read/pipeline_webhook_status.go outputStatusJSON
func OutputStatusJSON(rc *eos_io.RuntimeContext, status *WebhookStatus) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Prepare JSON output
	logger.Info("Assessing JSON status output")

	// INTERVENE - Encode and output JSON
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")

	err := encoder.Encode(status)
	if err != nil {
		logger.Error("Failed to encode status as JSON", zap.Error(err))
		return fmt.Errorf("failed to encode status as JSON: %w", err)
	}

	// EVALUATE - Log successful output
	logger.Info("Status output in JSON format completed successfully")

	return nil
}

// OutputStatusText outputs webhook status in human-readable text format
// Migrated from cmd/read/pipeline_webhook_status.go outputStatusText
func OutputStatusText(rc *eos_io.RuntimeContext, status *WebhookStatus) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Prepare text output
	logger.Info("Assessing text status output")

	// INTERVENE - Display formatted status information
	logger.Info(" Delphi Webhook Integration Status")
	logger.Info(strings.Repeat("=", 50))

	// Deployment status
	if status.Deployed {
		logger.Info(" Deployment Status: DEPLOYED")
	} else {
		logger.Info(" Deployment Status: NOT DEPLOYED")
	}

	// File presence
	logger.Info(" File Status:")
	for file, present := range status.FilesPresent {
		if present {
			perm := status.Permissions[file]
			logger.Info(fmt.Sprintf("   %s (permissions: %s)", file, perm))
		} else {
			logger.Info(fmt.Sprintf("   %s (missing)", file))
		}
	}

	// Configuration status
	logger.Info(" Configuration Status:")
	if status.ConfigPresent {
		logger.Info("   Environment file present")
		for envVar, present := range status.EnvironmentVars {
			if present {
				logger.Info(fmt.Sprintf("     %s configured", envVar))
			} else {
				logger.Info(fmt.Sprintf("     %s missing", envVar))
			}
		}
	} else {
		logger.Info("   Environment file missing")
	}

	// Issues
	if len(status.Issues) > 0 {
		logger.Info(" Issues Found:")
		for _, issue := range status.Issues {
			logger.Info(fmt.Sprintf("  • %s", issue))
		}
	} else {
		logger.Info(" No issues found")
	}

	logger.Info(strings.Repeat("=", 50))

	// EVALUATE - Log successful output
	logger.Info("Status output in text format completed successfully",
		zap.Bool("deployed", status.Deployed),
		zap.Int("issues_count", len(status.Issues)))

	return nil
}
