// pkg/authentik/backup/backup.go
package backup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	consul_config "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// Backup performs an Authentik configuration backup
// ASSESS → INTERVENE → EVALUATE pattern
func Backup(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Validate API parameters
	logger.Info("Starting Authentik configuration backup")

	// Resolve URL from multiple sources
	url := config.URL
	if url == "" {
		// Try to get from Consul
		if consulClient, err := consul_config.NewClient(rc.Ctx); err == nil {
			if consulURL, found, _ := consulClient.Get(rc.Ctx, "authentik/url"); found && consulURL != "" {
				url = consulURL
				logger.Info("Retrieved Authentik URL from Consul", zap.String("url", url))
			}
		} else {
			logger.Debug("Consul not available for config retrieval", zap.Error(err))
		}
	}

	if url == "" {
		input, err := eos_io.PromptInput(rc, "Enter Authentik URL (e.g., https://auth.example.com): ", "authentik_url")
		if err != nil {
			return err
		}
		url = input

		// Offer to save to Consul for next time
		savePrompt, err := eos_io.PromptInput(rc, "Save Authentik URL to Consul for future use? (y/n): ", "save_to_consul")
		if err == nil && (savePrompt == "y" || savePrompt == "yes" || savePrompt == "Y" || savePrompt == "Yes") {
			if consulClient, err := consul_config.NewClient(rc.Ctx); err == nil {
				if err := consulClient.Set(rc.Ctx, "authentik/url", url); err == nil {
					logger.Info("Saved Authentik URL to Consul - you won't be prompted again")
				} else {
					logger.Warn("Failed to save to Consul", zap.Error(err))
				}
			}
		}
	}

	// Auto-add https:// if no protocol specified
	if url != "" && !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
		logger.Info("Added https:// prefix to URL", zap.String("url", url))
	}

	// Resolve token
	token := config.Token
	if token == "" {
		input, err := eos_io.PromptSecurePassword(rc, "Enter Authentik API token: ")
		if err != nil {
			return err
		}
		token = input
	}

	if url == "" || token == "" {
		return eos_err.NewUserError("Authentik URL and token are required")
	}

	// Determine output file - default to /mnt for centralized backup storage
	output := config.Output
	if output == "" {
		timestamp := time.Now().Format("20060102-150405")
		backupDir := "/mnt/eos-backups/authentik"

		// Create backup directory if it doesn't exist
		if err := os.MkdirAll(backupDir, shared.ServiceDirPerm); err != nil {
			logger.Warn("Failed to create /mnt backup directory, using current directory",
				zap.Error(err))
			output = fmt.Sprintf("authentik-backup-%s.%s", timestamp, config.Format)
		} else {
			output = filepath.Join(backupDir, fmt.Sprintf("authentik-backup-%s.%s", timestamp, config.Format))
		}
	}

	// Create backup directory if needed
	backupDir := filepath.Dir(output)
	if backupDir != "." && backupDir != "/" {
		if err := os.MkdirAll(backupDir, shared.ServiceDirPerm); err != nil {
			return fmt.Errorf("failed to create backup directory: %w", err)
		}
	}

	// INTERVENE - Extract configuration
	logger.Info("Extracting Authentik configuration",
		zap.String("url", url),
		zap.String("output", output))

	// If extracting Wazuh-specific config
	types := config.Types
	if config.ExtractWazuh {
		types = []string{"providers", "applications", "mappings", "groups"}
		logger.Info("Extracting Wazuh/Wazuh SSO specific configuration")
	}

	// Default to all types if none specified
	if len(types) == 0 && !config.ExtractWazuh {
		types = []string{"providers", "applications", "mappings", "flows",
			"stages", "groups", "policies", "certificates", "blueprints", "outposts", "tenants"}
	}

	// Extract configuration using the helper function
	authentikConfig, err := authentik.ExtractConfigurationAPI(rc.Ctx, url, token, types, config.Apps, config.Providers, config.IncludeSecrets)
	if err != nil {
		return fmt.Errorf("failed to extract configuration: %w", err)
	}

	// Save to file
	var data []byte
	if config.Format == "yaml" {
		data, err = yaml.Marshal(authentikConfig)
	} else {
		data, err = json.MarshalIndent(authentikConfig, "", "  ")
	}
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(output, data, shared.SecretFilePerm); err != nil {
		return fmt.Errorf("failed to save backup: %w", err)
	}

	// EVALUATE - Verify and report
	logger.Info("Backup completed successfully",
		zap.String("file", output),
		zap.Int("providers", len(authentikConfig.Providers)),
		zap.Int("applications", len(authentikConfig.Applications)),
		zap.Int("mappings", len(authentikConfig.PropertyMappings)),
		zap.Int("flows", len(authentikConfig.Flows)),
		zap.Int("stages", len(authentikConfig.Stages)),
		zap.Int("groups", len(authentikConfig.Groups)),
		zap.Int("policies", len(authentikConfig.Policies)),
		zap.Int("certificates", len(authentikConfig.Certificates)),
		zap.Int("blueprints", len(authentikConfig.Blueprints)),
		zap.Int("outposts", len(authentikConfig.Outposts)),
		zap.Int("tenants", len(authentikConfig.Tenants)))

	// Check for critical Wazuh configuration
	if config.ExtractWazuh || CheckWazuhConfiguration(authentikConfig) {
		logger.Info("Found Wazuh/Wazuh SSO configuration",
			zap.String("tip", "Use 'eos update authentik --from-backup' to import"))

		// Verify critical Roles mapping
		if !CheckRolesMapping(authentikConfig) {
			logger.Warn("Missing critical 'Roles' property mapping required for Wazuh SSO")
		}
	}

	return nil
}

// BackupFilesystem handles legacy filesystem-based backups
func BackupFilesystem(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Warn("Filesystem backup mode is deprecated. Consider using API-based backup instead.")

	// TODO: Implement filesystem backup if needed
	return eos_err.NewUserError("Filesystem backup not yet implemented. Use API-based backup with --url and --token flags")
}
