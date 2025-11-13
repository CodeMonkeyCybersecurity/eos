// pkg/hecate/regenerate.go

package hecate

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// RegenerateFromConsulKV regenerates Hecate deployment files from Consul KV configuration.
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Load configuration from Consul KV, check existing files
// - Intervene: Backup existing files, regenerate from templates
// - Evaluate: Verify files created, restart containers
func RegenerateFromConsulKV(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Load configuration from Consul KV
	logger.Info("Loading Hecate configuration from Consul KV")

	configStorage, err := NewConfigStorage(rc)
	if err != nil {
		return fmt.Errorf("failed to initialize config storage: %w", err)
	}

	rawConfig, err := configStorage.LoadConfig(rc)
	if err != nil {
		return fmt.Errorf("failed to load configuration from Consul KV: %w", err)
	}

	if rawConfig == nil || len(rawConfig.Apps) == 0 {
		return fmt.Errorf("no Hecate configuration found in Consul KV\n\n" +
			"Fix:\n" +
			"  1. Run: eos create config --hecate\n" +
			"  2. Then: eos create hecate --config hecate-config.yaml")
	}

	logger.Info("Configuration loaded from Consul KV",
		zap.Int("apps", len(rawConfig.Apps)))

	// Convert RawYAMLConfig to YAMLHecateConfig by creating temp YAML file
	tempYAMLPath := "/tmp/hecate-config-from-consul.yaml"
	yamlData, err := yaml.Marshal(rawConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	if err := os.WriteFile(tempYAMLPath, yamlData, shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write temp config: %w", err)
	}
	defer func() { _ = os.Remove(tempYAMLPath) }()

	config, err := LoadYAMLConfig(rc, tempYAMLPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// ASSESS: Check existing files and create backups
	outputDir := "/opt/hecate"
	timestamp := time.Now().Format("20060102-150405")

	filesToBackup := []string{
		filepath.Join(outputDir, "docker-compose.yml"),
		filepath.Join(outputDir, ".env"),
		filepath.Join(outputDir, "Caddyfile"),
	}

	logger.Info("Backing up existing files",
		zap.String("timestamp", timestamp))

	for _, file := range filesToBackup {
		if _, err := os.Stat(file); err == nil {
			backupFile := fmt.Sprintf("%s.%s.bak", file, timestamp)
			if err := os.Rename(file, backupFile); err != nil {
				logger.Warn("Failed to backup file",
					zap.String("file", file),
					zap.Error(err))
			} else {
				logger.Info("Backed up file",
					zap.String("original", file),
					zap.String("backup", backupFile))
			}
		}
	}

	// INTERVENE: Discover environment for secret management
	logger.Info("Initializing environment and secrets")

	envConfig, err := environment.DiscoverEnvironment(rc)
	if err != nil {
		return fmt.Errorf("failed to discover environment: %w", err)
	}

	// INTERVENE: Regenerate files using YAML generator
	logger.Info("Regenerating deployment files from templates")

	if err := GenerateFromYAML(rc, config, outputDir, envConfig); err != nil {
		return fmt.Errorf("failed to regenerate deployment files: %w", err)
	}

	// EVALUATE: Verify files were created and validate them
	logger.Info("Verifying generated files")

	for _, file := range filesToBackup {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			return fmt.Errorf("file not created: %s", file)
		}
		logger.Debug("File verified",
			zap.String("file", file))
	}

	// CRITICAL: Validate generated files for syntax errors
	logger.Info("Validating generated configuration files")
	if err := ValidateGeneratedFiles(rc, outputDir); err != nil {
		return fmt.Errorf("validation failed: %w\n\n"+
			"Generated files have errors. This is a bug in Eos.\n"+
			"Please report this issue with the validation output above.", err)
	}

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ✓ Files regenerated successfully")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Backups saved with timestamp: " + timestamp)
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Next steps:")
	logger.Info("terminal prompt:   1. Review generated files in: " + outputDir)
	logger.Info("terminal prompt:   2. Restart containers: cd " + outputDir + " && sudo docker compose up -d --force-recreate")
	logger.Info("terminal prompt: ")

	return nil
}
