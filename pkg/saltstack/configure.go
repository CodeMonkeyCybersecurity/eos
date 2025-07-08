package saltstack

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// Configurer handles Salt configuration operations
type Configurer struct{}

// NewConfigurer creates a new Salt configurer instance
func NewConfigurer() *Configurer {
	return &Configurer{}
}

// Configure sets up Salt configuration files and directories
func (c *Configurer) Configure(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Step 1: Create directory structure
	logger.Info("Creating Salt directory structure")
	if err := c.createDirectories(rc); err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to create directories: %w", err))
	}
	
	// Step 2: Create minion configuration
	logger.Info("Creating minion configuration")
	if err := c.createMinionConfig(rc, config); err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to create minion config: %w", err))
	}
	
	// Step 3: Create test state file
	logger.Info("Creating test state file")
	if err := c.createTestState(rc); err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to create test state: %w", err))
	}
	
	// Step 4: Deploy Eos salt states
	logger.Info("Deploying Eos salt states")
	if err := c.deployStates(rc); err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to deploy states: %w", err))
	}
	
	// Step 5: Set permissions
	logger.Info("Setting permissions on Salt directories")
	if err := c.setPermissions(rc); err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("failed to set permissions: %w", err))
	}
	
	logger.Info("Salt configuration completed successfully")
	return nil
}

// createDirectories creates the necessary Salt directory structure
func (c *Configurer) createDirectories(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	directories := []string{
		SaltConfigDir,
		SaltStatesDir,
		EosStatesDir,
		SaltPillarDir,
	}
	
	for _, dir := range directories {
		logger.Debug("Creating directory", zap.String("path", dir))
		
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
		
		// Verify directory was created
		if stat, err := os.Stat(dir); err != nil {
			return fmt.Errorf("failed to verify directory %s: %w", dir, err)
		} else if !stat.IsDir() {
			return fmt.Errorf("%s exists but is not a directory", dir)
		}
	}
	
	logger.Debug("All directories created successfully")
	return nil
}

// createMinionConfig creates the Salt minion configuration file
func (c *Configurer) createMinionConfig(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Backup existing configuration if it exists
	if _, err := os.Stat(MinionConfigPath); err == nil {
		backupPath := MinionConfigPath + ".backup." + time.Now().Format("20060102-150405")
		logger.Info("Backing up existing minion config", zap.String("backup", backupPath))
		
		if err := c.backupFile(rc, MinionConfigPath, backupPath); err != nil {
			logger.Warn("Failed to backup existing config", zap.Error(err))
		}
	}
	
	// Create minion configuration
	minionConfig := &MinionConfig{
		LogLevel: config.LogLevel,
	}
	
	if config.MasterMode {
		// Master-minion mode configuration
		minionConfig.FileClient = "remote"
		minionConfig.MasterHost = "salt"  // Default master hostname
		minionConfig.MinionID = DefaultMinionID
		
		logger.Info("Configuring for master-minion mode")
	} else {
		// Masterless mode configuration
		minionConfig.FileClient = DefaultFileClient
		minionConfig.FileRoots = map[string][]string{
			"base": {
				SaltStatesDir,
				EosStatesDir,
			},
		}
		minionConfig.PillarRoots = map[string][]string{
			"base": {
				SaltPillarDir,
			},
		}
		
		logger.Info("Configuring for masterless mode")
	}
	
	// Marshal configuration to YAML
	configData, err := yaml.Marshal(minionConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal minion config: %w", err)
	}
	
	// Write configuration file
	if err := os.WriteFile(MinionConfigPath, configData, 0644); err != nil {
		return fmt.Errorf("failed to write minion config: %w", err)
	}
	
	logger.Debug("Minion configuration written", zap.String("path", MinionConfigPath))
	
	// Verify configuration was written
	if stat, err := os.Stat(MinionConfigPath); err != nil {
		return fmt.Errorf("failed to verify minion config: %w", err)
	} else if stat.Size() == 0 {
		return fmt.Errorf("minion config file is empty")
	}
	
	return nil
}

// createTestState creates a test Salt state file
func (c *Configurer) createTestState(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	testStatePath := filepath.Join(EosStatesDir, TestStateName+".sls")
	
	// Write test state file
	if err := os.WriteFile(testStatePath, []byte(TestStateContent), 0644); err != nil {
		return fmt.Errorf("failed to write test state: %w", err)
	}
	
	logger.Debug("Test state file created", zap.String("path", testStatePath))
	
	// Verify file was created
	if stat, err := os.Stat(testStatePath); err != nil {
		return fmt.Errorf("failed to verify test state: %w", err)
	} else if stat.Size() == 0 {
		return fmt.Errorf("test state file is empty")
	}
	
	return nil
}

// setPermissions sets appropriate permissions on Salt directories
func (c *Configurer) setPermissions(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Set ownership to root:root for security
	directories := []string{
		SaltConfigDir,
		SaltStatesDir,
		SaltPillarDir,
	}
	
	for _, dir := range directories {
		logger.Debug("Setting permissions", zap.String("path", dir))
		
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "chown",
			Args:    []string{"-R", "root:root", dir},
			Timeout: 30 * time.Second,
		})
		
		if err != nil {
			logger.Warn("Failed to set ownership", zap.String("path", dir), zap.Error(err))
			// Continue, this is not fatal
		}
	}
	
	return nil
}

// backupFile creates a backup of an existing file
func (c *Configurer) backupFile(rc *eos_io.RuntimeContext, source, destination string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "cp",
		Args:    []string{"-p", source, destination},
		Timeout: 10 * time.Second,
	})
	
	if err != nil {
		return fmt.Errorf("failed to backup file: %w", err)
	}
	
	logger.Debug("File backed up", zap.String("source", source), zap.String("destination", destination))
	return nil
}

// deployStates copies Eos salt states from the codebase to the Salt file system
func (c *Configurer) deployStates(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Get the current working directory to find the Eos codebase
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}
	
	// Find the Eos salt states directory
	saltStatesSourceDir := filepath.Join(cwd, "salt", "states")
	
	// Check if the source directory exists
	if _, err := os.Stat(saltStatesSourceDir); os.IsNotExist(err) {
		// Try alternative path (might be running from different location)
		altPath := "/usr/local/share/eos/salt/states"
		if _, err := os.Stat(altPath); os.IsNotExist(err) {
			logger.Warn("Salt states source directory not found, skipping deployment",
				zap.String("primary_path", saltStatesSourceDir),
				zap.String("alternative_path", altPath))
			return nil
		}
		saltStatesSourceDir = altPath
	}
	
	logger.Info("Deploying salt states from source",
		zap.String("source", saltStatesSourceDir),
		zap.String("destination", SaltStatesDir))
	
	// Copy the entire states directory to /srv/salt
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "cp",
		Args:    []string{"-r", saltStatesSourceDir + "/.", SaltStatesDir},
		Timeout: 60 * time.Second,
	})
	
	if err != nil {
		return fmt.Errorf("failed to copy salt states: %w", err)
	}
	
	// Verify key states were deployed
	minioStatePath := filepath.Join(SaltStatesDir, "minio", "init.sls")
	if _, err := os.Stat(minioStatePath); err != nil {
		return fmt.Errorf("failed to verify minio state deployment: %w", err)
	}
	
	logger.Info("Salt states deployed successfully",
		zap.String("verified_state", minioStatePath))
	
	return nil
}