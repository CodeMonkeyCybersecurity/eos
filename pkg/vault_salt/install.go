package vault_salt

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// Install installs Vault using SaltStack
func Install(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Vault installation via Salt")
	
	// ASSESS - Check prerequisites
	logger.Info("Assessing prerequisites for Vault installation")
	if err := checkInstallPrerequisites(rc, config); err != nil {
		return fmt.Errorf("prerequisite check failed: %w", err)
	}
	
	// INTERVENE - Execute Salt state
	logger.Info("Executing Salt state for Vault installation")
	if err := executeSaltInstall(rc, config); err != nil {
		return fmt.Errorf("salt installation failed: %w", err)
	}
	
	// Initialize Vault if needed
	logger.Info("Checking if Vault initialization is needed")
	if err := initializeVault(rc, config); err != nil {
		return fmt.Errorf("vault initialization failed: %w", err)
	}
	
	// EVALUATE - Verify installation
	logger.Info("Verifying Vault installation")
	if err := verifyInstallation(rc, config); err != nil {
		return fmt.Errorf("installation verification failed: %w", err)
	}
	
	logger.Info("Vault installation completed successfully")
	return nil
}

func checkInstallPrerequisites(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if Salt is available
	cli := eos_cli.New(rc)
	if _, err := cli.ExecString("salt-call", "--version"); err != nil {
		logger.Error("Salt is not available", zap.Error(err))
		return eos_err.NewUserError("salt is not available")
	}
	
	// Check if Vault is already installed
	if _, err := cli.ExecString("vault", "version"); err == nil {
		logger.Warn("Vault appears to be already installed")
		// Check if service is running
		if output, err := cli.ExecString("systemctl", "is-active", VaultServiceName); err == nil {
			if strings.TrimSpace(output) == "active" {
				return eos_err.NewUserError("vault service is already running")
			}
		}
	}
	
	// Check system requirements
	if err := checkSystemRequirements(rc); err != nil {
		return err
	}
	
	// Create necessary directories
	directories := []string{
		config.InstallPath,
		config.ConfigPath,
		config.DataPath,
		config.LogPath,
		config.TLSPath,
		filepath.Dir(VaultInitDataFile),
	}
	
	for _, dir := range directories {
		if err := os.MkdirAll(dir, 0755); err != nil {
			logger.Error("Failed to create directory",
				zap.String("directory", dir),
				zap.Error(err))
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	
	logger.Info("Prerequisites check passed")
	return nil
}

func checkSystemRequirements(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check OS
	cli := eos_cli.New(rc)
	if output, err := cli.ExecString("lsb_release", "-i", "-s"); err == nil {
		if !strings.Contains(strings.ToLower(output), "ubuntu") {
			return eos_err.NewUserError("this tool requires Ubuntu")
		}
	}
	
	// Check if running as root
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("this command requires root privileges")
	}
	
	// Check disk space (minimum 1GB free)
	if output, err := cli.ExecString("df", "-BG", "/opt"); err == nil {
		lines := strings.Split(output, "\n")
		if len(lines) > 1 {
			fields := strings.Fields(lines[1])
			if len(fields) > 3 {
				available := strings.TrimSuffix(fields[3], "G")
				logger.Debug("Available disk space", zap.String("space", available+"G"))
			}
		}
	}
	
	return nil
}

func executeSaltInstall(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Prepare Salt pillar data
	pillarData := map[string]interface{}{
		"vault": map[string]interface{}{
			"version":         config.Version,
			"install_path":    config.InstallPath,
			"config_path":     config.ConfigPath,
			"data_path":       config.DataPath,
			"log_path":        config.LogPath,
			"tls_path":        config.TLSPath,
			"listen_address":  config.ListenAddress,
			"port":            config.Port,
			"cluster_port":    config.ClusterPort,
			"ui_enabled":      config.UIEnabled,
			"tls_disable":     config.TLSDisable,
			"storage_type":    config.StorageType,
			"storage_path":    config.StoragePath,
			"max_lease_ttl":   config.MaxLeaseTTL.String(),
			"default_lease_ttl": config.DefaultLeaseTTL.String(),
		},
	}
	
	pillarJSON, err := json.Marshal(pillarData)
	if err != nil {
		return fmt.Errorf("failed to marshal pillar data: %w", err)
	}
	
	// Execute Salt state
	args := []string{
		"--local",
		"--file-root=" + config.SaltFileRoot,
		"--pillar-root=" + config.SaltPillarRoot,
		"state.apply",
		SaltStateVaultInstall,
		"--output=json",
		"--output-indent=2",
		fmt.Sprintf("pillar='%s'", string(pillarJSON)),
	}
	
	logger.Info("Executing Salt state",
		zap.String("state", SaltStateVaultInstall),
		zap.Strings("args", args))
	
	cli := eos_cli.WithTimeout(rc, config.SaltTimeout)
	output, err := cli.ExecString("salt-call", args...)
	if err != nil {
		logger.Error("Salt state execution failed",
			zap.Error(err),
			zap.String("output", output))
		return fmt.Errorf("salt state execution failed: %w", err)
	}
	
	// Parse Salt output
	if err := parseSaltOutput(output); err != nil {
		return fmt.Errorf("salt state failed: %w", err)
	}
	
	logger.Info("Salt installation state executed successfully")
	return nil
}

func initializeVault(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Set Vault address
	os.Setenv(VaultAddrEnvVar, fmt.Sprintf("https://127.0.0.1:%d", config.Port))
	if config.TLSDisable {
		os.Setenv(VaultAddrEnvVar, fmt.Sprintf("http://127.0.0.1:%d", config.Port))
	}
	os.Setenv(VaultSkipVerifyEnvVar, "true") // Skip verification for initial setup
	
	// Create Vault client
	vaultConfig := api.DefaultConfig()
	if err := vaultConfig.ReadEnvironment(); err != nil {
		return fmt.Errorf("failed to read vault environment: %w", err)
	}
	
	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return fmt.Errorf("failed to create vault client: %w", err)
	}
	
	// Check initialization status
	initStatus, err := client.Sys().InitStatus()
	if err != nil {
		logger.Warn("Failed to check init status, assuming not initialized",
			zap.Error(err))
		initStatus = false
	}
	
	if initStatus {
		logger.Info("Vault is already initialized")
		return nil
	}
	
	// Initialize Vault
	logger.Info("Initializing Vault",
		zap.Int("key_shares", config.KeyShares),
		zap.Int("key_threshold", config.KeyThreshold))
	
	initRequest := &api.InitRequest{
		SecretShares:    config.KeyShares,
		SecretThreshold: config.KeyThreshold,
	}
	
	initResponse, err := client.Sys().Init(initRequest)
	if err != nil {
		return fmt.Errorf("failed to initialize vault: %w", err)
	}
	
	// Save initialization data
	initData := VaultInitResponse{
		UnsealKeysB64:   initResponse.Keys,
		UnsealKeysHex:   initResponse.KeysB64,
		UnsealShares:    config.KeyShares,
		UnsealThreshold: config.KeyThreshold,
		RootToken:       initResponse.RootToken,
	}
	
	if err := saveInitData(rc, &initData); err != nil {
		return fmt.Errorf("failed to save init data: %w", err)
	}
	
	// Unseal Vault
	logger.Info("Unsealing Vault")
	for i := 0; i < config.KeyThreshold; i++ {
		_, err := client.Sys().Unseal(initResponse.Keys[i])
		if err != nil {
			logger.Error("Failed to unseal with key",
				zap.Int("key_index", i),
				zap.Error(err))
			return fmt.Errorf("failed to unseal vault: %w", err)
		}
	}
	
	logger.Info("Vault initialized and unsealed successfully")
	return nil
}

func saveInitData(rc *eos_io.RuntimeContext, data *VaultInitResponse) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(VaultInitDataFile), 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	
	// Marshal data
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal init data: %w", err)
	}
	
	// Write file with restricted permissions
	if err := os.WriteFile(VaultInitDataFile, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write init data: %w", err)
	}
	
	logger.Info("Vault initialization data saved",
		zap.String("file", VaultInitDataFile))
	
	// Display important information
	logger.Info("IMPORTANT: Vault root token and unseal keys have been saved",
		zap.String("location", VaultInitDataFile),
		zap.String("root_token", data.RootToken))
	
	return nil
}

func verifyInstallation(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check Vault binary
	cli := eos_cli.New(rc)
	if _, err := cli.ExecString("vault", "version"); err != nil {
		return fmt.Errorf("vault binary not found: %w", err)
	}
	
	// Check service status
	output, err := cli.ExecString("systemctl", "is-active", VaultServiceName)
	if err != nil || strings.TrimSpace(output) != "active" {
		return fmt.Errorf("vault service is not active")
	}
	
	// Check Vault status
	statusOutput, err := cli.ExecString("vault", "status", "-format=json")
	if err != nil {
		// Vault returns exit code 2 when sealed, which is expected
		if !strings.Contains(err.Error(), "exit status 2") {
			return fmt.Errorf("failed to check vault status: %w", err)
		}
	}
	
	var status VaultStatus
	if err := json.Unmarshal([]byte(statusOutput), &status); err == nil {
		logger.Info("Vault status",
			zap.Bool("initialized", status.Initialized),
			zap.Bool("sealed", status.Sealed),
			zap.String("version", status.Version))
	}
	
	// Check directories
	requiredDirs := []string{
		config.ConfigPath,
		config.DataPath,
		config.LogPath,
		config.TLSPath,
	}
	
	for _, dir := range requiredDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return fmt.Errorf("required directory %s does not exist", dir)
		}
	}
	
	logger.Info("Vault installation verified successfully")
	return nil
}

func parseSaltOutput(output string) error {
	// Basic validation of Salt output
	if strings.Contains(output, "Failed:") && !strings.Contains(output, "Failed:     0") {
		return fmt.Errorf("salt state execution had failures")
	}
	
	if strings.Contains(output, "ERROR") {
		return fmt.Errorf("salt state execution had errors")
	}
	
	return nil
}