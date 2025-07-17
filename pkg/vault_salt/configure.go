package vault_salt

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// Configure configures Vault using SaltStack
func Configure(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Vault configuration via Salt")
	
	// ASSESS - Check prerequisites
	logger.Info("Assessing prerequisites for Vault configuration")
	if err := checkConfigurePrerequisites(rc, config); err != nil {
		return fmt.Errorf("prerequisite check failed: %w", err)
	}
	
	// INTERVENE - Execute Salt state
	logger.Info("Executing Salt state for Vault configuration")
	if err := executeSaltConfigure(rc, config); err != nil {
		return fmt.Errorf("salt configuration failed: %w", err)
	}
	
	// EVALUATE - Verify configuration
	logger.Info("Verifying Vault configuration")
	if err := verifyConfiguration(rc, config); err != nil {
		return fmt.Errorf("configuration verification failed: %w", err)
	}
	
	logger.Info("Vault configuration completed successfully")
	return nil
}

func checkConfigurePrerequisites(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if Salt is available
	cli := eos_cli.New(rc)
	if _, err := cli.ExecString("salt-call", "--version"); err != nil {
		logger.Error("Salt is not available", zap.Error(err))
		return eos_err.NewUserError("salt is not available")
	}
	
	// Check if Vault is installed
	if _, err := cli.ExecString("vault", "version"); err != nil {
		logger.Error("Vault is not installed", zap.Error(err))
		return eos_err.NewUserError("vault is not installed")
	}
	
	// Check if Vault service exists
	if _, err := cli.ExecString("systemctl", "status", VaultServiceName); err != nil {
		logger.Warn("Vault service not found, will create it")
	}
	
	// Ensure configuration directory exists
	configDir := config.ConfigPath
	if err := ensureDirectory(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	
	// Generate TLS certificates if needed
	if !config.TLSDisable {
		logger.Info("Checking TLS certificates")
		if err := ensureTLSCertificates(rc, config); err != nil {
			return fmt.Errorf("failed to ensure TLS certificates: %w", err)
		}
	}
	
	logger.Info("Configuration prerequisites check passed")
	return nil
}

func ensureDirectory(path string, perm os.FileMode) error {
	if err := os.MkdirAll(path, perm); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", path, err)
	}
	return nil
}

func ensureTLSCertificates(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	certFile := filepath.Join(config.TLSPath, "vault-cert.pem")
	keyFile := filepath.Join(config.TLSPath, "vault-key.pem")
	
	// Check if certificates already exist
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			logger.Info("TLS certificates already exist")
			config.TLSCertFile = certFile
			config.TLSKeyFile = keyFile
			return nil
		}
	}
	
	// Generate self-signed certificates
	logger.Info("Generating self-signed TLS certificates")
	
	// Ensure TLS directory exists
	if err := ensureDirectory(config.TLSPath, 0755); err != nil {
		return err
	}
	
	// Generate certificates using openssl
	args := []string{
		"req", "-x509", "-nodes", "-newkey", "rsa:4096",
		"-keyout", keyFile,
		"-out", certFile,
		"-days", "3650",
		"-subj", "/C=AU/ST=State/L=City/O=Organization/CN=vault.local",
		"-addext", "subjectAltName=DNS:vault.local,DNS:localhost,IP:127.0.0.1",
	}
	
	cli := eos_cli.New(rc)
	if _, err := cli.ExecString("openssl", args...); err != nil {
		return fmt.Errorf("failed to generate TLS certificates: %w", err)
	}
	
	// Set proper permissions
	if err := os.Chmod(keyFile, 0600); err != nil {
		return fmt.Errorf("failed to set key permissions: %w", err)
	}
	
	if err := os.Chmod(certFile, 0644); err != nil {
		return fmt.Errorf("failed to set cert permissions: %w", err)
	}
	
	config.TLSCertFile = certFile
	config.TLSKeyFile = keyFile
	
	logger.Info("TLS certificates generated successfully",
		zap.String("cert", certFile),
		zap.String("key", keyFile))
	
	return nil
}

func executeSaltConfigure(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Prepare Salt pillar data
	pillarData := map[string]interface{}{
		"vault": map[string]interface{}{
			"config_path":      config.ConfigPath,
			"data_path":        config.DataPath,
			"log_path":         config.LogPath,
			"listen_address":   config.ListenAddress,
			"cluster_address":  config.ClusterAddress,
			"api_addr":         fmt.Sprintf("https://%s:%d", getHostname(), config.Port),
			"cluster_api_addr": fmt.Sprintf("https://%s:%d", getHostname(), config.ClusterPort),
			"port":             config.Port,
			"cluster_port":     config.ClusterPort,
			"ui_enabled":       config.UIEnabled,
			"tls_disable":      config.TLSDisable,
			"tls_cert_file":    config.TLSCertFile,
			"tls_key_file":     config.TLSKeyFile,
			"tls_min_version":  config.TLSMinVersion,
			"storage_type":     config.StorageType,
			"storage_path":     config.StoragePath,
			"max_lease_ttl":    config.MaxLeaseTTL.String(),
			"default_lease_ttl": config.DefaultLeaseTTL.String(),
			"telemetry_enabled": config.TelemetryEnabled,
			"metrics_path":     config.MetricsPath,
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
		SaltStateVaultConfigure,
		"--output=json",
		"--output-indent=2",
		fmt.Sprintf("pillar='%s'", string(pillarJSON)),
	}
	
	logger.Info("Executing Salt state",
		zap.String("state", SaltStateVaultConfigure),
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
	
	// Restart Vault service to apply configuration
	logger.Info("Restarting Vault service")
	if _, err := cli.ExecString("systemctl", "restart", VaultServiceName); err != nil {
		return fmt.Errorf("failed to restart vault service: %w", err)
	}
	
	// Wait for service to be ready
	logger.Info("Waiting for Vault service to be ready")
	if err := waitForVaultReady(rc, config); err != nil {
		return fmt.Errorf("vault service failed to become ready: %w", err)
	}
	
	logger.Info("Salt configuration state executed successfully")
	return nil
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "localhost"
	}
	return hostname
}

func waitForVaultReady(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	maxAttempts := 30
	for i := 0; i < maxAttempts; i++ {
		select {
		case <-rc.Ctx.Done():
			return rc.Ctx.Err()
		default:
			// Check if service is active
			cli := eos_cli.New(rc)
			output, err := cli.ExecString("systemctl", "is-active", VaultServiceName)
			if err == nil && strings.TrimSpace(output) == "active" {
				// Check if Vault is responding
				if _, err := cli.ExecString("vault", "status"); err == nil || strings.Contains(err.Error(), "exit status 2") {
					logger.Info("Vault service is ready")
					return nil
				}
			}
			
			logger.Debug("Waiting for Vault service",
				zap.Int("attempt", i+1),
				zap.Int("max_attempts", maxAttempts))
			
			time.Sleep(2 * time.Second)
		}
	}
	
	return fmt.Errorf("vault service did not become ready in time")
}

func verifyConfiguration(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check configuration file exists
	configFile := filepath.Join(config.ConfigPath, VaultConfigFile)
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return fmt.Errorf("configuration file not found: %s", configFile)
	}
	
	// Check service is running
	cli := eos_cli.New(rc)
	output, err := cli.ExecString("systemctl", "is-active", VaultServiceName)
	if err != nil || strings.TrimSpace(output) != "active" {
		return fmt.Errorf("vault service is not active")
	}
	
	// Check Vault is responding
	statusOutput, err := cli.ExecString("vault", "status", "-format=json")
	if err != nil && !strings.Contains(err.Error(), "exit status 2") {
		return fmt.Errorf("vault is not responding: %w", err)
	}
	
	// Parse status
	var status VaultStatus
	if err := json.Unmarshal([]byte(statusOutput), &status); err == nil {
		logger.Info("Vault configuration verified",
			zap.Bool("initialized", status.Initialized),
			zap.Bool("sealed", status.Sealed),
			zap.String("version", status.Version))
		
		// Check expected configuration
		if !config.TLSDisable {
			// Verify TLS is enabled by checking the API address
			if !strings.HasPrefix(os.Getenv(VaultAddrEnvVar), "https://") {
				logger.Warn("TLS appears to be disabled when it should be enabled")
			}
		}
	}
	
	// Check directories exist with proper permissions
	dirs := []string{
		config.DataPath,
		config.LogPath,
	}
	
	for _, dir := range dirs {
		info, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("directory %s does not exist: %w", dir, err)
		}
		
		if !info.IsDir() {
			return fmt.Errorf("%s is not a directory", dir)
		}
		
		logger.Debug("Directory verified",
			zap.String("path", dir),
			zap.String("permissions", info.Mode().String()))
	}
	
	logger.Info("Vault configuration verified successfully")
	return nil
}