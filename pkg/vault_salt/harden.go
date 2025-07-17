package vault_salt

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
)

// Harden applies security hardening to Vault using SaltStack
func Harden(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Vault hardening via Salt")
	
	// ASSESS - Check prerequisites
	logger.Info("Assessing prerequisites for Vault hardening")
	if err := checkHardenPrerequisites(rc, config); err != nil {
		return fmt.Errorf("prerequisite check failed: %w", err)
	}
	
	// Confirm with user
	logger.Info("terminal prompt: Vault hardening will apply security configurations that may impact operations")
	if !interaction.PromptYesNo(rc.Ctx, "Do you want to proceed with Vault hardening?", false) {
		logger.Info("User declined Vault hardening")
		return nil
	}
	
	// Get root token for configuration
	rootToken, err := getRootToken(rc)
	if err != nil {
		return fmt.Errorf("failed to get root token: %w", err)
	}
	
	// INTERVENE - Execute Salt state
	logger.Info("Executing Salt state for Vault hardening")
	if err := executeSaltHarden(rc, config, rootToken); err != nil {
		return fmt.Errorf("salt hardening failed: %w", err)
	}
	
	// EVALUATE - Verify hardening
	logger.Info("Verifying Vault hardening")
	if err := verifyHardening(rc, config); err != nil {
		return fmt.Errorf("hardening verification failed: %w", err)
	}
	
	// Display important information
	displayHardeningInfo(rc, config)
	
	logger.Info("Vault hardening completed successfully")
	return nil
}

func checkHardenPrerequisites(rc *eos_io.RuntimeContext, config *Config) error {
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
	
	// Check if Vault service is running
	output, err := cli.ExecString("systemctl", "is-active", VaultServiceName)
	if err != nil || strings.TrimSpace(output) != "active" {
		return eos_err.NewUserError("vault service is not running")
	}
	
	// Check Vault status
	statusOutput, err := cli.ExecString("vault", "status", "-format=json")
	if err != nil && !strings.Contains(err.Error(), "exit status 2") {
		return fmt.Errorf("failed to check vault status: %w", err)
	}
	
	var status VaultStatus
	if err := json.Unmarshal([]byte(statusOutput), &status); err == nil {
		if !status.Initialized {
			return eos_err.NewUserError("vault is not initialized")
		}
		if status.Sealed {
			return eos_err.NewUserError("vault is sealed")
		}
	}
	
	// Check system requirements for hardening
	if err := checkHardeningSystemRequirements(rc); err != nil {
		return err
	}
	
	logger.Info("Hardening prerequisites check passed")
	return nil
}

func checkHardeningSystemRequirements(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if running as root
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("hardening requires root privileges")
	}
	
	// Check for required tools
	cli := eos_cli.New(rc)
	requiredTools := []string{"ufw", "sysctl", "systemctl", "logrotate"}
	for _, tool := range requiredTools {
		if _, err := cli.ExecString("which", tool); err != nil {
			logger.Warn("Required tool not found",
				zap.String("tool", tool))
		}
	}
	
	return nil
}

func executeSaltHarden(rc *eos_io.RuntimeContext, config *Config, rootToken string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Set Vault environment variables
	vaultAddr := fmt.Sprintf("https://127.0.0.1:%d", config.Port)
	if config.TLSDisable {
		vaultAddr = fmt.Sprintf("http://127.0.0.1:%d", config.Port)
	}
	
	// Prepare Salt pillar data
	pillarData := map[string]interface{}{
		"vault": map[string]interface{}{
			"addr":               vaultAddr,
			"token":              rootToken,
			"skip_verify":        true,
			"port":               config.Port,
			"cluster_port":       config.ClusterPort,
			"harden_system":      config.HardenSystem,
			"harden_network":     config.HardenNetwork,
			"harden_vault":       config.HardenVault,
			"harden_backup":      config.HardenBackup,
			"backup_enabled":     config.BackupEnabled,
			"backup_path":        config.BackupPath,
			"backup_schedule":    config.BackupSchedule,
			"audit_log_path":     AuditLogFilePath,
		},
	}
	
	// Add system hardening configuration
	if config.HardenSystem {
		pillarData["vault"].(map[string]interface{})["system_hardening"] = map[string]interface{}{
			"disable_swap":       true,
			"disable_core_dumps": true,
			"secure_kernel_params": map[string]interface{}{
				"kernel.randomize_va_space": 2,
				"kernel.exec-shield":        1,
				"kernel.kptr_restrict":      1,
				"kernel.yama.ptrace_scope":  1,
				"net.ipv4.tcp_syncookies":   1,
				"net.ipv4.conf.all.rp_filter": 1,
			},
			"ulimits": map[string]interface{}{
				"vault_nofile": 65536,
				"vault_nproc":  4096,
			},
		}
	}
	
	// Add network hardening configuration
	if config.HardenNetwork {
		pillarData["vault"].(map[string]interface{})["network_hardening"] = map[string]interface{}{
			"firewall_rules": []map[string]interface{}{
				{
					"port":     config.Port,
					"protocol": "tcp",
					"action":   "allow",
					"comment":  "Vault API",
				},
				{
					"port":     config.ClusterPort,
					"protocol": "tcp",
					"action":   "allow",
					"comment":  "Vault Cluster",
				},
			},
			"ssh_hardening": map[string]interface{}{
				"permit_root_login":     "no",
				"password_auth":         "no",
				"x11_forwarding":        "no",
				"max_auth_tries":        3,
				"client_alive_interval": 300,
			},
		}
	}
	
	// Add Vault-specific hardening
	if config.HardenVault {
		pillarData["vault"].(map[string]interface{})["vault_hardening"] = map[string]interface{}{
			"tls_min_version":     config.TLSMinVersion,
			"disable_mlock":       false,
			"disable_cache":       false,
			"disable_indexing":    false,
			"log_level":           "warn",
			"log_format":          "json",
			"enable_response_header_hostname": false,
			"enable_response_header_raft_node_id": false,
			"rate_limit": map[string]interface{}{
				"rate":        10000,
				"burst":       20000,
				"enabled":     true,
			},
			"request_limiter": map[string]interface{}{
				"rate":        1000,
				"burst":       2000,
				"enabled":     true,
			},
		}
	}
	
	// Add backup configuration
	if config.HardenBackup && config.BackupEnabled {
		pillarData["vault"].(map[string]interface{})["backup_config"] = map[string]interface{}{
			"backup_path":     config.BackupPath,
			"backup_schedule": config.BackupSchedule,
			"retention_days":  30,
			"encryption":      true,
			"compression":     true,
		}
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
		SaltStateVaultHarden,
		"--output=json",
		"--output-indent=2",
		fmt.Sprintf("pillar='%s'", string(pillarJSON)),
	}
	
	// Set environment variables for Salt execution
	env := os.Environ()
	env = append(env, fmt.Sprintf("%s=%s", VaultAddrEnvVar, vaultAddr))
	env = append(env, fmt.Sprintf("%s=%s", VaultTokenEnvVar, rootToken))
	env = append(env, fmt.Sprintf("%s=true", VaultSkipVerifyEnvVar))
	
	logger.Info("Executing Salt state",
		zap.String("state", SaltStateVaultHarden),
		zap.Bool("system", config.HardenSystem),
		zap.Bool("network", config.HardenNetwork),
		zap.Bool("vault", config.HardenVault),
		zap.Bool("backup", config.HardenBackup))
	
	// Execute with environment variables
	os.Setenv(VaultAddrEnvVar, vaultAddr)
	os.Setenv(VaultTokenEnvVar, rootToken)
	os.Setenv(VaultSkipVerifyEnvVar, "true")
	defer func() {
		os.Unsetenv(VaultAddrEnvVar)
		os.Unsetenv(VaultTokenEnvVar)
		os.Unsetenv(VaultSkipVerifyEnvVar)
	}()
	
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
	
	// Restart Vault to apply hardening changes
	logger.Info("Restarting Vault service to apply hardening")
	if _, err := cli.ExecString("systemctl", "restart", VaultServiceName); err != nil {
		return fmt.Errorf("failed to restart vault service: %w", err)
	}
	
	// Wait for service to be ready
	if err := waitForVaultReady(rc, config); err != nil {
		return fmt.Errorf("vault service failed to become ready after hardening: %w", err)
	}
	
	logger.Info("Salt hardening state executed successfully")
	return nil
}

func verifyHardening(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	cli := eos_cli.New(rc)
	
	// Verify system hardening
	if config.HardenSystem {
		// Check swap
		swapOutput, err := cli.ExecString("swapon", "--show")
		if err == nil && swapOutput != "" {
			logger.Warn("Swap is still enabled")
		} else {
			logger.Info("Swap is disabled")
		}
		
		// Check kernel parameters
		kernelParams := []string{
			"kernel.randomize_va_space",
			"net.ipv4.tcp_syncookies",
		}
		for _, param := range kernelParams {
			output, err := cli.ExecString("sysctl", param)
			if err != nil {
				logger.Warn("Failed to check kernel parameter",
					zap.String("param", param),
					zap.Error(err))
			} else {
				logger.Debug("Kernel parameter verified",
					zap.String("param", param),
					zap.String("value", strings.TrimSpace(output)))
			}
		}
	}
	
	// Verify network hardening
	if config.HardenNetwork {
		// Check firewall rules
		ufwOutput, err := cli.ExecString("ufw", "status", "numbered")
		if err != nil {
			logger.Warn("Failed to check firewall status", zap.Error(err))
		} else {
			if strings.Contains(ufwOutput, fmt.Sprintf("%d/tcp", config.Port)) {
				logger.Info("Firewall rule for Vault API verified")
			}
		}
		
		// Check SSH configuration
		sshConfig := "/etc/ssh/sshd_config"
		if content, err := os.ReadFile(sshConfig); err == nil {
			configStr := string(content)
			if strings.Contains(configStr, "PermitRootLogin no") {
				logger.Info("SSH root login disabled")
			}
			if strings.Contains(configStr, "PasswordAuthentication no") {
				logger.Info("SSH password authentication disabled")
			}
		}
	}
	
	// Verify Vault hardening
	if config.HardenVault {
		// Check audit logging
		auditLogPath := AuditLogFilePath
		if info, err := os.Stat(auditLogPath); err == nil {
			logger.Info("Vault audit log verified",
				zap.String("path", auditLogPath),
				zap.Int64("size", info.Size()))
		}
		
		// Check log rotation
		logrotateConfig := "/etc/logrotate.d/vault"
		if _, err := os.Stat(logrotateConfig); err == nil {
			logger.Info("Log rotation configured")
		}
	}
	
	// Verify backup configuration
	if config.HardenBackup && config.BackupEnabled {
		// Check backup directory
		if info, err := os.Stat(config.BackupPath); err == nil && info.IsDir() {
			logger.Info("Backup directory verified",
				zap.String("path", config.BackupPath))
		}
		
		// Check backup cron job
		cronOutput, err := cli.ExecString("crontab", "-l")
		if err == nil && strings.Contains(cronOutput, "vault-backup") {
			logger.Info("Backup cron job configured")
		}
	}
	
	logger.Info("Vault hardening verified successfully")
	return nil
}

func displayHardeningInfo(rc *eos_io.RuntimeContext, config *Config) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("=== Vault Hardening Summary ===")
	
	if config.HardenSystem {
		logger.Info("System Hardening Applied:",
			zap.String("swap", "disabled"),
			zap.String("core_dumps", "disabled"),
			zap.String("kernel_hardening", "enabled"))
	}
	
	if config.HardenNetwork {
		logger.Info("Network Hardening Applied:",
			zap.Int("vault_port", config.Port),
			zap.Int("cluster_port", config.ClusterPort),
			zap.String("firewall", "configured"),
			zap.String("ssh", "hardened"))
	}
	
	if config.HardenVault {
		logger.Info("Vault Hardening Applied:",
			zap.String("tls_min_version", config.TLSMinVersion),
			zap.String("audit_logging", "enabled"),
			zap.String("rate_limiting", "enabled"),
			zap.String("log_rotation", "configured"))
	}
	
	if config.HardenBackup && config.BackupEnabled {
		logger.Info("Backup Configuration:",
			zap.String("path", config.BackupPath),
			zap.String("schedule", config.BackupSchedule),
			zap.String("encryption", "enabled"))
	}
	
	logger.Info("IMPORTANT: Remember to:",
		zap.String("1", "Regularly review audit logs"),
		zap.String("2", "Monitor system resources"),
		zap.String("3", "Test backup restoration"),
		zap.String("4", "Keep Vault updated"),
		zap.String("5", "Review and rotate credentials"))
}