// cmd/update/system.go

package update

import (
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/config_loader"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/security/security_config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system/system_display"
	cerr "github.com/cockroachdb/errors"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var systemUpdateCmd = &cobra.Command{
	Use:   "system [target]",
	Short: "Apply comprehensive security hardening to target systems",
	Long: `Apply comprehensive security hardening to target systems using SaltStack.

This command follows the assessment→intervention→evaluation model:
1. Assessment: Evaluates current security posture
2. Intervention: Applies security hardening measures via SaltStack
3. Evaluation: Verifies security improvements

Examples:
  eos secure system "*"                    # Harden all minions
  eos secure system "web-servers"         # Harden web server group
  eos secure system "prod-*" --profile advanced    # Advanced hardening profile`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		if len(args) == 0 {
			return cerr.New("target minions must be specified")
		}

		target := args[0]
		profile, _ := cmd.Flags().GetString("profile")
		saltAPI, _ := cmd.Flags().GetString("salt-api")
		vaultPath, _ := cmd.Flags().GetString("vault-path")
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		logger.Info("Starting system security hardening",
			zap.String("target", target),
			zap.String("profile", profile),
			zap.Bool("dry_run", dryRun))

		// Assessment: Initialize SaltStack manager
		saltConfig := &system.SaltStackConfig{
			APIURL:    saltAPI,
			VaultPath: vaultPath + "/salt",
			Timeout:   5 * time.Minute,
		}

		saltManager, err := system.NewSaltStackManager(rc, saltConfig)
		if err != nil {
			return cerr.Wrap(err, "failed to initialize SaltStack manager")
		}

		// Create security hardening manager
		securityManager := system.NewSecurityHardeningManager(saltManager, vaultPath)

		// Generate security configuration based on profile
		securityConfig, err := security_config.GenerateSecurityConfig(rc, system.SecurityProfile(profile))
		if err != nil {
			return cerr.Wrap(err, "failed to generate security configuration")
		}

		if dryRun {
			logger.Info("Dry run mode - assessing security posture only")
			assessment, err := securityManager.AssessSecurityPosture(rc, target, securityConfig.Profile)
			if err != nil {
				return cerr.Wrap(err, "security assessment failed")
			}

			// Display assessment results
			if err := security_config.DisplaySecurityAssessment(rc, assessment); err != nil {
				logger.Warn("Failed to display security assessment", zap.Error(err))
			}
			return nil
		}

		// Intervention: Apply security hardening
		systemConfig := security_config.ConvertToSystemSecurityConfiguration(securityConfig)
		assessment, err := securityManager.HardenSystem(rc, target, systemConfig)
		if err != nil {
			return cerr.Wrap(err, "system hardening failed")
		}

		// Evaluation: Display results
		logger.Info("System security hardening completed",
			zap.Float64("compliance_score", assessment.ComplianceScore),
			zap.String("risk_level", assessment.RiskLevel),
			zap.Int("vulnerabilities_found", len(assessment.Vulnerabilities)),
			zap.Int("recommendations", len(assessment.Recommendations)))

		if err := security_config.DisplaySecurityAssessment(rc, assessment); err != nil {
			logger.Warn("Failed to display security assessment", zap.Error(err))
		}

		return nil
	}),
}

var twoFactorCmd = &cobra.Command{
	Use:   "2fa [target]",
	Short: "Setup two-factor authentication on target systems",
	Long: `Setup two-factor authentication (2FA) on target systems using SaltStack.

Supported 2FA methods:
- TOTP (Time-based One-Time Password) via Google Authenticator
- U2F (Universal 2nd Factor) hardware tokens
- FIDO2 WebAuthn

Examples:
  eos secure 2fa "*" --users alice,bob       # Setup 2FA for specific users
  eos secure 2fa "servers" --method totp     # Setup TOTP 2FA
  eos secure 2fa "prod-*" --enforce-ssh      # Enforce 2FA for SSH`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		if len(args) == 0 {
			return cerr.New("target minions must be specified")
		}

		target := args[0]
		method, _ := cmd.Flags().GetString("method")
		users, _ := cmd.Flags().GetStringSlice("users")
		saltAPI, _ := cmd.Flags().GetString("salt-api")
		vaultPath, _ := cmd.Flags().GetString("vault-path")
		enforceSSH, _ := cmd.Flags().GetBool("enforce-ssh")
		enforceSudo, _ := cmd.Flags().GetBool("enforce-sudo")

		logger.Info("Setting up two-factor authentication",
			zap.String("target", target),
			zap.String("method", method),
			zap.Strings("users", users))

		// Initialize SaltStack manager
		saltConfig := &system.SaltStackConfig{
			APIURL:    saltAPI,
			VaultPath: vaultPath + "/salt",
			Timeout:   5 * time.Minute,
		}

		saltManager, err := system.NewSaltStackManager(rc, saltConfig)
		if err != nil {
			return cerr.Wrap(err, "failed to initialize SaltStack manager")
		}

		// Create security hardening manager
		securityManager := system.NewSecurityHardeningManager(saltManager, vaultPath)

		// Configure 2FA settings
		twoFactorConfig := &system.TwoFactorAuthConfig{
			Enabled:       true,
			Method:        method,
			RequiredUsers: users,
			EnforceSSH:    enforceSSH,
			EnforceSudo:   enforceSudo,
			BackupCodes:   true,
			TOTPSettings: system.TOTPConfig{
				Issuer:     "Eos Security",
				WindowSize: 3,
				SecretBits: 160,
				RateLimit:  3,
			},
		}

		// Apply 2FA configuration
		if err := securityManager.SetupTwoFactorAuthentication(rc, target, twoFactorConfig); err != nil {
			return cerr.Wrap(err, "two-factor authentication setup failed")
		}

		logger.Info("Two-factor authentication setup completed successfully")

		return nil
	}),
}

func init() {
	// Add system security hardening command
	systemUpdateCmd.Flags().String("profile", "baseline", "Security profile: baseline, intermediate, advanced, compliance")
	systemUpdateCmd.Flags().String("salt-api", "https://localhost:8000", "Salt API URL")
	systemUpdateCmd.Flags().String("vault-path", "secret/eos", "Vault base path for secrets")
	systemUpdateCmd.Flags().Bool("dry-run", false, "Perform assessment only without applying changes")

	// Add 2FA setup command
	twoFactorCmd.Flags().String("method", "totp", "2FA method: totp, u2f, fido2")
	twoFactorCmd.Flags().StringSlice("users", []string{}, "Users to enable 2FA for")
	twoFactorCmd.Flags().String("salt-api", "https://localhost:8000", "Salt API URL")
	twoFactorCmd.Flags().String("vault-path", "secret/eos", "Vault base path for secrets")
	twoFactorCmd.Flags().Bool("enforce-ssh", false, "Enforce 2FA for SSH authentication")
	twoFactorCmd.Flags().Bool("enforce-sudo", false, "Enforce 2FA for sudo commands")

	UpdateCmd.AddCommand(systemUpdateCmd)
	UpdateCmd.AddCommand(twoFactorCmd)
}

var manageServicesCmd = &cobra.Command{
	Use:   "services [target]",
	Short: "Manage system services via SaltStack",
	Long: `Manage system services on target minions using SaltStack.

This command follows the assessment→intervention→evaluation model:
1. Assessment: Check current service states
2. Intervention: Apply desired service configurations
3. Evaluation: Verify service state changes

Examples:
  eos manage services "*" --config services.json
  eos manage services "web-*" --service nginx --state running --enable
  eos manage services "db-servers" --service postgresql --state stopped`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		if len(args) == 0 {
			return cerr.New("target minions must be specified")
		}

		target := args[0]
		configFile, _ := cmd.Flags().GetString("config")
		serviceName, _ := cmd.Flags().GetString("service")
		serviceState, _ := cmd.Flags().GetString("state")
		enable, _ := cmd.Flags().GetBool("enable")
		saltAPI, _ := cmd.Flags().GetString("salt-api")
		vaultPath, _ := cmd.Flags().GetString("vault-path")

		logger.Info("Managing services via SaltStack",
			zap.String("target", target),
			zap.String("service", serviceName),
			zap.String("state", serviceState))

		// Initialize SaltStack manager
		saltConfig := &system.SaltStackConfig{
			APIURL:    saltAPI,
			VaultPath: vaultPath + "/salt",
			Timeout:   5 * time.Minute,
		}

		saltManager, err := system.NewSaltStackManager(rc, saltConfig)
		if err != nil {
			return cerr.Wrap(err, "failed to initialize SaltStack manager")
		}

		var services []system.ServiceConfig

		if configFile != "" {
			// Load services from configuration file
			services, err = config_loader.LoadServicesFromFile(rc, configFile)
			if err != nil {
				return cerr.Wrap(err, "failed to load services configuration")
			}
		} else if serviceName != "" {
			// Single service configuration from flags
			services = []system.ServiceConfig{
				{
					Name:   serviceName,
					State:  serviceState,
					Enable: enable,
					Reload: true,
				},
			}
		} else {
			return cerr.New("either --config file or --service must be specified")
		}

		// Manage services
		if err := saltManager.ManageServices(rc, target, services); err != nil {
			return cerr.Wrap(err, "service management failed")
		}

		logger.Info("Service management completed successfully",
			zap.Int("services_managed", len(services)))

		return nil
	}),
}

var manageCronCmd = &cobra.Command{
	Use:   "cron [target]",
	Short: "Manage cron jobs via SaltStack",
	Long: `Manage cron jobs on target minions using SaltStack.

Examples:
  eos manage cron "*" --config cron.json
  eos manage cron "servers" --job backup --command "/usr/bin/backup.sh" --minute "0" --hour "2"
  eos manage cron "web-*" --job cleanup --command "/usr/bin/cleanup.sh" --minute "*/15" --user www-data`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		if len(args) == 0 {
			return cerr.New("target minions must be specified")
		}

		target := args[0]
		configFile, _ := cmd.Flags().GetString("config")
		jobName, _ := cmd.Flags().GetString("job")
		command, _ := cmd.Flags().GetString("command")
		minute, _ := cmd.Flags().GetString("minute")
		hour, _ := cmd.Flags().GetString("hour")
		user, _ := cmd.Flags().GetString("user")
		present, _ := cmd.Flags().GetBool("present")
		saltAPI, _ := cmd.Flags().GetString("salt-api")
		vaultPath, _ := cmd.Flags().GetString("vault-path")

		logger.Info("Managing cron jobs via SaltStack",
			zap.String("target", target),
			zap.String("job", jobName))

		// Initialize SaltStack manager
		saltConfig := &system.SaltStackConfig{
			APIURL:    saltAPI,
			VaultPath: vaultPath + "/salt",
			Timeout:   5 * time.Minute,
		}

		saltManager, err := system.NewSaltStackManager(rc, saltConfig)
		if err != nil {
			return cerr.Wrap(err, "failed to initialize SaltStack manager")
		}

		var cronJobs []system.CronJobConfig

		if configFile != "" {
			// Load cron jobs from configuration file
			cronJobs, err = config_loader.LoadCronJobsFromFile(rc, configFile)
			if err != nil {
				return cerr.Wrap(err, "failed to load cron jobs configuration")
			}
		} else if jobName != "" {
			// Single cron job configuration from flags
			cronJobs = []system.CronJobConfig{
				{
					Name:       jobName,
					Command:    command,
					User:       user,
					Minute:     minute,
					Hour:       hour,
					Day:        "*",
					Month:      "*",
					Weekday:    "*",
					Identifier: jobName,
					Present:    present,
				},
			}
		} else {
			return cerr.New("either --config file or --job must be specified")
		}

		// Manage cron jobs
		if err := saltManager.ManageCronJobs(rc, target, cronJobs); err != nil {
			return cerr.Wrap(err, "cron job management failed")
		}

		logger.Info("Cron job management completed successfully",
			zap.Int("jobs_managed", len(cronJobs)))

		return nil
	}),
}

var manageUsersCmd = &cobra.Command{
	Use:   "users [target]",
	Short: "Manage user accounts via SaltStack",
	Long: `Manage user accounts on target minions using SaltStack.

This replaces traditional user management scripts with Salt-based automation
following the assessment→intervention→evaluation pattern.

Examples:
  eos manage users "*" --config users.json
  eos manage users "servers" --user alice --groups sudo,admin --shell /bin/bash
  eos manage users "web-*" --user www-data --home /var/www --groups www-data`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		if len(args) == 0 {
			return cerr.New("target minions must be specified")
		}

		target := args[0]
		configFile, _ := cmd.Flags().GetString("config")
		username, _ := cmd.Flags().GetString("user")
		groups, _ := cmd.Flags().GetStringSlice("groups")
		shell, _ := cmd.Flags().GetString("shell")
		home, _ := cmd.Flags().GetString("home")
		present, _ := cmd.Flags().GetBool("present")
		saltAPI, _ := cmd.Flags().GetString("salt-api")
		vaultPath, _ := cmd.Flags().GetString("vault-path")

		logger.Info("Managing users via SaltStack",
			zap.String("target", target),
			zap.String("user", username))

		// Initialize SaltStack manager
		saltConfig := &system.SaltStackConfig{
			APIURL:    saltAPI,
			VaultPath: vaultPath + "/salt",
			Timeout:   5 * time.Minute,
		}

		saltManager, err := system.NewSaltStackManager(rc, saltConfig)
		if err != nil {
			return cerr.Wrap(err, "failed to initialize SaltStack manager")
		}

		var users []system.UserConfig

		if configFile != "" {
			// Load users from configuration file
			users, err = config_loader.LoadUsersFromFile(rc, configFile)
			if err != nil {
				return cerr.Wrap(err, "failed to load users configuration")
			}
		} else if username != "" {
			// Single user configuration from flags
			users = []system.UserConfig{
				{
					Name:    username,
					Groups:  groups,
					Shell:   shell,
					Home:    home,
					Present: present,
				},
			}
		} else {
			return cerr.New("either --config file or --user must be specified")
		}

		// Manage users
		if err := saltManager.ManageUsers(rc, target, users); err != nil {
			return cerr.Wrap(err, "user management failed")
		}

		logger.Info("User management completed successfully",
			zap.Int("users_managed", len(users)))

		return nil
	}),
}

var manageStateCmd = &cobra.Command{
	Use:   "state [target]",
	Short: "Apply comprehensive system state via SaltStack",
	Long: `Apply comprehensive system state including services, users, cron jobs, and packages.

This command provides holistic system management by applying multiple 
configuration types in a coordinated manner.

Examples:
  eos manage state "*" --config system-state.json
  eos manage state "prod-servers" --config production.json --dry-run`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		if len(args) == 0 {
			return cerr.New("target minions must be specified")
		}

		target := args[0]
		configFile, _ := cmd.Flags().GetString("config")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		saltAPI, _ := cmd.Flags().GetString("salt-api")
		vaultPath, _ := cmd.Flags().GetString("vault-path")

		if configFile == "" {
			return cerr.New("--config file must be specified")
		}

		logger.Info("Applying system state via SaltStack",
			zap.String("target", target),
			zap.String("config_file", configFile),
			zap.Bool("dry_run", dryRun))

		// Initialize SaltStack manager
		saltConfig := &system.SaltStackConfig{
			APIURL:    saltAPI,
			VaultPath: vaultPath + "/salt",
			Timeout:   10 * time.Minute,
		}

		saltManager, err := system.NewSaltStackManager(rc, saltConfig)
		if err != nil {
			return cerr.Wrap(err, "failed to initialize SaltStack manager")
		}

		// Load system state configuration
		systemState, err := config_loader.LoadSystemStateFromFile(rc, configFile)
		if err != nil {
			return cerr.Wrap(err, "failed to load system state configuration")
		}

		if dryRun {
			logger.Info("Dry run mode - assessing current state only")
			// In a real implementation, this would show what changes would be made
			if err := system_display.DisplaySystemState(rc, systemState); err != nil {
				logger.Warn("Failed to display system state", zap.Error(err))
			}
			return nil
		}

		// Apply system state
		convertedState := config_loader.ConvertToSystemState(systemState)
		result, err := saltManager.ApplySystemState(rc, target, convertedState)
		if err != nil {
			return cerr.Wrap(err, "system state application failed")
		}

		// Display results
		if err := system_display.DisplayStateApplication(rc, result); err != nil {
			logger.Warn("Failed to display state application", zap.Error(err))
		}

		return nil
	}),
}

func init() {
	// Services management command
	manageServicesCmd.Flags().String("config", "", "Configuration file for services")
	manageServicesCmd.Flags().String("service", "", "Single service name to manage")
	manageServicesCmd.Flags().String("state", "running", "Service state: running, stopped")
	manageServicesCmd.Flags().Bool("enable", true, "Enable service on boot")
	manageServicesCmd.Flags().String("salt-api", "https://localhost:8000", "Salt API URL")
	manageServicesCmd.Flags().String("vault-path", "secret/eos", "Vault base path for secrets")

	// Cron management command
	manageCronCmd.Flags().String("config", "", "Configuration file for cron jobs")
	manageCronCmd.Flags().String("job", "", "Cron job name")
	manageCronCmd.Flags().String("command", "", "Command to execute")
	manageCronCmd.Flags().String("minute", "*", "Minute field (0-59)")
	manageCronCmd.Flags().String("hour", "*", "Hour field (0-23)")
	manageCronCmd.Flags().String("user", "root", "User to run the cron job as")
	manageCronCmd.Flags().Bool("present", true, "Whether the cron job should be present")
	manageCronCmd.Flags().String("salt-api", "https://localhost:8000", "Salt API URL")
	manageCronCmd.Flags().String("vault-path", "secret/eos", "Vault base path for secrets")

	// Users management command
	manageUsersCmd.Flags().String("config", "", "Configuration file for users")
	manageUsersCmd.Flags().String("user", "", "Username to manage")
	manageUsersCmd.Flags().StringSlice("groups", []string{}, "Groups for the user")
	manageUsersCmd.Flags().String("shell", "/bin/bash", "User's shell")
	manageUsersCmd.Flags().String("home", "", "User's home directory")
	manageUsersCmd.Flags().Bool("present", true, "Whether the user should be present")
	manageUsersCmd.Flags().String("salt-api", "https://localhost:8000", "Salt API URL")
	manageUsersCmd.Flags().String("vault-path", "secret/eos", "Vault base path for secrets")

	// System state management command
	manageStateCmd.Flags().String("config", "", "System state configuration file")
	manageStateCmd.Flags().Bool("dry-run", false, "Show what would be done without applying changes")
	manageStateCmd.Flags().String("salt-api", "https://localhost:8000", "Salt API URL")
	manageStateCmd.Flags().String("vault-path", "secret/eos", "Vault base path for secrets")

	UpdateCmd.AddCommand(manageServicesCmd)
	UpdateCmd.AddCommand(manageCronCmd)
	UpdateCmd.AddCommand(manageUsersCmd)
	UpdateCmd.AddCommand(manageStateCmd)
}

// Cleanup functionality has been moved to cmd/update/cleanup.go
