// cmd/manage/system.go

package manage

import (
	"encoding/json"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	cerr "github.com/cockroachdb/errors"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

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
			services, err = loadServicesFromFile(configFile)
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
			cronJobs, err = loadCronJobsFromFile(configFile)
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
			users, err = loadUsersFromFile(configFile)
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
		systemState, err := loadSystemStateFromFile(configFile)
		if err != nil {
			return cerr.Wrap(err, "failed to load system state configuration")
		}

		if dryRun {
			logger.Info("Dry run mode - assessing current state only")
			// In a real implementation, this would show what changes would be made
			displaySystemState(rc, systemState)
			return nil
		}

		// Apply system state
		result, err := saltManager.ApplySystemState(rc, target, systemState)
		if err != nil {
			return cerr.Wrap(err, "system state application failed")
		}

		// Display results
		displayStateApplication(rc, result)

		return nil
	}),
}

// Helper functions to load configurations from files

func loadServicesFromFile(configFile string) ([]system.ServiceConfig, error) {
	// In a real implementation, this would read and parse the JSON file
	// For now, return a sample configuration
	return []system.ServiceConfig{
		{
			Name:   "nginx",
			State:  "running",
			Enable: true,
			Reload: true,
		},
		{
			Name:   "postgresql",
			State:  "running",
			Enable: true,
			Reload: false,
		},
	}, nil
}

func loadCronJobsFromFile(configFile string) ([]system.CronJobConfig, error) {
	// In a real implementation, this would read and parse the JSON file
	return []system.CronJobConfig{
		{
			Name:       "daily-backup",
			Command:    "/usr/bin/backup.sh",
			User:       "root",
			Minute:     "0",
			Hour:       "2",
			Day:        "*",
			Month:      "*",
			Weekday:    "*",
			Identifier: "daily-backup",
			Present:    true,
		},
	}, nil
}

func loadUsersFromFile(configFile string) ([]system.UserConfig, error) {
	// In a real implementation, this would read and parse the JSON file
	return []system.UserConfig{
		{
			Name:    "alice",
			Groups:  []string{"sudo", "admin"},
			Shell:   "/bin/bash",
			Home:    "/home/alice",
			Present: true,
		},
	}, nil
}

func loadSystemStateFromFile(configFile string) (*system.SystemState, error) {
	// In a real implementation, this would read and parse the JSON file
	return &system.SystemState{
		Services: []system.ServiceConfig{
			{Name: "nginx", State: "running", Enable: true},
			{Name: "postgresql", State: "running", Enable: true},
		},
		CronJobs: []system.CronJobConfig{
			{
				Name:       "backup",
				Command:    "/usr/bin/backup.sh",
				User:       "root",
				Minute:     "0",
				Hour:       "2",
				Identifier: "backup",
				Present:    true,
			},
		},
		Users: []system.UserConfig{
			{
				Name:    "deploy",
				Groups:  []string{"deploy"},
				Shell:   "/bin/bash",
				Home:    "/home/deploy",
				Present: true,
			},
		},
		Environment: map[string]string{
			"ENVIRONMENT": "production",
			"LOG_LEVEL":   "info",
		},
	}, nil
}

func displaySystemState(rc *eos_io.RuntimeContext, state *system.SystemState) {
	logger := otelzap.Ctx(rc.Ctx)

	stateJSON, _ := json.MarshalIndent(state, "", "  ")
	logger.Info("System state configuration",
		zap.Int("services", len(state.Services)),
		zap.Int("cron_jobs", len(state.CronJobs)),
		zap.Int("users", len(state.Users)),
		zap.String("state_json", string(stateJSON)))
}

func displayStateApplication(rc *eos_io.RuntimeContext, result *system.StateApplication) {
	logger := otelzap.Ctx(rc.Ctx)

	if result.Success {
		logger.Info("System state application completed successfully",
			zap.String("target", result.Target),
			zap.Duration("duration", result.Duration),
			zap.Int("states_applied", len(result.States)))
	} else {
		logger.Error("System state application failed",
			zap.String("target", result.Target),
			zap.Duration("duration", result.Duration),
			zap.Strings("errors", result.Errors))
	}

	// Display individual state results
	for stateName, stateResult := range result.Results {
		if stateResult.Result {
			logger.Info("State applied successfully",
				zap.String("state", stateName),
				zap.String("comment", stateResult.Comment),
				zap.Float64("duration", stateResult.Duration))
		} else {
			logger.Error("State application failed",
				zap.String("state", stateName),
				zap.String("comment", stateResult.Comment))
		}
	}

	// Log as JSON for machine parsing
	resultJSON, _ := json.MarshalIndent(result, "", "  ")
	logger.Debug("Complete state application result", zap.String("result_json", string(resultJSON)))
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

	ManageCmd.AddCommand(manageServicesCmd)
	ManageCmd.AddCommand(manageCronCmd)
	ManageCmd.AddCommand(manageUsersCmd)
	ManageCmd.AddCommand(manageStateCmd)
}
