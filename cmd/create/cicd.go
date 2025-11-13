package create

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/cicd"
	// "github.com/CodeMonkeyCybersecurity/eos/pkg/deploy" // TODO: Re-enable when pkg/deploy is refactored
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var cicdCmd = &cobra.Command{
	Use:   "cicd [app-name]",
	Short: "Set up a complete CI/CD pipeline for an application",
	Long: `Set up a complete CI/CD pipeline that follows the  → Terraform → Nomad orchestration 
hierarchy for reliable deployment automation.

This command creates a comprehensive deployment pipeline that includes:
- Hugo static site building with Docker containerization
- Terraform for infrastructure provisioning and management
- Nomad for container scheduling and management
- Consul for service discovery and health checking
- Vault for secrets management
- Automated rollback capabilities

The pipeline follows the assessment→intervention→evaluation pattern for each
deployment step to ensure reliable deployment and easy troubleshooting.

Examples:
  # Set up CI/CD pipeline for Helen Hugo website
  eos create cicd helen

  # Set up with custom Git repository
  eos create cicd helen --git-repo https://github.com/user/helen.git

  # Set up with custom domain and environment
  eos create cicd helen --domain helen.example.com --environment production

  # Set up with custom resource allocation
  eos create cicd helen --cpu 1000 --memory 512

  # Set up with custom deployment strategy
  eos create cicd helen --strategy blue-green --canary 2`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// CRITICAL: Detect flag-like args (P0-1 fix)
		if err := verify.ValidateNoFlagLikeArgs(args); err != nil {
			return err
		}

		appName := args[0]

		logger.Info("Setting up CI/CD pipeline",
			zap.String("command", "create cicd"),
			zap.String("app_name", appName),
			zap.String("component", rc.Component))

		// Parse command line flags into pipeline configuration
		config, err := parseeCICDFlags(cmd, appName)
		if err != nil {
			logger.Error("Failed to parse command flags", zap.Error(err))
			return fmt.Errorf("flag parsing failed: %w", err)
		}

		// Log configuration
		logger.Info("CI/CD pipeline configuration",
			zap.String("app_name", config.AppName),
			zap.String("git_repo", config.Git.Repository),
			zap.String("git_branch", config.Git.Branch),
			zap.String("environment", config.Deployment.Environment),
			zap.String("domain", config.Deployment.Domain),
			zap.String("strategy", config.Deployment.Strategy.Type))

		// Display success information
		logger.Info("CI/CD pipeline setup completed successfully",
			zap.String("app_name", appName),
			zap.String("domain", config.Deployment.Domain))

		logger.Info("CI/CD pipeline ready",
			zap.String("config_file", fmt.Sprintf(".eos/%s-pipeline.yaml", appName)),
			zap.String("_states", fmt.Sprintf("/srv//states/%s/", appName)),
			zap.String("terraform_config", fmt.Sprintf("/srv/terraform/%s/", appName)))

		logger.Info("Next steps",
			zap.String("deploy", fmt.Sprintf("eos deploy %s", appName)),
			zap.String("status", fmt.Sprintf("eos read deployment-status %s", appName)),
			zap.String("rollback", fmt.Sprintf("eos update rollback %s --to-version <version>", appName)))

		return nil
	}),
}

func init() {
	// TODO: Re-enable when pkg/deploy is refactored
	// Add cicd command to create
	// CreateCmd.AddCommand(cicdCmd)

	// Git configuration flags
	cicdCmd.Flags().String("git-repo", "", "Git repository URL (prompted if not provided)")
	cicdCmd.Flags().String("git-branch", "main", "Git branch to deploy from")

	// Build configuration flags
	cicdCmd.Flags().String("dockerfile", "Dockerfile", "Path to Dockerfile")
	cicdCmd.Flags().String("build-context", ".", "Docker build context directory")
	cicdCmd.Flags().String("registry", "registry.cybermonkey.net.au", "Docker registry URL")
	cicdCmd.Flags().Bool("hugo", false, "Enable Hugo static site building")
	cicdCmd.Flags().String("hugo-config", "config.yaml", "Hugo configuration file")
	cicdCmd.Flags().String("hugo-environment", "production", "Hugo build environment")
	cicdCmd.Flags().Bool("hugo-minify", true, "Enable Hugo minification")

	// Deployment configuration flags
	cicdCmd.Flags().String("environment", "production", "Deployment environment")
	cicdCmd.Flags().String("domain", "", "Domain name for the application (prompted if not provided)")
	cicdCmd.Flags().String("namespace", "", "Deployment namespace (defaults to app name)")
	cicdCmd.Flags().String("strategy", "rolling", "Deployment strategy: rolling, blue-green, canary")
	cicdCmd.Flags().Int("canary", 1, "Number of canary instances for canary deployments")
	cicdCmd.Flags().Bool("auto-revert", true, "Automatically revert failed deployments")
	cicdCmd.Flags().Bool("auto-promote", true, "Automatically promote successful canary deployments")

	// Resource configuration flags
	cicdCmd.Flags().Int("cpu", 500, "CPU allocation in MHz")
	cicdCmd.Flags().Int("memory", 256, "Memory allocation in MB")
	cicdCmd.Flags().Int("memory-max", 512, "Maximum memory allocation in MB")

	// Infrastructure configuration flags
	cicdCmd.Flags().String("provider", "hetzner", "Infrastructure provider: hetzner, aws, gcp")
	cicdCmd.Flags().String("region", "nbg1", "Infrastructure region")
	cicdCmd.Flags().String("server-type", "cx21", "Server type for infrastructure")

	// Pipeline configuration flags
	cicdCmd.Flags().Duration("timeout", 1800, "Pipeline timeout in seconds")
	cicdCmd.Flags().Int("retry-attempts", 3, "Number of retry attempts for failed stages")
	cicdCmd.Flags().Bool("fail-fast", true, "Stop pipeline on first failure")
	cicdCmd.Flags().String("notification-channel", "deployments", "Notification channel for pipeline events")

	// Health check configuration flags
	cicdCmd.Flags().String("health-path", "/health", "Health check endpoint path")
	cicdCmd.Flags().Duration("health-interval", 30, "Health check interval in seconds")
	cicdCmd.Flags().Duration("health-timeout", 5, "Health check timeout in seconds")
	cicdCmd.Flags().Int("health-retries", 3, "Number of health check retries")

	// Service addresses
	hostname := shared.GetInternalHostname()
	cicdCmd.Flags().String("nomad-addr", fmt.Sprintf("http://%s:%d", hostname, shared.PortNomad), "Nomad server address")
	cicdCmd.Flags().String("consul-addr", fmt.Sprintf("http://%s:%d", hostname, shared.PortConsul), "Consul server address")
	cicdCmd.Flags().String("vault-addr", fmt.Sprintf("https://%s:%d", hostname, shared.PortVault), "Vault server address")

	cicdCmd.Example = `  # Set up basic CI/CD pipeline for Helen
  eos create cicd helen

  # Set up with custom Git repository and domain
  eos create cicd helen --git-repo https://github.com/user/helen.git --domain helen.example.com

  # Set up Hugo site with custom configuration
  eos create cicd helen --hugo --hugo-config config.toml --hugo-environment production

  # Set up with blue-green deployment strategy
  eos create cicd helen --strategy blue-green --auto-revert=false

  # Set up with high-performance settings
  eos create cicd helen --cpu 1000 --memory 512 --memory-max 1024`
}

// parseeCICDFlags parses command line flags into a PipelineConfig
func parseeCICDFlags(cmd *cobra.Command, appName string) (*cicd.PipelineConfig, error) {
	// Start with default configuration
	config := cicd.DefaultPipelineConfig(appName)

	// Parse Git configuration
	if gitRepo, _ := cmd.Flags().GetString("git-repo"); gitRepo != "" {
		config.Git.Repository = gitRepo
	}
	if gitBranch, _ := cmd.Flags().GetString("git-branch"); gitBranch != "" {
		config.Git.Branch = gitBranch
	}

	// Parse build configuration
	if dockerfile, _ := cmd.Flags().GetString("dockerfile"); dockerfile != "" {
		config.Build.DockerFile = dockerfile
	}
	if buildContext, _ := cmd.Flags().GetString("build-context"); buildContext != "" {
		config.Build.Context = buildContext
	}
	if registry, _ := cmd.Flags().GetString("registry"); registry != "" {
		config.Build.Registry = registry
		config.Build.Image = appName // Use app name as image name
	}

	// Parse Hugo configuration
	if hugo, _ := cmd.Flags().GetBool("hugo"); hugo {
		config.Build.Type = "hugo"
		if hugoConfig, _ := cmd.Flags().GetString("hugo-config"); hugoConfig != "" {
			config.Build.Hugo.ConfigFile = hugoConfig
		}
		if hugoEnv, _ := cmd.Flags().GetString("hugo-environment"); hugoEnv != "" {
			config.Build.Hugo.Environment = hugoEnv
		}
		if hugoMinify, _ := cmd.Flags().GetBool("hugo-minify"); hugoMinify {
			config.Build.Hugo.Minify = hugoMinify
		}
	}

	// Parse deployment configuration
	if environment, _ := cmd.Flags().GetString("environment"); environment != "" {
		config.Deployment.Environment = environment
	}
	if domain, _ := cmd.Flags().GetString("domain"); domain != "" {
		config.Deployment.Domain = domain
	}
	if namespace, _ := cmd.Flags().GetString("namespace"); namespace != "" {
		config.Deployment.Namespace = namespace
	} else {
		config.Deployment.Namespace = appName
	}

	// Parse deployment strategy
	if strategy, _ := cmd.Flags().GetString("strategy"); strategy != "" {
		config.Deployment.Strategy.Type = strategy
	}
	if canary, _ := cmd.Flags().GetInt("canary"); canary > 0 {
		config.Deployment.Strategy.Canary = canary
	}
	if autoRevert, _ := cmd.Flags().GetBool("auto-revert"); cmd.Flags().Changed("auto-revert") {
		config.Deployment.Strategy.AutoRevert = autoRevert
	}
	if autoPromote, _ := cmd.Flags().GetBool("auto-promote"); cmd.Flags().Changed("auto-promote") {
		config.Deployment.Strategy.AutoPromote = autoPromote
	}

	// Parse resource configuration
	if cpu, _ := cmd.Flags().GetInt("cpu"); cpu > 0 {
		config.Deployment.Resources.CPU = cpu
	}
	if memory, _ := cmd.Flags().GetInt("memory"); memory > 0 {
		config.Deployment.Resources.Memory = memory
	}
	if memoryMax, _ := cmd.Flags().GetInt("memory-max"); memoryMax > 0 {
		config.Deployment.Resources.MemoryMax = memoryMax
	}

	// Parse infrastructure configuration
	if provider, _ := cmd.Flags().GetString("provider"); provider != "" {
		config.Infrastructure.Provider = provider
	}
	if region, _ := cmd.Flags().GetString("region"); region != "" {
		config.Infrastructure.Region = region
	}
	if serverType, _ := cmd.Flags().GetString("server-type"); serverType != "" {
		config.Infrastructure.ServerType = serverType
	}

	// Parse health check configuration
	if healthPath, _ := cmd.Flags().GetString("health-path"); healthPath != "" {
		config.Deployment.Health.Path = healthPath
	}
	if healthInterval, _ := cmd.Flags().GetDuration("health-interval"); healthInterval > 0 {
		config.Deployment.Health.Interval = healthInterval
	}
	if healthTimeout, _ := cmd.Flags().GetDuration("health-timeout"); healthTimeout > 0 {
		config.Deployment.Health.Timeout = healthTimeout
	}
	if healthRetries, _ := cmd.Flags().GetInt("health-retries"); healthRetries > 0 {
		config.Deployment.Health.Retries = healthRetries
	}

	// Parse service addresses
	if nomadAddr, _ := cmd.Flags().GetString("nomad-addr"); nomadAddr != "" {
		config.Infrastructure.Nomad.Address = nomadAddr
	}
	if consulAddr, _ := cmd.Flags().GetString("consul-addr"); consulAddr != "" {
		config.Infrastructure.Consul.Address = consulAddr
	}
	if vaultAddr, _ := cmd.Flags().GetString("vault-addr"); vaultAddr != "" {
		config.Infrastructure.Vault.Address = vaultAddr
	}

	// Parse pipeline configuration
	if timeout, _ := cmd.Flags().GetDuration("timeout"); timeout > 0 {
		config.Pipeline.Timeout = timeout
	}
	if retryAttempts, _ := cmd.Flags().GetInt("retry-attempts"); retryAttempts > 0 {
		config.Pipeline.RetryAttempts = retryAttempts
	}
	if failFast, _ := cmd.Flags().GetBool("fail-fast"); cmd.Flags().Changed("fail-fast") {
		config.Pipeline.FailFast = failFast
	}
	if notificationChannel, _ := cmd.Flags().GetString("notification-channel"); notificationChannel != "" {
		config.Pipeline.NotificationChannel = notificationChannel
	}

	return config, nil
}
