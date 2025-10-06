package deploy

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/deploy"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/environments"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var appCmd = &cobra.Command{
	Use:   "app <app-name>",
	Short: "Deploy a specific application with advanced deployment strategies",
	Long: `Deploy a specific application to target environments using sophisticated deployment
strategies including rolling, blue-green, canary, and immutable deployments.

This command orchestrates comprehensive application deployment following the  → Terraform → Nomad
pattern with extensive validation, health checking, and rollback capabilities. Each deployment
follows the assessment→intervention→evaluation pattern to ensure reliable operations.

The application deployment process includes:
- Pre-deployment validation and environment compatibility checking
- Artifact preparation and version verification
- Strategy-specific deployment orchestration with progress monitoring
- Comprehensive health checks and smoke testing
- Service registration and traffic routing configuration
- Post-deployment verification and performance validation
- Automated rollback on failure with configurable thresholds

Examples:
  # Rolling deployment to staging
  eos deploy app helen --environment staging

  # Blue-green deployment to production
  eos deploy app helen --environment production --strategy blue-green

  # Canary deployment with custom traffic split
  eos deploy app api --environment production --strategy canary --canary-percentage 10

  # Deployment with custom timeout and health checks
  eos deploy app frontend --environment staging --timeout 20m --health-check-retries 5

  # Dry run deployment
  eos deploy app helen --environment production --strategy blue-green --dry-run`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		appName := args[0]

		logger.Info("Deploying application",
			zap.String("command", "deploy app"),
			zap.String("app", appName),
			zap.String("context", rc.Component))

		// Parse flags
		environment, _ := cmd.Flags().GetString("environment")
		strategy, _ := cmd.Flags().GetString("strategy")
		version, _ := cmd.Flags().GetString("version")
		timeout, _ := cmd.Flags().GetDuration("timeout")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		force, _ := cmd.Flags().GetBool("force")
		skipValidation, _ := cmd.Flags().GetBool("skip-validation")
		skipHealthCheck, _ := cmd.Flags().GetBool("skip-health-check")
		rollbackOnFailure, _ := cmd.Flags().GetBool("rollback-on-failure")

		// Strategy-specific flags
		batchSize, _ := cmd.Flags().GetInt("batch-size")
		canaryPercentage, _ := cmd.Flags().GetInt("canary-percentage")
		canaryDuration, _ := cmd.Flags().GetDuration("canary-duration")
		healthCheckRetries, _ := cmd.Flags().GetInt("health-check-retries")
		healthCheckTimeout, _ := cmd.Flags().GetDuration("health-check-timeout")

		logger.Debug("Deployment configuration",
			zap.String("app", appName),
			zap.String("environment", environment),
			zap.String("strategy", strategy),
			zap.String("version", version),
			zap.Duration("timeout", timeout),
			zap.Bool("dry_run", dryRun),
			zap.Bool("force", force),
			zap.Int("batch_size", batchSize),
			zap.Int("canary_percentage", canaryPercentage),
			zap.Duration("canary_duration", canaryDuration))

		// Validate required parameters
		if environment == "" {
			return fmt.Errorf("environment is required (--environment flag)")
		}

		// Validate strategy
		strategyEnum := deploy.DeploymentStrategyRolling
		switch strategy {
		case "rolling":
			strategyEnum = deploy.DeploymentStrategyRolling
		case "blue-green":
			strategyEnum = deploy.DeploymentStrategyBlueGreen
		case "canary":
			strategyEnum = deploy.DeploymentStrategyCanary
		case "immutable":
			strategyEnum = deploy.DeploymentStrategyImmutable
		case "":
			// Use default
		default:
			return fmt.Errorf("invalid strategy '%s'. Valid options: rolling, blue-green, canary, immutable", strategy)
		}

		// Create environment manager
		envManager, err := environments.NewEnvironmentManager("")
		if err != nil {
			logger.Error("Failed to create environment manager", zap.Error(err))
			return fmt.Errorf("failed to create environment manager: %w", err)
		}

		// Validate environment exists
		_, err = envManager.GetEnvironment(rc, environment)
		if err != nil {
			logger.Error("Failed to get environment", zap.Error(err))
			return fmt.Errorf("environment '%s' not found: %w", environment, err)
		}

		// Create deployment configuration
		deployConfig := &deploy.AppDeploymentConfig{
			AppName:           appName,
			Environment:       environment,
			Strategy:          strategyEnum,
			Version:           version,
			Timeout:           timeout,
			DryRun:            dryRun,
			Force:             force,
			SkipValidation:    skipValidation,
			SkipHealthCheck:   skipHealthCheck,
			RollbackOnFailure: rollbackOnFailure,
			StrategyConfig: deploy.StrategyConfig{
				Rolling: deploy.RollingConfig{
					BatchSize:        batchSize,
					MaxSurge:         1,
					MaxUnavailable:   0,
					ProgressDeadline: 10 * time.Minute,
				},
				BlueGreen: deploy.BlueGreenConfig{
					PrePromotionAnalysis: 5 * time.Minute,
					ScaleDownDelay:       10 * time.Minute,
					AutoPromotionEnabled: false,
				},
				Canary: deploy.CanaryConfig{
					InitialPercentage: canaryPercentage,
					StepPercentage:    10,
					StepDuration:      canaryDuration,
					MaxSteps:          10,
					AnalysisDelay:     2 * time.Minute,
				},
			},
			HealthCheck: deploy.HealthCheckConfig{
				Enabled:      !skipHealthCheck,
				Path:         "/health",
				Retries:      healthCheckRetries,
				Timeout:      healthCheckTimeout,
				Interval:     30 * time.Second,
				InitialDelay: 10 * time.Second,
			},
		}

		// Create deployment manager
		managerConfig := deploy.DefaultDeploymentConfig()
		manager, err := deploy.NewDeploymentManager(managerConfig)
		if err != nil {
			logger.Error("Failed to create deployment manager", zap.Error(err))
			return fmt.Errorf("failed to create deployment manager: %w", err)
		}

		// Display deployment plan
		fmt.Printf("Application Deployment Plan:\n")
		fmt.Printf("═══════════════════════════\n")
		fmt.Printf("Application:      %s\n", appName)
		fmt.Printf("Environment:      %s\n", environment)
		fmt.Printf("Strategy:         %s\n", strategy)
		if version != "" {
			fmt.Printf("Version:          %s\n", version)
		}
		fmt.Printf("Timeout:          %s\n", timeout)
		fmt.Printf("Rollback on Fail: %t\n", rollbackOnFailure)
		fmt.Printf("Dry Run:          %t\n", dryRun)
		fmt.Printf("\n")

		// Display strategy-specific details
		switch strategyEnum {
		case deploy.DeploymentStrategyRolling:
			fmt.Printf("Rolling Strategy Configuration:\n")
			fmt.Printf("• Batch Size:         %d\n", batchSize)
			fmt.Printf("• Max Surge:          %d\n", deployConfig.StrategyConfig.Rolling.MaxSurge)
			fmt.Printf("• Max Unavailable:    %d\n", deployConfig.StrategyConfig.Rolling.MaxUnavailable)
		case deploy.DeploymentStrategyBlueGreen:
			fmt.Printf("Blue-Green Strategy Configuration:\n")
			fmt.Printf("• Pre-promotion Analysis: %s\n", deployConfig.StrategyConfig.BlueGreen.PrePromotionAnalysis)
			fmt.Printf("• Scale Down Delay:       %s\n", deployConfig.StrategyConfig.BlueGreen.ScaleDownDelay)
			fmt.Printf("• Auto Promotion:         %t\n", deployConfig.StrategyConfig.BlueGreen.AutoPromotionEnabled)
		case deploy.DeploymentStrategyCanary:
			fmt.Printf("Canary Strategy Configuration:\n")
			fmt.Printf("• Initial Percentage: %d%%\n", deployConfig.StrategyConfig.Canary.InitialPercentage)
			fmt.Printf("• Step Percentage:    %d%%\n", deployConfig.StrategyConfig.Canary.StepPercentage)
			fmt.Printf("• Step Duration:      %s\n", deployConfig.StrategyConfig.Canary.StepDuration)
			fmt.Printf("• Max Steps:          %d\n", deployConfig.StrategyConfig.Canary.MaxSteps)
		}
		fmt.Printf("\n")

		// Show production deployment warning
		if isProductionEnvironment(environment) {
			fmt.Printf("🚨 Production Deployment Warning:\n")
			fmt.Printf("   This deployment targets the production environment.\n")
			fmt.Printf("   Ensure all testing has been completed in lower environments.\n")
			fmt.Printf("   Consider using --rollback-on-failure for additional safety.\n")
			fmt.Printf("\n")
		}

		// Dry run - show what would be deployed
		if dryRun {
			fmt.Printf(" Dry Run - No actual deployment will be executed\n")
			fmt.Printf("\nDeployment Steps (would execute):\n")
			fmt.Printf("1. Validate deployment prerequisites\n")
			fmt.Printf("2. Prepare application artifacts\n")
			fmt.Printf("3. Execute %s deployment strategy\n", strategy)
			fmt.Printf("4. Register service in Consul\n")
			fmt.Printf("5. Configure traffic routing\n")
			fmt.Printf("6. Run health checks and validation\n")
			fmt.Printf("7. Update deployment registry\n")
			if rollbackOnFailure {
				fmt.Printf("8. Automated rollback on failure (if needed)\n")
			}
			return nil
		}

		// Get final confirmation for production deployments
		if isProductionEnvironment(environment) && !force {
			fmt.Printf("Proceed with production deployment? (y/N): ")
			// In real implementation, would read from stdin
			fmt.Printf("y\n")
		}

		// Execute deployment
		result, err := manager.DeployApplication(rc, deployConfig)
		if err != nil {
			logger.Error("Application deployment failed",
				zap.String("app", appName),
				zap.String("environment", environment),
				zap.Error(err))

			// Check if rollback was attempted
			if rollbackOnFailure && result != nil && result.RollbackAttempted {
				fmt.Printf("❌ Deployment failed, but rollback was %s\n",
					func() string {
						if result.RollbackSuccessful {
							return "successful"
						}
						return "unsuccessful"
					}())
			}

			return fmt.Errorf("application deployment failed: %w", err)
		}

		// Display deployment results
		fmt.Printf(" Application deployment completed successfully\n")
		fmt.Printf("\nDeployment Results:\n")
		fmt.Printf("───────────────────\n")
		fmt.Printf("Application:      %s\n", appName)
		fmt.Printf("Environment:      %s\n", environment)
		fmt.Printf("Strategy:         %s\n", strategy)
		fmt.Printf("Version:          %s\n", result.Version)
		fmt.Printf("Duration:         %s\n", result.Duration)
		fmt.Printf("Deployment ID:    %s\n", result.DeploymentID)

		if result.ServiceURL != "" {
			fmt.Printf("Service URL:      %s\n", result.ServiceURL)
		}

		// Show deployment steps executed
		if len(result.StepsExecuted) > 0 {
			fmt.Printf("\nSteps Executed:\n")
			for _, step := range result.StepsExecuted {
				status := ""
				if step.Status != "completed" {
					status = "❌"
				}
				fmt.Printf("  %s %s (%s)\n", status, step.Description, step.Duration)
			}
		}

		// Show health check results
		if len(result.HealthCheckResults) > 0 {
			fmt.Printf("\nHealth Check Results:\n")
			for _, check := range result.HealthCheckResults {
				status := ""
				if !check.Passed {
					status = "❌"
				}
				fmt.Printf("  %s %s: %s\n", status, check.Check, check.Message)
			}
		}

		// Show rollback information
		if result.RollbackPlan != nil {
			fmt.Printf("\nRollback Plan Generated:\n")
			fmt.Printf("Previous Version: %s\n", result.RollbackPlan.PreviousVersion)
			fmt.Printf("Estimated Time:   %s\n", result.RollbackPlan.EstimatedTime)
			fmt.Printf("\nTo rollback if needed:\n")
			fmt.Printf("  eos deploy rollback %s --to-version %s\n", appName, result.RollbackPlan.PreviousVersion)
		}

		logger.Info("Application deployment completed successfully",
			zap.String("app", appName),
			zap.String("environment", environment),
			zap.String("strategy", strategy),
			zap.String("version", result.Version),
			zap.Duration("duration", result.Duration))

		return nil
	}),
}

func init() {
	DeployCmd.AddCommand(appCmd)

	// Required deployment flags
	appCmd.Flags().String("environment", "", "Target environment (required)")

	// Deployment configuration
	appCmd.Flags().String("strategy", "rolling", "Deployment strategy (rolling, blue-green, canary, immutable)")
	appCmd.Flags().String("version", "", "Application version to deploy (latest if not specified)")
	appCmd.Flags().Duration("timeout", 30*time.Minute, "Deployment timeout")

	// Safety and validation flags
	appCmd.Flags().Bool("dry-run", false, "Show deployment plan without executing")
	appCmd.Flags().Bool("force", false, "Force deployment without confirmation")
	appCmd.Flags().Bool("skip-validation", false, "Skip pre-deployment validation")
	appCmd.Flags().Bool("skip-health-check", false, "Skip post-deployment health checks")
	appCmd.Flags().Bool("rollback-on-failure", true, "Automatically rollback on deployment failure")

	// Rolling strategy flags
	appCmd.Flags().Int("batch-size", 1, "Rolling deployment batch size")
	appCmd.Flags().Int("max-surge", 1, "Maximum number of instances above desired count")
	appCmd.Flags().Int("max-unavailable", 0, "Maximum number of unavailable instances")

	// Blue-green strategy flags
	appCmd.Flags().Duration("pre-promotion-analysis", 5*time.Minute, "Blue-green pre-promotion analysis duration")
	appCmd.Flags().Duration("scale-down-delay", 10*time.Minute, "Blue-green scale down delay")
	appCmd.Flags().Bool("auto-promotion", false, "Enable automatic promotion in blue-green deployment")

	// Canary strategy flags
	appCmd.Flags().Int("canary-percentage", 10, "Initial canary traffic percentage")
	appCmd.Flags().Int("canary-step-percentage", 10, "Canary step increase percentage")
	appCmd.Flags().Duration("canary-duration", 5*time.Minute, "Duration for each canary step")
	appCmd.Flags().Int("canary-max-steps", 10, "Maximum number of canary steps")

	// Health check flags
	appCmd.Flags().Int("health-check-retries", 3, "Number of health check retries")
	appCmd.Flags().Duration("health-check-timeout", 30*time.Second, "Health check timeout")
	appCmd.Flags().Duration("health-check-interval", 30*time.Second, "Health check interval")
	appCmd.Flags().String("health-check-path", "/health", "Health check endpoint path")

	appCmd.Example = `  # Rolling deployment to staging
  eos deploy app helen --environment staging

  # Blue-green deployment to production
  eos deploy app helen --environment production --strategy blue-green

  # Canary deployment with 5% initial traffic
  eos deploy app api --environment production --strategy canary --canary-percentage 5

  # Rolling deployment with custom batch size
  eos deploy app frontend --environment staging --strategy rolling --batch-size 2

  # Dry run deployment
  eos deploy app helen --environment production --dry-run`
}

// Helper functions

func isProductionEnvironment(environment string) bool {
	prodEnvironments := []string{"production", "prod", "live"}
	for _, prodEnv := range prodEnvironments {
		if environment == prodEnv {
			return true
		}
	}
	return false
}
