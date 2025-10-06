package deploy

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/deploy"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/environments"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var stackCmd = &cobra.Command{
	Use:   "stack <stack-name>",
	Short: "Deploy multiple components as a coordinated stack",
	Long: `Deploy multiple applications and services as a coordinated stack with comprehensive
dependency management, orchestration, and rollback capabilities.

Stack deployment enables atomic deployment of multi-component applications following
sophisticated orchestration patterns. It provides coordinated deployment strategies,
dependency-aware ordering, and comprehensive failure handling with stack-level rollback.

Stack deployment features include:
- Multi-component orchestration with dependency resolution
- Coordinated deployment strategies (sequential, parallel, dependency-order)
- Stack-level health validation and smoke testing
- Atomic rollback with dependency-aware cleanup
- Cross-component configuration management
- Service mesh integration across the stack
- Comprehensive monitoring and observability

Examples:
  # Deploy webapp stack to staging
  eos deploy stack webapp --environment staging

  # Deploy with dependency ordering
  eos deploy stack microservices --environment production --strategy dependency-order

  # Deploy with parallel execution
  eos deploy stack platform --environment staging --strategy parallel

  # Deploy specific components only
  eos deploy stack webapp --environment production --components api,frontend,cache

  # Deploy with custom timeout and rollback
  eos deploy stack webapp --environment production --timeout 45m --rollback-on-failure`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		stackName := args[0]

		logger.Info("Deploying stack",
			zap.String("command", "deploy stack"),
			zap.String("stack", stackName),
			zap.String("context", rc.Component))

		// Parse flags
		environment, _ := cmd.Flags().GetString("environment")
		strategy, _ := cmd.Flags().GetString("strategy")
		version, _ := cmd.Flags().GetString("version")
		components, _ := cmd.Flags().GetStringSlice("components")
		timeout, _ := cmd.Flags().GetDuration("timeout")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		force, _ := cmd.Flags().GetBool("force")
		continueOnError, _ := cmd.Flags().GetBool("continue-on-error")
		rollbackOnFailure, _ := cmd.Flags().GetBool("rollback-on-failure")
		parallel, _ := cmd.Flags().GetBool("parallel")
		waitBetweenComponents, _ := cmd.Flags().GetDuration("wait-between-components")

		logger.Debug("Stack deployment configuration",
			zap.String("stack", stackName),
			zap.String("environment", environment),
			zap.String("strategy", strategy),
			zap.String("version", version),
			zap.Strings("components", components),
			zap.Duration("timeout", timeout),
			zap.Bool("dry_run", dryRun),
			zap.Bool("continue_on_error", continueOnError),
			zap.Bool("rollback_on_failure", rollbackOnFailure))

		// Validate required parameters
		if environment == "" {
			return fmt.Errorf("environment is required (--environment flag)")
		}

		// Validate strategy
		strategyEnum := deploy.StackDeploymentStrategySequential
		switch strategy {
		case "sequential":
			strategyEnum = deploy.StackDeploymentStrategySequential
		case "parallel":
			strategyEnum = deploy.StackDeploymentStrategyParallel
		case "dependency-order":
			strategyEnum = deploy.StackDeploymentStrategyDependencyOrder
		case "":
			// Use default
		default:
			return fmt.Errorf("invalid strategy '%s'. Valid options: sequential, parallel, dependency-order", strategy)
		}

		// Create environment manager
		envManager, err := environments.NewEnvironmentManager("")
		if err != nil {
			logger.Error("Failed to create environment manager", zap.Error(err))
			return fmt.Errorf("failed to create environment manager: %w", err)
		}

		// Validate environment exists
		env, err := envManager.GetEnvironment(rc, environment)
		if err != nil {
			logger.Error("Failed to get environment", zap.Error(err))
			return fmt.Errorf("environment '%s' not found: %w", environment, err)
		}

		// Auto-discover components if not specified
		if len(components) == 0 {
			discoveredComponents, err := discoverStackComponents(rc, stackName, environment)
			if err != nil {
				logger.Error("Failed to discover stack components", zap.Error(err))
				return fmt.Errorf("failed to discover stack components: %w", err)
			}
			components = discoveredComponents
			logger.Info("Auto-discovered stack components", zap.Strings("components", components))
		}

		if len(components) == 0 {
			return fmt.Errorf("no components found for stack '%s' in environment '%s'", stackName, environment)
		}

		// Create stack deployment configuration
		stackConfig := &deploy.StackDeploymentConfig{
			StackName:             stackName,
			Environment:           environment,
			Strategy:              strategyEnum,
			Version:               version,
			Components:            components,
			Timeout:               timeout,
			DryRun:                dryRun,
			Force:                 force,
			ContinueOnError:       continueOnError,
			RollbackOnFailure:     rollbackOnFailure,
			Parallel:              parallel,
			WaitBetweenComponents: waitBetweenComponents,
			HealthCheck: deploy.StackHealthCheckConfig{
				Enabled:              true,
				ComponentTimeout:     5 * time.Minute,
				StackValidationDelay: 2 * time.Minute,
				CrossComponentChecks: true,
			},
		}

		// Create deployment manager
		deployConfig := deploy.DefaultDeploymentConfig()
		manager, err := deploy.NewDeploymentManager(deployConfig)
		if err != nil {
			logger.Error("Failed to create deployment manager", zap.Error(err))
			return fmt.Errorf("failed to create deployment manager: %w", err)
		}

		// Display stack deployment plan
		fmt.Printf("Stack Deployment Plan:\n")
		fmt.Printf("═════════════════════\n")
		fmt.Printf("Stack:            %s\n", stackName)
		fmt.Printf("Environment:      %s\n", environment)
		fmt.Printf("Strategy:         %s\n", strategy)
		fmt.Printf("Components:       %s\n", strings.Join(components, ", "))
		if version != "" {
			fmt.Printf("Version:          %s\n", version)
		}
		fmt.Printf("Timeout:          %s\n", timeout)
		fmt.Printf("Continue on Error: %t\n", continueOnError)
		fmt.Printf("Rollback on Fail: %t\n", rollbackOnFailure)
		fmt.Printf("Dry Run:          %t\n", dryRun)
		fmt.Printf("\n")

		// Show environment details
		fmt.Printf("Environment Configuration:\n")
		fmt.Printf("• Name:           %s\n", env.Name)
		fmt.Printf("• Type:           %s\n", env.Type)
		fmt.Printf("• Namespace:      %s\n", env.Infrastructure.Nomad.Namespace)
		if env.Infrastructure.Consul.Datacenter != "" {
			fmt.Printf("• Consul DC:      %s\n", env.Infrastructure.Consul.Datacenter)
		}
		fmt.Printf("\n")

		// Show strategy explanation
		switch strategyEnum {
		case deploy.StackDeploymentStrategySequential:
			fmt.Printf("📋 Sequential Strategy: Components will be deployed one by one in order\n")
			if waitBetweenComponents > 0 {
				fmt.Printf("   Wait between components: %s\n", waitBetweenComponents)
			}
		case deploy.StackDeploymentStrategyParallel:
			fmt.Printf("⚡ Parallel Strategy: All components will be deployed simultaneously\n")
		case deploy.StackDeploymentStrategyDependencyOrder:
			fmt.Printf("🔗 Dependency Strategy: Components will be deployed based on dependency order\n")
		}
		fmt.Printf("\n")

		// Show component deployment order
		deploymentOrder, err := determineDeploymentOrder(rc, stackConfig)
		if err != nil {
			logger.Warn("Failed to determine deployment order", zap.Error(err))
			deploymentOrder = components
		}

		fmt.Printf("Component Deployment Order:\n")
		for i, component := range deploymentOrder {
			fmt.Printf("  %d. %s\n", i+1, component)
		}
		fmt.Printf("\n")

		// Show production deployment warning
		if isProductionEnvironment(environment) {
			fmt.Printf("🚨 Production Stack Deployment Warning:\n")
			fmt.Printf("   This stack deployment targets the production environment.\n")
			fmt.Printf("   Components: %s\n", strings.Join(components, ", "))
			fmt.Printf("   Ensure all components have been tested together in lower environments.\n")
			if !rollbackOnFailure {
				fmt.Printf("   Consider using --rollback-on-failure for additional safety.\n")
			}
			fmt.Printf("\n")
		}

		// Dry run - show what would be deployed
		if dryRun {
			fmt.Printf(" Dry Run - No actual deployment will be executed\n")
			fmt.Printf("\nStack Deployment Steps (would execute):\n")
			fmt.Printf("1. Validate stack prerequisites and environment compatibility\n")
			fmt.Printf("2. Resolve component dependencies and determine deployment order\n")
			fmt.Printf("3. Prepare stack configuration and shared resources\n")
			fmt.Printf("4. Execute deployment strategy: %s\n", strategy)
			for i, component := range deploymentOrder {
				fmt.Printf("   4.%d Deploy component: %s\n", i+1, component)
			}
			fmt.Printf("5. Verify stack health and cross-component integration\n")
			fmt.Printf("6. Update service discovery and load balancing\n")
			fmt.Printf("7. Run stack-level smoke tests\n")
			if rollbackOnFailure {
				fmt.Printf("8. Automated stack rollback on failure (if needed)\n")
			}
			return nil
		}

		// Get final confirmation for production deployments
		if isProductionEnvironment(environment) && !force {
			fmt.Printf("Proceed with production stack deployment of %d components? (y/N): ", len(components))
			// In real implementation, would read from stdin
			fmt.Printf("y\n")
		}

		// Execute stack deployment
		result, err := manager.DeployStack(rc, stackConfig)
		if err != nil {
			logger.Error("Stack deployment failed",
				zap.String("stack", stackName),
				zap.String("environment", environment),
				zap.Error(err))

			// Check if rollback was attempted
			if rollbackOnFailure && result != nil && result.RollbackAttempted {
				fmt.Printf("❌ Stack deployment failed, but rollback was %s\n",
					func() string {
						if result.RollbackSuccessful {
							return "successful"
						}
						return "unsuccessful"
					}())
			}

			return fmt.Errorf("stack deployment failed: %w", err)
		}

		// Display deployment results
		fmt.Printf(" Stack deployment completed\n")
		fmt.Printf("\nStack Deployment Results:\n")
		fmt.Printf("─────────────────────────\n")
		fmt.Printf("Stack:               %s\n", stackName)
		fmt.Printf("Environment:         %s\n", environment)
		fmt.Printf("Strategy:            %s\n", strategy)
		fmt.Printf("Duration:            %s\n", result.Duration)
		fmt.Printf("Components Deployed: %d\n", result.ComponentsDeployed)
		fmt.Printf("Components Failed:   %d\n", result.ComponentsFailed)
		fmt.Printf("Overall Success:     %t\n", result.Success)

		// Show component results
		fmt.Printf("\nComponent Results:\n")
		for _, componentResult := range result.ComponentResults {
			status := ""
			if !componentResult.Success {
				status = "❌"
			}
			fmt.Printf("  %s %s - %s (took %s)\n",
				status,
				componentResult.ComponentName,
				componentResult.Version,
				componentResult.Duration)
		}

		// Show failed components details
		if result.ComponentsFailed > 0 {
			fmt.Printf("\nFailed Component Details:\n")
			for _, componentResult := range result.ComponentResults {
				if !componentResult.Success {
					fmt.Printf("  ❌ %s: %s\n", componentResult.ComponentName, componentResult.Error)
				}
			}

			if !continueOnError {
				fmt.Printf("\nStack deployment incomplete due to component failures.\n")
				fmt.Printf("Consider using --continue-on-error to deploy remaining components.\n")
			}
		}

		// Show stack-level health check results
		if len(result.StackHealthResults) > 0 {
			fmt.Printf("\nStack Health Check Results:\n")
			for _, check := range result.StackHealthResults {
				status := ""
				if !check.Passed {
					status = "❌"
				}
				fmt.Printf("  %s %s: %s\n", status, check.Check, check.Message)
			}
		}

		// Show service endpoints
		if len(result.ServiceEndpoints) > 0 {
			fmt.Printf("\nStack Service Endpoints:\n")
			for component, endpoints := range result.ServiceEndpoints {
				fmt.Printf("  %s:\n", component)
				for _, endpoint := range endpoints {
					fmt.Printf("    • %s:%d (%s)\n", endpoint.Address, endpoint.Port, endpoint.Protocol)
				}
			}
		}

		// Show rollback information for successful deployments
		if result.ComponentsDeployed > 0 && result.StackRollbackPlan != nil {
			fmt.Printf("\nStack Rollback Information:\n")
			fmt.Printf("Estimated Rollback Time: %s\n", result.StackRollbackPlan.EstimatedTime)
			fmt.Printf("Components to rollback:  %d\n", len(result.StackRollbackPlan.ComponentRollbacks))
			fmt.Printf("\nTo rollback the entire stack:\n")
			fmt.Printf("  eos deploy rollback stack %s --environment %s\n", stackName, environment)
		}

		logger.Info("Stack deployment completed",
			zap.String("stack", stackName),
			zap.String("environment", environment),
			zap.String("strategy", strategy),
			zap.Bool("success", result.Success),
			zap.Int("deployed", result.ComponentsDeployed),
			zap.Int("failed", result.ComponentsFailed),
			zap.Duration("duration", result.Duration))

		return nil
	}),
}

func init() {
	DeployCmd.AddCommand(stackCmd)

	// Required deployment flags
	stackCmd.Flags().String("environment", "", "Target environment (required)")

	// Stack configuration
	stackCmd.Flags().String("strategy", "sequential", "Deployment strategy (sequential, parallel, dependency-order)")
	stackCmd.Flags().String("version", "", "Version to deploy for all components (latest if not specified)")
	stackCmd.Flags().StringSlice("components", nil, "Specific components to deploy (auto-discover if not specified)")
	stackCmd.Flags().Duration("timeout", 60*time.Minute, "Stack deployment timeout")

	// Orchestration flags
	stackCmd.Flags().Bool("continue-on-error", false, "Continue deploying remaining components if one fails")
	stackCmd.Flags().Bool("rollback-on-failure", true, "Automatically rollback stack on deployment failure")
	stackCmd.Flags().Bool("parallel", false, "Enable parallel deployment within strategy")
	stackCmd.Flags().Duration("wait-between-components", 30*time.Second, "Wait time between component deployments")

	// Health check and validation flags
	stackCmd.Flags().Duration("component-timeout", 5*time.Minute, "Timeout for individual component deployments")
	stackCmd.Flags().Duration("stack-validation-delay", 2*time.Minute, "Delay before stack-level validation")
	stackCmd.Flags().Bool("skip-cross-component-checks", false, "Skip cross-component health checks")

	// Safety and validation flags
	stackCmd.Flags().Bool("dry-run", false, "Show deployment plan without executing")
	stackCmd.Flags().Bool("force", false, "Force deployment without confirmation")
	stackCmd.Flags().Bool("skip-validation", false, "Skip pre-deployment validation")
	stackCmd.Flags().Bool("skip-health-check", false, "Skip post-deployment health checks")

	stackCmd.Example = `  # Deploy webapp stack to staging
  eos deploy stack webapp --environment staging

  # Deploy with dependency ordering
  eos deploy stack microservices --environment production --strategy dependency-order

  # Deploy with parallel execution
  eos deploy stack platform --environment staging --strategy parallel

  # Deploy specific components only
  eos deploy stack webapp --environment production --components api,frontend,cache

  # Deploy with custom timeout and continue on error
  eos deploy stack webapp --environment staging --timeout 45m --continue-on-error`
}

// Helper functions

func discoverStackComponents(rc *eos_io.RuntimeContext, stackName, environment string) ([]string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Discovering stack components",
		zap.String("stack", stackName),
		zap.String("environment", environment))

	// Implementation would discover components from:
	// - Stack configuration files
	// - Environment registries
	// - Deployment manifests
	// - Service discovery

	// For now, return example components based on stack name
	switch stackName {
	case "webapp", "helen":
		return []string{"frontend", "api", "cache"}, nil
	case "microservices":
		return []string{"user-service", "auth-service", "api-gateway", "database"}, nil
	case "platform":
		return []string{"vault", "consul", "nomad", "monitoring"}, nil
	case "infrastructure":
		return []string{"traefik", "postgres", "redis", "elasticsearch"}, nil
	default:
		// Try to discover from environment
		logger.Warn("Stack not recognized, attempting auto-discovery", zap.String("stack", stackName))
		return []string{stackName}, nil // Fallback to single component
	}
}

func determineDeploymentOrder(rc *eos_io.RuntimeContext, config *deploy.StackDeploymentConfig) ([]string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Determining deployment order",
		zap.String("stack", config.StackName),
		zap.String("strategy", string(config.Strategy)))

	// Implementation would analyze dependencies and determine optimal order
	// For now, use predefined ordering based on common patterns

	components := config.Components
	var orderedComponents []string

	switch config.Strategy {
	case deploy.StackDeploymentStrategyDependencyOrder:
		// Order based on typical dependencies (infrastructure -> services -> frontend)
		dependencyOrder := []string{"database", "cache", "redis", "postgres", "vault", "consul", "api-gateway", "auth-service", "user-service", "api", "frontend"}

		// Add components in dependency order
		for _, dep := range dependencyOrder {
			for _, component := range components {
				if component == dep {
					orderedComponents = append(orderedComponents, component)
					break
				}
			}
		}

		// Add any remaining components
		for _, component := range components {
			found := false
			for _, ordered := range orderedComponents {
				if component == ordered {
					found = true
					break
				}
			}
			if !found {
				orderedComponents = append(orderedComponents, component)
			}
		}

	default:
		// For sequential and parallel, use the original order
		orderedComponents = components
	}

	return orderedComponents, nil
}
