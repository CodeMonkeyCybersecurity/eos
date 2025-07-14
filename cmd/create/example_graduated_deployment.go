package create

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/deploy/strategy"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var exampleGraduatedDeploymentCmd = &cobra.Command{
	Use:   "example-graduated",
	Short: "Example of graduated deployment strategies",
	Long: `Demonstrates the graduated deployment model with different strategies:

1. Direct Strategy - For development/testing
2. Salt Strategy - For production infrastructure
3. Salt+Nomad Strategy - For production services
4. Full Stack Strategy - For complex production deployments

This command shows how the deployment strategy is automatically selected
based on component type and environment, with manual override options.`,
	Example: `  # Deploy in development mode (uses direct strategy)
  eos create example-graduated --environment dev --component consul

  # Deploy in production mode (selects appropriate strategy)
  eos create example-graduated --environment prod --component consul

  # Force specific strategy
  eos create example-graduated --strategy salt --component vault

  # Show strategy recommendation
  eos create example-graduated --recommend --component postgres`,
	RunE: eos_cli.Wrap(runExampleGraduatedDeployment),
}

func init() {
	CreateCmd.AddCommand(exampleGraduatedDeploymentCmd)

	// Component configuration
	exampleGraduatedDeploymentCmd.Flags().String("component", "consul", "Component to deploy (consul, vault, nomad, postgres)")
	exampleGraduatedDeploymentCmd.Flags().String("environment", "dev", "Target environment (dev, test, prod)")
	exampleGraduatedDeploymentCmd.Flags().String("strategy", "", "Override deployment strategy (direct, salt, salt-nomad, full)")
	exampleGraduatedDeploymentCmd.Flags().String("version", "", "Component version (uses defaults if not specified)")
	
	// Operation modes
	exampleGraduatedDeploymentCmd.Flags().Bool("recommend", false, "Show strategy recommendation without deploying")
	exampleGraduatedDeploymentCmd.Flags().Bool("dry-run", false, "Show what would be deployed without applying")
	exampleGraduatedDeploymentCmd.Flags().Bool("list-strategies", false, "List available deployment strategies")
	
	// Advanced options
	exampleGraduatedDeploymentCmd.Flags().StringToString("config", nil, "Additional component configuration (key=value)")
	exampleGraduatedDeploymentCmd.Flags().Duration("timeout", 10*time.Minute, "Deployment timeout")
}

func runExampleGraduatedDeployment(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Parse flags
	componentName, _ := cmd.Flags().GetString("component")
	environment, _ := cmd.Flags().GetString("environment")
	strategyOverride, _ := cmd.Flags().GetString("strategy")
	version, _ := cmd.Flags().GetString("version")
	recommend, _ := cmd.Flags().GetBool("recommend")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	listStrategies, _ := cmd.Flags().GetBool("list-strategies")
	additionalConfig, _ := cmd.Flags().GetStringToString("config")
	timeout, _ := cmd.Flags().GetDuration("timeout")

	// Create deployer factory
	factory := strategy.NewDeployerFactory(rc)
	
	// Handle list strategies request
	if listStrategies {
		return showAvailableStrategies(rc, factory)
	}
	
	// Create component configuration
	component := createExampleComponent(componentName, environment, version, additionalConfig)
	
	// Apply strategy override if provided
	if strategyOverride != "" {
		component.Strategy = strategy.DeploymentStrategy(strategyOverride)
	}
	
	// Handle recommendation request
	if recommend {
		return showStrategyRecommendation(rc, factory, component)
	}
	
	// Create appropriate deployer
	deployer, err := factory.CreateDeployerForComponent(component)
	if err != nil {
		return fmt.Errorf("failed to create deployer: %w", err)
	}
	
	logger.Info("Starting graduated deployment example",
		zap.String("component", component.Name),
		zap.String("environment", component.Environment),
		zap.String("strategy", string(deployer.GetStrategy())),
		zap.Bool("dry_run", dryRun))
	
	// Add dry-run flag to component config
	if dryRun {
		component.Config["dry_run"] = true
	}
	
	// Create deployment context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	
	// Execute deployment
	result, err := deployer.Deploy(ctx, component)
	if err != nil {
		return fmt.Errorf("deployment failed: %w", err)
	}
	
	// Display results
	displayDeploymentResult(rc, result, deployer.GetStrategy())
	
	// Show next steps
	if !dryRun {
		showNextSteps(rc, component, result)
	}
	
	return nil
}

func createExampleComponent(name, environment, version string, additionalConfig map[string]string) *strategy.Component {
	// Create base component
	component := &strategy.Component{
		Name:        name,
		Environment: environment,
		Config:      make(map[string]interface{}),
	}
	
	// Set component type based on name
	switch name {
	case "consul", "vault", "nomad":
		component.Type = strategy.InfrastructureType
	case "postgres", "redis":
		component.Type = strategy.DatabaseType
	default:
		component.Type = strategy.ServiceType
	}
	
	// Set version defaults
	if version == "" {
		switch name {
		case "consul":
			version = "1.17.0"
		case "vault":
			version = "1.15.0"
		case "nomad":
			version = "1.7.0"
		case "postgres":
			version = "15"
		default:
			version = "latest"
		}
	}
	component.Version = version
	
	// Add component-specific defaults
	switch name {
	case "consul":
		component.Config["datacenter"] = "dc1"
		component.Config["bootstrap_expect"] = 1
		component.Config["ui_enabled"] = true
		component.Config["server_mode"] = true
	case "vault":
		component.Config["backend"] = "file"
		component.Config["storage_path"] = "/opt/vault/data"
	case "nomad":
		component.Config["datacenter"] = "dc1"
		component.Config["region"] = "global"
	case "postgres":
		component.Config["database"] = "example_db"
		component.Config["user"] = "example_user"
		component.Config["password"] = "example_pass"
		component.Config["port"] = 5432
	}
	
	// Add additional configuration
	for key, value := range additionalConfig {
		component.Config[key] = value
	}
	
	return component
}

func showAvailableStrategies(rc *eos_io.RuntimeContext, factory *strategy.DeployerFactory) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Available Deployment Strategies")
	logger.Info("================================")
	
	strategies := factory.GetAvailableStrategies()
	capabilities := factory.GetStrategyCapabilities()
	
	for _, strategyName := range strategies {
		caps := capabilities[strategyName]
		
		logger.Info(fmt.Sprintf("Strategy: %s", strategyName))
		logger.Info(fmt.Sprintf("  Supports Rollback:    %v", caps.SupportsRollback))
		logger.Info(fmt.Sprintf("  Supports Validation:  %v", caps.SupportsValidation))
		logger.Info(fmt.Sprintf("  Supports Dry Run:     %v", caps.SupportsDryRun))
		logger.Info(fmt.Sprintf("  Supports Health Check: %v", caps.SupportsHealthCheck))
		logger.Info(fmt.Sprintf("  Requires Salt:        %v", caps.RequiresSalt))
		logger.Info(fmt.Sprintf("  Requires Terraform:   %v", caps.RequiresTerraform))
		logger.Info(fmt.Sprintf("  Requires Nomad:       %v", caps.RequiresNomad))
		logger.Info("")
	}
	
	return nil
}

func showStrategyRecommendation(rc *eos_io.RuntimeContext, factory *strategy.DeployerFactory, component *strategy.Component) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	recommendation := factory.GetRecommendation(component)
	
	logger.Info("Deployment Strategy Recommendation")
	logger.Info("==================================")
	logger.Info(fmt.Sprintf("Component: %s (%s)", component.Name, component.Type))
	logger.Info(fmt.Sprintf("Environment: %s", component.Environment))
	logger.Info("")
	logger.Info(fmt.Sprintf("Recommended Strategy: %s", recommendation.RecommendedStrategy))
	logger.Info(fmt.Sprintf("Reasoning: %s", recommendation.Reasoning))
	logger.Info("")
	
	if len(recommendation.Alternatives) > 0 {
		logger.Info("Alternative Strategies:")
		for _, alt := range recommendation.Alternatives {
			logger.Info(fmt.Sprintf("  %s - %s", alt.Strategy, alt.Description))
			if len(alt.Pros) > 0 {
				logger.Info("    Pros:")
				for _, pro := range alt.Pros {
					logger.Info(fmt.Sprintf("      + %s", pro))
				}
			}
			if len(alt.Cons) > 0 {
				logger.Info("    Cons:")
				for _, con := range alt.Cons {
					logger.Info(fmt.Sprintf("      - %s", con))
				}
			}
			logger.Info("")
		}
	}
	
	if len(recommendation.Warnings) > 0 {
		logger.Info("Warnings:")
		for _, warning := range recommendation.Warnings {
			logger.Info(fmt.Sprintf("  ⚠️  %s", warning))
		}
		logger.Info("")
	}
	
	return nil
}

func displayDeploymentResult(rc *eos_io.RuntimeContext, result *strategy.DeploymentResult, strategyUsed strategy.DeploymentStrategy) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("")
	logger.Info("╔══════════════════════════════════════════════════════════════════╗")
	logger.Info("║                    DEPLOYMENT RESULT                            ║")
	logger.Info("╚══════════════════════════════════════════════════════════════════╝")
	logger.Info("")
	
	logger.Info("📋 Deployment Details:")
	logger.Info(fmt.Sprintf("   • Component:     %s", result.Component))
	logger.Info(fmt.Sprintf("   • Strategy Used: %s", strategyUsed))
	logger.Info(fmt.Sprintf("   • Status:        %s", result.Status))
	logger.Info(fmt.Sprintf("   • Deployment ID: %s", result.ID))
	
	if result.EndTime != nil {
		duration := result.EndTime.Sub(result.StartTime)
		logger.Info(fmt.Sprintf("   • Duration:      %s", duration))
	}
	
	if result.Error != "" {
		logger.Info(fmt.Sprintf("   • Error:         %s", result.Error))
	}
	
	if len(result.Outputs) > 0 {
		logger.Info("")
		logger.Info("📊 Deployment Outputs:")
		for key, value := range result.Outputs {
			logger.Info(fmt.Sprintf("   • %s: %v", key, value))
		}
	}
	
	logger.Info("")
}

func showNextSteps(rc *eos_io.RuntimeContext, component *strategy.Component, result *strategy.DeploymentResult) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("✅ Next Steps:")
	
	// Generic next steps
	logger.Info("   1. Verify deployment health:")
	logger.Info(fmt.Sprintf("      eos read deployment status %s", result.ID))
	
	logger.Info("   2. View deployment logs:")
	logger.Info(fmt.Sprintf("      eos read deployment logs %s", result.ID))
	
	// Component-specific next steps
	switch component.Name {
	case "consul":
		logger.Info("   3. Check cluster members:")
		logger.Info("      consul members")
		logger.Info("   4. Access web UI:")
		logger.Info("      http://localhost:8161/ui")
	case "vault":
		logger.Info("   3. Initialize Vault:")
		logger.Info("      vault operator init")
		logger.Info("   4. Unseal Vault:")
		logger.Info("      vault operator unseal")
	case "nomad":
		logger.Info("   3. Check cluster status:")
		logger.Info("      nomad node status")
		logger.Info("   4. Access web UI:")
		logger.Info("      http://localhost:4646")
	case "postgres":
		logger.Info("   3. Connect to database:")
		logger.Info("      psql -h localhost -U example_user -d example_db")
	}
	
	// Strategy-specific next steps
	switch result.Strategy {
	case strategy.SaltStrategy:
		logger.Info("   • Salt state applied: " + fmt.Sprintf("%v", result.Outputs["salt_state"]))
	case strategy.SaltNomadStrategy:
		logger.Info("   • Salt state: " + fmt.Sprintf("%v", result.Outputs["salt_state"]))
		logger.Info("   • Nomad job: " + fmt.Sprintf("%v", result.Outputs["nomad_job_id"]))
	case strategy.FullStackStrategy:
		logger.Info("   • Full stack deployment with all layers configured")
		if workspace, ok := result.Outputs["terraform_workspace"]; ok {
			logger.Info("   • Terraform workspace: " + fmt.Sprintf("%v", workspace))
		}
	}
	
	if result.RollbackInfo != nil {
		logger.Info("")
		logger.Info("🔄 Rollback Information:")
		logger.Info(fmt.Sprintf("   • Rollback available: %s strategy", result.RollbackInfo.Strategy))
		logger.Info(fmt.Sprintf("   • To rollback: eos rollback deployment %s", result.ID))
	}
	
	logger.Info("")
	logger.Info("═══════════════════════════════════════════════════════════════════")
}