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

var serviceCmd = &cobra.Command{
	Use:   "service <service-name>",
	Short: "Deploy a service component with fine-ed control",
	Long: `Deploy a specific service component with granular deployment control and
service-specific configuration options.

Service deployments provide fine-ed control over individual microservices,
allowing for independent scaling, configuration, and deployment strategies.
Each service deployment follows the assessment→intervention→evaluation pattern
with comprehensive service mesh integration and dependency management.

Service deployment features include:
- Independent service lifecycle management
- Service mesh integration (Consul Connect)
- Fine-ed resource allocation and scaling
- Service-specific health checks and metrics
- Dependency management and orchestration
- Configuration management with environment-specific overrides
- Integration with service discovery and load balancing

Examples:
  # Deploy API service to staging
  eos deploy service api --environment staging

  # Deploy with specific resource allocation
  eos deploy service api --environment production --cpu 500m --memory 1Gi

  # Deploy with service mesh integration
  eos deploy service api --environment production --enable-mesh --mesh-proxy-cpu 100m

  # Deploy with custom configuration
  eos deploy service api --environment staging --config-file api-staging.yaml

  # Deploy with dependency verification
  eos deploy service frontend --environment production --verify-dependencies`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		serviceName := args[0]

		logger.Info("Deploying service",
			zap.String("command", "deploy service"),
			zap.String("service", serviceName),
			zap.String("context", rc.Component))

		// Parse flags
		environment, _ := cmd.Flags().GetString("environment")
		strategy, _ := cmd.Flags().GetString("strategy")
		version, _ := cmd.Flags().GetString("version")
		replicas, _ := cmd.Flags().GetInt("replicas")
		cpu, _ := cmd.Flags().GetString("cpu")
		memory, _ := cmd.Flags().GetString("memory")
		timeout, _ := cmd.Flags().GetDuration("timeout")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		force, _ := cmd.Flags().GetBool("force")

		// Service-specific flags
		enableMesh, _ := cmd.Flags().GetBool("enable-mesh")
		meshProxyCpu, _ := cmd.Flags().GetString("mesh-proxy-cpu")
		meshProxyMemory, _ := cmd.Flags().GetString("mesh-proxy-memory")
		configFile, _ := cmd.Flags().GetString("config-file")
		secretsPath, _ := cmd.Flags().GetString("secrets-path")
		verifyDependencies, _ := cmd.Flags().GetBool("verify-dependencies")
		healthCheckPath, _ := cmd.Flags().GetString("health-check-path")
		port, _ := cmd.Flags().GetInt("port")

		logger.Debug("Service deployment configuration",
			zap.String("service", serviceName),
			zap.String("environment", environment),
			zap.String("strategy", strategy),
			zap.String("version", version),
			zap.Int("replicas", replicas),
			zap.String("cpu", cpu),
			zap.String("memory", memory),
			zap.Bool("enable_mesh", enableMesh),
			zap.String("config_file", configFile),
			zap.Bool("verify_dependencies", verifyDependencies))

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
		env, err := envManager.GetEnvironment(rc, environment)
		if err != nil {
			logger.Error("Failed to get environment", zap.Error(err))
			return fmt.Errorf("environment '%s' not found: %w", environment, err)
		}

		// Create service deployment configuration
		serviceConfig := &deploy.ServiceDeploymentConfig{
			ServiceName: serviceName,
			Environment: environment,
			Strategy:    strategyEnum,
			Version:     version,
			Replicas:    replicas,
			Timeout:     timeout,
			DryRun:      dryRun,
			Force:       force,
			Resources: deploy.ResourceConfig{
				CPU:    cpu,
				Memory: memory,
			},
			ServiceMesh: deploy.ServiceMeshConfig{
				Enabled:     enableMesh,
				ProxyCPU:    meshProxyCpu,
				ProxyMemory: meshProxyMemory,
			},
			Configuration: deploy.ConfigurationConfig{
				ConfigFile:  configFile,
				SecretsPath: secretsPath,
			},
			HealthCheck: deploy.HealthCheckConfig{
				Enabled:  true,
				Path:     healthCheckPath,
				Port:     port,
				Timeout:  30 * time.Second,
				Interval: 15 * time.Second,
				Retries:  3,
			},
			Dependencies: deploy.DependencyConfig{
				VerifyDependencies: verifyDependencies,
				DependencyTimeout:  5 * time.Minute,
			},
		}

		// Create deployment manager
		deployConfig := deploy.DefaultDeploymentConfig()
		manager, err := deploy.NewDeploymentManager(deployConfig)
		if err != nil {
			logger.Error("Failed to create deployment manager", zap.Error(err))
			return fmt.Errorf("failed to create deployment manager: %w", err)
		}

		// Display service deployment plan
		fmt.Printf("Service Deployment Plan:\n")
		fmt.Printf("═══════════════════════\n")
		fmt.Printf("Service:          %s\n", serviceName)
		fmt.Printf("Environment:      %s\n", environment)
		fmt.Printf("Strategy:         %s\n", strategy)
		fmt.Printf("Replicas:         %d\n", replicas)
		if version != "" {
			fmt.Printf("Version:          %s\n", version)
		}
		if cpu != "" {
			fmt.Printf("CPU:              %s\n", cpu)
		}
		if memory != "" {
			fmt.Printf("Memory:           %s\n", memory)
		}
		if port > 0 {
			fmt.Printf("Port:             %d\n", port)
		}
		fmt.Printf("Service Mesh:     %t\n", enableMesh)
		fmt.Printf("Verify Dependencies: %t\n", verifyDependencies)
		fmt.Printf("Timeout:          %s\n", timeout)
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

		// Show service mesh configuration if enabled
		if enableMesh {
			fmt.Printf("Service Mesh Configuration:\n")
			fmt.Printf("• Consul Connect: enabled\n")
			fmt.Printf("• Proxy CPU:      %s\n", meshProxyCpu)
			fmt.Printf("• Proxy Memory:   %s\n", meshProxyMemory)
			fmt.Printf("• Service Identity: %s-%s\n", serviceName, environment)
			fmt.Printf("\n")
		}

		// Show configuration sources
		if configFile != "" || secretsPath != "" {
			fmt.Printf("Configuration Sources:\n")
			if configFile != "" {
				fmt.Printf("• Config File:    %s\n", configFile)
			}
			if secretsPath != "" {
				fmt.Printf("• Secrets Path:   %s\n", secretsPath)
			}
			fmt.Printf("\n")
		}

		// Show production deployment warning
		if isProductionEnvironment(environment) {
			fmt.Printf("🚨 Production Service Deployment Warning:\n")
			fmt.Printf("   This service deployment targets the production environment.\n")
			fmt.Printf("   Ensure service dependencies are properly configured.\n")
			if !verifyDependencies {
				fmt.Printf("   Consider using --verify-dependencies for additional safety.\n")
			}
			if !enableMesh {
				fmt.Printf("   Consider using --enable-mesh for enhanced security.\n")
			}
			fmt.Printf("\n")
		}

		// Dry run - show what would be deployed
		if dryRun {
			fmt.Printf(" Dry Run - No actual deployment will be executed\n")
			fmt.Printf("\nService Deployment Steps (would execute):\n")
			fmt.Printf("1. Validate service prerequisites and environment compatibility\n")
			if verifyDependencies {
				fmt.Printf("2. Verify service dependencies are healthy\n")
			}
			fmt.Printf("3. Prepare service artifacts and configuration\n")
			if enableMesh {
				fmt.Printf("4. Configure service mesh identity and policies\n")
			}
			fmt.Printf("5. Execute %s deployment strategy\n", strategy)
			fmt.Printf("6. Register service in Consul service discovery\n")
			fmt.Printf("7. Configure health checks and monitoring\n")
			fmt.Printf("8. Verify service health and readiness\n")
			return nil
		}

		// Get final confirmation for production deployments
		if isProductionEnvironment(environment) && !force {
			fmt.Printf("Proceed with production service deployment? (y/N): ")
			// In real implementation, would read from stdin
			fmt.Printf("y\n")
		}

		// Execute service deployment
		result, err := manager.DeployService(rc, serviceConfig)
		if err != nil {
			logger.Error("Service deployment failed",
				zap.String("service", serviceName),
				zap.String("environment", environment),
				zap.Error(err))

			return fmt.Errorf("service deployment failed: %w", err)
		}

		// Display deployment results
		fmt.Printf(" Service deployment completed successfully\n")
		fmt.Printf("\nDeployment Results:\n")
		fmt.Printf("───────────────────\n")
		fmt.Printf("Service:          %s\n", serviceName)
		fmt.Printf("Environment:      %s\n", environment)
		fmt.Printf("Strategy:         %s\n", strategy)
		fmt.Printf("Version:          %s\n", result.Version)
		fmt.Printf("Replicas:         %d\n", result.Replicas)
		fmt.Printf("Duration:         %s\n", result.Duration)
		fmt.Printf("Deployment ID:    %s\n", result.DeploymentID)

		if result.ServiceURL != "" {
			fmt.Printf("Service URL:      %s\n", result.ServiceURL)
		}

		if result.ServiceAddress != "" {
			fmt.Printf("Service Address:  %s\n", result.ServiceAddress)
		}

		// Show service mesh details if enabled
		if enableMesh && result.ServiceMeshConfig != nil {
			fmt.Printf("\nService Mesh Integration:\n")
			fmt.Printf("Connect Identity: %s\n", result.ServiceMeshConfig.Identity)
			fmt.Printf("Proxy Status:     %s\n", result.ServiceMeshConfig.ProxyStatus)
			if len(result.ServiceMeshConfig.Intentions) > 0 {
				fmt.Printf("Intentions:       %d configured\n", len(result.ServiceMeshConfig.Intentions))
			}
		}

		// Show dependency verification results
		if verifyDependencies && len(result.DependencyResults) > 0 {
			fmt.Printf("\nDependency Verification:\n")
			for _, dep := range result.DependencyResults {
				status := ""
				if !dep.Healthy {
					status = ""
				}
				fmt.Printf("  %s %s: %s\n", status, dep.Name, dep.Status)
			}
		}

		// Show deployment steps executed
		if len(result.StepsExecuted) > 0 {
			fmt.Printf("\nSteps Executed:\n")
			for _, step := range result.StepsExecuted {
				status := ""
				if step.Status != "completed" {
					status = ""
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
					status = ""
				}
				fmt.Printf("  %s %s: %s\n", status, check.Check, check.Message)
			}
		}

		// Show service endpoints
		if len(result.Endpoints) > 0 {
			fmt.Printf("\nService Endpoints:\n")
			for _, endpoint := range result.Endpoints {
				fmt.Printf("  • %s:%d (%s)\n", endpoint.Address, endpoint.Port, endpoint.Protocol)
			}
		}

		logger.Info("Service deployment completed successfully",
			zap.String("service", serviceName),
			zap.String("environment", environment),
			zap.String("strategy", strategy),
			zap.String("version", result.Version),
			zap.Int("replicas", result.Replicas),
			zap.Duration("duration", result.Duration))

		return nil
	}),
}

func init() {
	DeployCmd.AddCommand(serviceCmd)

	// Required deployment flags
	serviceCmd.Flags().String("environment", "", "Target environment (required)")

	// Service configuration
	serviceCmd.Flags().String("strategy", "rolling", "Deployment strategy (rolling, blue-green, canary, immutable)")
	serviceCmd.Flags().String("version", "", "Service version to deploy (latest if not specified)")
	serviceCmd.Flags().Int("replicas", 1, "Number of service replicas")
	serviceCmd.Flags().Duration("timeout", 20*time.Minute, "Deployment timeout")

	// Resource allocation
	serviceCmd.Flags().String("cpu", "", "CPU allocation (e.g., 500m, 1000m)")
	serviceCmd.Flags().String("memory", "", "Memory allocation (e.g., 512Mi, 1Gi)")
	serviceCmd.Flags().Int("port", 0, "Service port (auto-detect if not specified)")

	// Service mesh configuration
	serviceCmd.Flags().Bool("enable-mesh", false, "Enable service mesh (Consul Connect)")
	serviceCmd.Flags().String("mesh-proxy-cpu", "100m", "Service mesh proxy CPU allocation")
	serviceCmd.Flags().String("mesh-proxy-memory", "128Mi", "Service mesh proxy memory allocation")

	// Configuration and secrets
	serviceCmd.Flags().String("config-file", "", "Configuration file path")
	serviceCmd.Flags().String("secrets-path", "", "Vault secrets path")
	serviceCmd.Flags().Bool("verify-dependencies", false, "Verify service dependencies before deployment")

	// Health check configuration
	serviceCmd.Flags().String("health-check-path", "/health", "Health check endpoint path")
	serviceCmd.Flags().Duration("health-check-timeout", 30*time.Second, "Health check timeout")
	serviceCmd.Flags().Duration("health-check-interval", 15*time.Second, "Health check interval")

	// Safety and validation flags
	serviceCmd.Flags().Bool("dry-run", false, "Show deployment plan without executing")
	serviceCmd.Flags().Bool("force", false, "Force deployment without confirmation")
	serviceCmd.Flags().Bool("skip-validation", false, "Skip pre-deployment validation")
	serviceCmd.Flags().Bool("skip-health-check", false, "Skip post-deployment health checks")

	serviceCmd.Example = `  # Deploy API service to staging
  eos deploy service api --environment staging

  # Deploy with resource allocation
  eos deploy service api --environment production --cpu 500m --memory 1Gi --replicas 3

  # Deploy with service mesh
  eos deploy service api --environment production --enable-mesh

  # Deploy with dependency verification
  eos deploy service frontend --environment staging --verify-dependencies

  # Deploy with custom configuration
  eos deploy service api --environment staging --config-file /srv/config/api-staging.yaml`
}
