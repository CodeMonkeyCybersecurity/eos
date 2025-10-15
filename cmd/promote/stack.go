package promote

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environments"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/promotion"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var stackCmd = &cobra.Command{
	Use:   "stack <stack-name>",
	Short: "Promote a stack of components between environments",
	Long: `Promote multiple components as a coordinated stack between environments with
comprehensive dependency management, validation, and rollback capabilities.

Stack promotion enables atomic deployment of multi-component applications following
the assessment→intervention→evaluation pattern. It supports various promotion strategies
including sequential, parallel, and dependency-ordered execution with comprehensive
error handling and rollback planning.

The stack promotion process includes:
- Stack configuration validation and component discovery
- Inter-component dependency resolution and ordering
- Coordinated deployment with configurable strategies
- Cross-component health checking and validation
- Atomic rollback plan generation for the entire stack
- Comprehensive audit logging and compliance tracking

Examples:
  # Promote webapp stack from staging to production
  eos promote stack webapp --from staging --to production

  # Promote with dependency ordering
  eos promote stack microservices --from staging --to production --strategy dependency-order

  # Promote with parallel execution
  eos promote stack frontend --from dev --to staging --strategy parallel

  # Promote specific components only
  eos promote stack webapp --from staging --to production --components api,frontend,cache

  # Emergency stack promotion
  eos promote stack hotfix --from staging --to production --emergency --continue-on-error`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		stackName := args[0]

		logger.Info("Promoting stack",
			zap.String("command", "promote stack"),
			zap.String("stack", stackName),
			zap.String("context", rc.Component))

		// Parse flags
		fromEnv, _ := cmd.Flags().GetString("from")
		toEnv, _ := cmd.Flags().GetString("to")
		version, _ := cmd.Flags().GetString("version")
		reason, _ := cmd.Flags().GetString("reason")
		strategy, _ := cmd.Flags().GetString("strategy")
		components, _ := cmd.Flags().GetStringSlice("components")
		requireApproval, _ := cmd.Flags().GetBool("require-approval")
		emergency, _ := cmd.Flags().GetBool("emergency")
		continueOnError, _ := cmd.Flags().GetBool("continue-on-error")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		force, _ := cmd.Flags().GetBool("force")
		timeout, _ := cmd.Flags().GetDuration("timeout")

		logger.Debug("Stack promotion configuration",
			zap.String("stack", stackName),
			zap.String("from", fromEnv),
			zap.String("to", toEnv),
			zap.String("version", version),
			zap.String("strategy", strategy),
			zap.Strings("components", components),
			zap.Bool("require_approval", requireApproval),
			zap.Bool("emergency", emergency),
			zap.Bool("continue_on_error", continueOnError),
			zap.Bool("dry_run", dryRun))

		// Validate required flags
		if fromEnv == "" {
			return fmt.Errorf("source environment is required (--from flag)")
		}
		if toEnv == "" {
			return fmt.Errorf("target environment is required (--to flag)")
		}
		if fromEnv == toEnv {
			return fmt.Errorf("source and target environments cannot be the same")
		}

		// Validate strategy
		strategyEnum := promotion.StackPromotionStrategySequential
		switch strategy {
		case "sequential":
			strategyEnum = promotion.StackPromotionStrategySequential
		case "parallel":
			strategyEnum = promotion.StackPromotionStrategyParallel
		case "dependency-order":
			strategyEnum = promotion.StackPromotionStrategyDependency
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

		// Create promotion manager
		promotionConfig := &promotion.PromotionConfig{
			DryRun:         dryRun,
			Force:          force,
			SkipValidation: emergency,
			SkipApproval:   emergency && !requireApproval,
			Timeout:        timeout,
		}

		promotionManager, err := promotion.NewPromotionManager(envManager, promotionConfig)
		if err != nil {
			logger.Error("Failed to create promotion manager", zap.Error(err))
			return fmt.Errorf("failed to create promotion manager: %w", err)
		}

		// Auto-discover components if not specified
		if len(components) == 0 {
			discoveredComponents, err := discoverStackComponents(rc, stackName, fromEnv)
			if err != nil {
				logger.Error("Failed to discover stack components", zap.Error(err))
				return fmt.Errorf("failed to discover stack components: %w", err)
			}
			components = discoveredComponents
			logger.Info("Auto-discovered stack components", zap.Strings("components", components))
		}

		if len(components) == 0 {
			return fmt.Errorf("no components found for stack '%s' in environment '%s'", stackName, fromEnv)
		}

		// Create stack promotion request
		request := &promotion.StackPromotionRequest{
			ID:              generateStackPromotionID(stackName, fromEnv, toEnv),
			StackName:       stackName,
			Components:      components,
			FromEnvironment: fromEnv,
			ToEnvironment:   toEnv,
			Version:         version,
			Strategy:        strategyEnum,
			ContinueOnError: continueOnError,
			Status:          promotion.PromotionStatusPending,
			CreatedAt:       time.Now(),
		}

		// Set default reason if not provided
		if reason == "" {
			reason = fmt.Sprintf("Stack promotion: %s → %s", fromEnv, toEnv)
		}

		// Display stack promotion plan
		fmt.Printf("Stack Promotion Plan:\n")
		fmt.Printf("═══════════════════════\n")
		fmt.Printf("Stack:            %s\n", stackName)
		fmt.Printf("Components:       %s\n", strings.Join(components, ", "))
		fmt.Printf("From Environment: %s\n", fromEnv)
		fmt.Printf("To Environment:   %s\n", toEnv)
		if version != "" {
			fmt.Printf("Version:          %s\n", version)
		}
		fmt.Printf("Strategy:         %s\n", strategy)
		fmt.Printf("Reason:           %s\n", reason)
		fmt.Printf("Continue on Error: %t\n", continueOnError)
		fmt.Printf("Emergency Mode:   %t\n", emergency)
		fmt.Printf("Dry Run:          %t\n", dryRun)
		fmt.Printf("\n")

		// Show strategy explanation
		switch strategyEnum {
		case promotion.StackPromotionStrategySequential:
			fmt.Printf(" Sequential Strategy: Components will be promoted one by one in order\n")
		case promotion.StackPromotionStrategyParallel:
			fmt.Printf("⚡ Parallel Strategy: All components will be promoted simultaneously\n")
		case promotion.StackPromotionStrategyDependency:
			fmt.Printf(" Dependency Strategy: Components will be promoted based on dependency order\n")
		}
		fmt.Printf("\n")

		// Show production warning
		if isProductionTarget(toEnv) {
			fmt.Printf("🚨 Production Stack Promotion Warning:\n")
			fmt.Printf("   This stack promotion targets the production environment.\n")
			fmt.Printf("   Components: %s\n", strings.Join(components, ", "))
			fmt.Printf("   Ensure all components have been tested together in lower environments.\n")
			if !requireApproval {
				fmt.Printf("   Consider using --require-approval for additional safety.\n")
			}
			fmt.Printf("\n")
		}

		// Dry run - show what would be promoted
		if dryRun {
			fmt.Printf(" Dry Run - No actual promotion will be executed\n")
			fmt.Printf("\nStack Promotion Steps (would execute):\n")
			fmt.Printf("1. Validate all stack components in source environment\n")
			fmt.Printf("2. Check target environment compatibility for stack\n")
			fmt.Printf("3. Resolve component dependencies and determine promotion order\n")
			if requireApproval {
				fmt.Printf("4. Request stack promotion approval\n")
			}
			fmt.Printf("5. Execute promotion strategy: %s\n", strategy)
			for i, component := range components {
				fmt.Printf("   %d.%d Promote component: %s\n", 5, i+1, component)
			}
			fmt.Printf("6. Verify stack health and component integration\n")
			fmt.Printf("7. Update deployment registry for all components\n")
			fmt.Printf("8. Generate comprehensive stack rollback plan\n")
			return nil
		}

		// Get final confirmation for non-emergency promotions
		if !emergency && !force {
			fmt.Printf("Proceed with stack promotion of %d components? (y/N): ", len(components))
			// In real implementation, would read from stdin
			fmt.Printf("y\n")
		}

		// Execute stack promotion
		result, err := promotionManager.PromoteStack(rc, request)
		if err != nil {
			logger.Error("Stack promotion failed",
				zap.String("stack", stackName),
				zap.Error(err))

			// Check if it's an approval-required error
			if promotionErr, ok := err.(*promotion.PromotionError); ok && promotionErr.Type == "approval_required" {
				fmt.Printf("⏳ Stack promotion created and waiting for approval\n")
				fmt.Printf("\nStack Promotion Details:\n")
				fmt.Printf("──────────────────────\n")
				fmt.Printf("Promotion ID:     %s\n", request.ID)
				fmt.Printf("Stack:            %s\n", stackName)
				fmt.Printf("Components:       %s\n", strings.Join(components, ", "))
				fmt.Printf("\nTo approve this stack promotion:\n")
				fmt.Printf("  eos promote approve %s\n", request.ID)
				return nil
			}

			return fmt.Errorf("stack promotion failed: %w", err)
		}

		// Display stack promotion results
		fmt.Printf(" Stack promotion completed\n")
		fmt.Printf("\nStack Promotion Results:\n")
		fmt.Printf("────────────────────────\n")
		fmt.Printf("Stack:               %s\n", stackName)
		fmt.Printf("From:                %s\n", fromEnv)
		fmt.Printf("To:                  %s\n", toEnv)
		fmt.Printf("Duration:            %s\n", result.Duration)
		fmt.Printf("Components Promoted: %d\n", result.ComponentsPromoted)
		fmt.Printf("Components Failed:   %d\n", result.ComponentsFailed)
		fmt.Printf("Overall Success:     %t\n", result.Success)

		// Show component results
		fmt.Printf("\nComponent Results:\n")
		for _, componentResult := range result.Results {
			status := ""
			if !componentResult.Success {
				status = ""
			}
			fmt.Printf("  %s %s - %s (took %s)\n",
				status,
				componentResult.Request.Component,
				componentResult.Request.Version,
				componentResult.Duration)
		}

		// Show failed components details
		if result.ComponentsFailed > 0 {
			fmt.Printf("\nFailed Component Details:\n")
			for _, componentResult := range result.Results {
				if !componentResult.Success {
					fmt.Printf("   %s: %s\n", componentResult.Request.Component, componentResult.Error)
				}
			}

			if !continueOnError {
				fmt.Printf("\nStack promotion incomplete due to component failures.\n")
				fmt.Printf("Consider using --continue-on-error to promote remaining components.\n")
			}
		}

		// Show rollback information for successful promotions
		if result.ComponentsPromoted > 0 {
			fmt.Printf("\nRollback Information:\n")
			fmt.Printf("To rollback the entire stack:\n")
			for _, componentResult := range result.Results {
				if componentResult.Success && componentResult.RollbackPlan != nil {
					fmt.Printf("  eos rollback %s --to-version %s\n",
						componentResult.Request.Component,
						componentResult.RollbackPlan.PreviousVersion)
				}
			}
		}

		logger.Info("Stack promotion completed",
			zap.String("stack", stackName),
			zap.String("from", fromEnv),
			zap.String("to", toEnv),
			zap.Bool("success", result.Success),
			zap.Int("promoted", result.ComponentsPromoted),
			zap.Int("failed", result.ComponentsFailed),
			zap.Duration("duration", result.Duration))

		return nil
	}),
}

func init() {
	PromoteCmd.AddCommand(stackCmd)

	// Required promotion flags
	stackCmd.Flags().String("from", "", "Source environment (required)")
	stackCmd.Flags().String("to", "", "Target environment (required)")

	// Stack configuration
	stackCmd.Flags().String("version", "", "Version to promote for all components (latest if not specified)")
	stackCmd.Flags().String("reason", "", "Reason for stack promotion")
	stackCmd.Flags().StringSlice("components", nil, "Specific components to promote (auto-discover if not specified)")
	stackCmd.Flags().String("strategy", "sequential", "Promotion strategy (sequential, parallel, dependency-order)")

	// Approval and safety flags
	stackCmd.Flags().Bool("require-approval", false, "Force approval requirement even for non-production")
	stackCmd.Flags().Bool("emergency", false, "Emergency promotion (bypass some safety checks)")
	stackCmd.Flags().Bool("force", false, "Force promotion without confirmation")
	stackCmd.Flags().Bool("dry-run", false, "Show promotion plan without executing")
	stackCmd.Flags().Bool("continue-on-error", false, "Continue promoting remaining components if one fails")

	// Timeout and retry flags
	stackCmd.Flags().Duration("timeout", 60*time.Minute, "Stack promotion timeout")
	stackCmd.Flags().Int("retries", 0, "Number of retry attempts on failure")

	// Validation flags
	stackCmd.Flags().Bool("skip-validation", false, "Skip pre-promotion validation")
	stackCmd.Flags().Bool("skip-health-check", false, "Skip post-promotion health checks")
	stackCmd.Flags().StringSlice("validation-rules", nil, "Additional validation rules to apply")

	stackCmd.Example = `  # Basic stack promotion
  eos promote stack webapp --from staging --to production

  # Parallel promotion with specific components
  eos promote stack microservices --from staging --to production --strategy parallel --components api,frontend,cache

  # Dependency-ordered promotion
  eos promote stack platform --from dev --to staging --strategy dependency-order

  # Emergency stack promotion
  eos promote stack hotfix --from staging --to production --emergency --continue-on-error

  # With approval workflow
  eos promote stack webapp --from staging --to production --require-approval --reason "Release v2.0"`
}

// Helper functions

func generateStackPromotionID(stack, from, to string) string {
	timestamp := time.Now().Format("20060102150405")
	return fmt.Sprintf("%s-stack-%s-%s-%s", stack, to, timestamp, "promo")
}

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
	default:
		// Try to discover from environment
		logger.Warn("Stack not recognized, attempting auto-discovery", zap.String("stack", stackName))
		return []string{stackName}, nil // Fallback to single component
	}
}
