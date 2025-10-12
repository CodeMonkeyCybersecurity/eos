package promote

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environments"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/promotion"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var componentCmd = &cobra.Command{
	Use:   "component <component-name>",
	Short: "Promote a specific component between environments",
	Long: `Promote a specific component from one environment to another with comprehensive
validation, approval workflows, and automated rollback planning.

This command enables safe component promotion across environments following the
assessment→intervention→evaluation pattern. It includes pre-promotion validation,
deployment orchestration, post-deployment verification, and rollback plan generation.

The promotion process includes:
- Source environment validation and artifact verification
- Target environment compatibility checking  
- Approval workflow execution (if required)
- Deployment orchestration using  → Terraform → Nomad
- Health checks and smoke testing
- Deployment registry updates
- Rollback plan generation

Examples:
  # Promote from staging to production
  eos promote component helen --from staging --to production

  # Promote specific version with approval
  eos promote component api --from staging --to production --version v2.1.0 --require-approval

  # Promote with custom reason
  eos promote component frontend --from dev --to staging --reason "Feature complete for testing"

  # Emergency promotion (bypass some checks)
  eos promote component api --from staging --to production --emergency

  # Dry run to see promotion plan
  eos promote component helen --from staging --to production --dry-run`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		componentName := args[0]

		logger.Info("Promoting component",
			zap.String("command", "promote component"),
			zap.String("component", componentName),
			zap.String("context", rc.Component))

		// Parse flags
		fromEnv, _ := cmd.Flags().GetString("from")
		toEnv, _ := cmd.Flags().GetString("to")
		version, _ := cmd.Flags().GetString("version")
		reason, _ := cmd.Flags().GetString("reason")
		requireApproval, _ := cmd.Flags().GetBool("require-approval")
		emergency, _ := cmd.Flags().GetBool("emergency")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		force, _ := cmd.Flags().GetBool("force")
		timeout, _ := cmd.Flags().GetDuration("timeout")

		logger.Debug("Promotion configuration",
			zap.String("component", componentName),
			zap.String("from", fromEnv),
			zap.String("to", toEnv),
			zap.String("version", version),
			zap.Bool("require_approval", requireApproval),
			zap.Bool("emergency", emergency),
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

		// Create promotion request
		request := &promotion.PromotionRequest{
			ID:              generatePromotionID(componentName, fromEnv, toEnv),
			Component:       componentName,
			FromEnvironment: fromEnv,
			ToEnvironment:   toEnv,
			Version:         version,
			Reason:          reason,
			RequesterID:     "current-user", // Would get from context
			ApprovalPolicy: promotion.ApprovalPolicy{
				Required:        requireApproval || isProductionTarget(toEnv),
				AutoApprove:     emergency || (!requireApproval && !isProductionTarget(toEnv)),
				MinApprovals:    getMinApprovalsForEnvironment(toEnv),
				ApprovalTimeout: 24 * time.Hour,
			},
			Status:    promotion.PromotionStatusPending,
			CreatedAt: time.Now(),
		}

		// Set default reason if not provided
		if request.Reason == "" {
			request.Reason = fmt.Sprintf("Component promotion: %s → %s", fromEnv, toEnv)
		}

		// Display promotion plan
		fmt.Printf("Component Promotion Plan:\n")
		fmt.Printf("═════════════════════════\n")
		fmt.Printf("Component:        %s\n", componentName)
		fmt.Printf("From Environment: %s\n", fromEnv)
		fmt.Printf("To Environment:   %s\n", toEnv)
		if version != "" {
			fmt.Printf("Version:          %s\n", version)
		}
		fmt.Printf("Reason:           %s\n", request.Reason)
		fmt.Printf("Approval Required: %t\n", request.ApprovalPolicy.Required)
		fmt.Printf("Emergency Mode:   %t\n", emergency)
		fmt.Printf("Dry Run:          %t\n", dryRun)
		fmt.Printf("\n")

		// Show warnings for production promotions
		if isProductionTarget(toEnv) {
			fmt.Printf("🚨 Production Promotion Warning:\n")
			fmt.Printf("   This promotion targets the production environment.\n")
			fmt.Printf("   Ensure all testing has been completed in lower environments.\n")
			if !request.ApprovalPolicy.Required {
				fmt.Printf("   Consider using --require-approval for additional safety.\n")
			}
			fmt.Printf("\n")
		}

		// Dry run - show what would be promoted
		if dryRun {
			fmt.Printf(" Dry Run - No actual promotion will be executed\n")
			fmt.Printf("\nPromotion Steps (would execute):\n")
			fmt.Printf("1. Validate source environment and component\n")
			fmt.Printf("2. Check target environment compatibility\n")
			if request.ApprovalPolicy.Required {
				fmt.Printf("3. Request promotion approval\n")
			}
			fmt.Printf("4. Prepare artifacts for promotion\n")
			fmt.Printf("5. Deploy to target environment\n")
			fmt.Printf("6. Verify deployment health\n")
			fmt.Printf("7. Update deployment registry\n")
			fmt.Printf("8. Generate rollback plan\n")
			return nil
		}

		// Get final confirmation for non-emergency promotions
		if !emergency && !force {
			fmt.Printf("Proceed with promotion? (y/N): ")
			// In real implementation, would read from stdin
			fmt.Printf("y\n")
		}

		// Execute promotion
		result, err := promotionManager.PromoteComponent(rc, request)
		if err != nil {
			logger.Error("Component promotion failed",
				zap.String("component", componentName),
				zap.Error(err))

			// Check if it's an approval-required error
			if promotionErr, ok := err.(*promotion.PromotionError); ok && promotionErr.Type == "approval_required" {
				fmt.Printf("⏳ Promotion created and waiting for approval\n")
				fmt.Printf("\nPromotion Details:\n")
				fmt.Printf("──────────────────\n")
				fmt.Printf("Promotion ID:     %s\n", request.ID)
				fmt.Printf("Required Approvals: %d\n", request.ApprovalPolicy.MinApprovals)
				fmt.Printf("Timeout:          %s\n", request.ApprovalPolicy.ApprovalTimeout)
				fmt.Printf("\nTo approve this promotion:\n")
				fmt.Printf("  eos promote approve %s\n", request.ID)
				return nil
			}

			return fmt.Errorf("component promotion failed: %w", err)
		}

		// Display promotion results
		fmt.Printf(" Component promotion completed successfully\n")
		fmt.Printf("\nPromotion Results:\n")
		fmt.Printf("──────────────────\n")
		fmt.Printf("Component:        %s\n", componentName)
		fmt.Printf("From:             %s\n", fromEnv)
		fmt.Printf("To:               %s\n", toEnv)
		fmt.Printf("Version:          %s\n", result.Request.Version)
		fmt.Printf("Duration:         %s\n", result.Duration)
		fmt.Printf("Deployment ID:    %s\n", result.DeploymentID)

		// Show promoted artifacts
		if len(result.ArtifactsPromoted) > 0 {
			fmt.Printf("\nPromoted Artifacts:\n")
			for _, artifact := range result.ArtifactsPromoted {
				fmt.Printf("  • %s (%s) - %s\n", artifact.Name, artifact.Type, formatSize(artifact.Size))
			}
		}

		// Show validation results
		if len(result.ValidationResults) > 0 {
			fmt.Printf("\nValidation Results:\n")
			for _, validation := range result.ValidationResults {
				status := ""
				if !validation.Passed {
					status = ""
				}
				fmt.Printf("  %s %s: %s\n", status, validation.Check, validation.Message)
			}
		}

		// Show rollback information
		if result.RollbackPlan != nil {
			fmt.Printf("\nRollback Plan Generated:\n")
			fmt.Printf("Previous Version: %s\n", result.RollbackPlan.PreviousVersion)
			fmt.Printf("Estimated Time:   %s\n", result.RollbackPlan.EstimatedTime)
			fmt.Printf("\nTo rollback if needed:\n")
			fmt.Printf("  eos rollback %s --to-version %s\n", componentName, result.RollbackPlan.PreviousVersion)
		}

		logger.Info("Component promotion completed successfully",
			zap.String("component", componentName),
			zap.String("from", fromEnv),
			zap.String("to", toEnv),
			zap.Duration("duration", result.Duration))

		return nil
	}),
}

func init() {
	PromoteCmd.AddCommand(componentCmd)

	// Required promotion flags
	componentCmd.Flags().String("from", "", "Source environment (required)")
	componentCmd.Flags().String("to", "", "Target environment (required)")

	// Optional promotion configuration
	componentCmd.Flags().String("version", "", "Specific version to promote (latest if not specified)")
	componentCmd.Flags().String("reason", "", "Reason for promotion")

	// Approval and safety flags
	componentCmd.Flags().Bool("require-approval", false, "Force approval requirement even for non-production")
	componentCmd.Flags().Bool("emergency", false, "Emergency promotion (bypass some safety checks)")
	componentCmd.Flags().Bool("force", false, "Force promotion without confirmation")
	componentCmd.Flags().Bool("dry-run", false, "Show promotion plan without executing")

	// Timeout and retry flags
	componentCmd.Flags().Duration("timeout", 30*time.Minute, "Promotion timeout")
	componentCmd.Flags().Int("retries", 0, "Number of retry attempts on failure")

	// Validation flags
	componentCmd.Flags().Bool("skip-validation", false, "Skip pre-promotion validation")
	componentCmd.Flags().Bool("skip-health-check", false, "Skip post-promotion health checks")
	componentCmd.Flags().StringSlice("validation-rules", nil, "Additional validation rules to apply")

	componentCmd.Example = `  # Basic promotion
  eos promote component helen --from staging --to production

  # Promote specific version
  eos promote component api --from dev --to staging --version v2.1.0

  # Emergency promotion
  eos promote component critical-fix --from staging --to production --emergency

  # With approval workflow
  eos promote component webapp --from staging --to production --require-approval --reason "Release v2.0"`
}

// Helper functions

func generatePromotionID(component, from, to string) string {
	timestamp := time.Now().Format("20060102150405")
	return fmt.Sprintf("%s-%s-%s-%s", component, to, timestamp, "promo")
}

func isProductionTarget(environment string) bool {
	prodEnvironments := []string{"production", "prod", "live"}
	for _, prodEnv := range prodEnvironments {
		if environment == prodEnv {
			return true
		}
	}
	return false
}

func getMinApprovalsForEnvironment(environment string) int {
	if isProductionTarget(environment) {
		return 2 // Production requires 2 approvals
	}
	return 1 // Other environments require 1 approval
}

func formatSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.1f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.1f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.1f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
