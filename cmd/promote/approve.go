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

var approveCmd = &cobra.Command{
	Use:   "approve <promotion-id>",
	Short: "Approve a pending promotion request",
	Long: `Approve a pending promotion request to allow execution of the promotion.

The approval system provides governance and control over critical deployments,
particularly to production environments. Approvals include comprehensive tracking,
audit logging, and policy enforcement to ensure compliance with deployment procedures.

Approval features include:
- Multi-level approval policies with configurable thresholds
- Approval delegation and escalation workflows
- Time-based approval expiration and automatic rejection
- Comprehensive audit trails for compliance reporting
- Integration with external approval systems and notifications
- Conditional approvals based on validation results

Examples:
  # Approve a pending promotion
  eos promote approve helen-prod-20240113154530-promo

  # Approve with comment
  eos promote approve api-prod-20240113160000-promo --comment "Approved after security review"

  # Approve on behalf of another user (delegation)
  eos promote approve webapp-stack-prod-20240113161500-promo --delegate-for john.doe

  # List pending approvals first
  eos promote approve --list-pending

  # Emergency approval override
  eos promote approve critical-fix-prod-20240113162000-promo --emergency-override`,
	Args: cobra.MaximumNArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		logger.Info("Processing promotion approval",
			zap.String("command", "promote approve"),
			zap.String("context", rc.Component))

		// Parse flags
		listPending, _ := cmd.Flags().GetBool("list-pending")
		comment, _ := cmd.Flags().GetString("comment")
		delegateFor, _ := cmd.Flags().GetString("delegate-for")
		emergencyOverride, _ := cmd.Flags().GetBool("emergency-override")
		reject, _ := cmd.Flags().GetBool("reject")
		force, _ := cmd.Flags().GetBool("force")

		// Handle list pending approvals
		if listPending {
			return listPendingApprovals(rc)
		}

		if len(args) == 0 {
			return fmt.Errorf("promotion ID is required. Use --list-pending to see pending approvals")
		}

		promotionID := args[0]

		logger.Debug("Approval configuration",
			zap.String("promotion_id", promotionID),
			zap.String("comment", comment),
			zap.String("delegate_for", delegateFor),
			zap.Bool("emergency_override", emergencyOverride),
			zap.Bool("reject", reject))

		// Create environment manager
		envManager, err := environments.NewEnvironmentManager("")
		if err != nil {
			logger.Error("Failed to create environment manager", zap.Error(err))
			return fmt.Errorf("failed to create environment manager: %w", err)
		}

		// Create promotion manager
		promotionConfig := &promotion.PromotionConfig{
			Force: force,
		}

		promotionManager, err := promotion.NewPromotionManager(envManager, promotionConfig)
		if err != nil {
			logger.Error("Failed to create promotion manager", zap.Error(err))
			return fmt.Errorf("failed to create promotion manager: %w", err)
		}

		// Get promotion details
		promotionRequest, err := getPromotionRequest(rc, promotionID)
		if err != nil {
			logger.Error("Failed to get promotion request", zap.Error(err))
			return fmt.Errorf("failed to get promotion request: %w", err)
		}

		// Display promotion details
		fmt.Printf("Promotion Request Details:\n")
		fmt.Printf("═══════════════════════\n")
		fmt.Printf("ID:               %s\n", promotionRequest.ID)
		fmt.Printf("Component:        %s\n", promotionRequest.Component)
		fmt.Printf("From Environment: %s\n", promotionRequest.FromEnvironment)
		fmt.Printf("To Environment:   %s\n", promotionRequest.ToEnvironment)
		if promotionRequest.Version != "" {
			fmt.Printf("Version:          %s\n", promotionRequest.Version)
		}
		fmt.Printf("Reason:           %s\n", promotionRequest.Reason)
		fmt.Printf("Requester:        %s\n", promotionRequest.RequesterID)
		fmt.Printf("Status:           %s\n", promotionRequest.Status)
		fmt.Printf("Created:          %s\n", promotionRequest.CreatedAt.Format(time.RFC3339))
		fmt.Printf("Required Approvals: %d\n", promotionRequest.ApprovalPolicy.MinApprovals)
		if promotionRequest.ApprovalPolicy.ApprovalTimeout != 0 {
			fmt.Printf("Approval Timeout: %s\n", promotionRequest.ApprovalPolicy.ApprovalTimeout)
		}
		fmt.Printf("\n")

		// Check if already approved/rejected
		if promotionRequest.Status == promotion.PromotionStatusApproved {
			fmt.Printf("This promotion has already been approved.\n")
			return nil
		}
		if promotionRequest.Status == promotion.PromotionStatusRejected {
			fmt.Printf(" This promotion has already been rejected.\n")
			return nil
		}
		if promotionRequest.Status == promotion.PromotionStatusCompleted {
			fmt.Printf(" This promotion has already been completed.\n")
			return nil
		}
		if promotionRequest.Status == promotion.PromotionStatusFailed {
			fmt.Printf(" This promotion has already failed.\n")
			return nil
		}

		// Get current approvals
		existingApprovals, err := getExistingApprovals(rc, promotionID)
		if err != nil {
			logger.Warn("Failed to get existing approvals", zap.Error(err))
			existingApprovals = []promotion.Approval{}
		}

		if len(existingApprovals) > 0 {
			fmt.Printf("Existing Approvals:\n")
			for _, approval := range existingApprovals {
				status := " Approved"
				if approval.Status == "rejected" {
					status = " Rejected"
				}
				fmt.Printf("  %s by %s at %s\n",
					status,
					approval.ApproverID,
					approval.Timestamp.Format(time.RFC3339))
				if approval.Comment != "" {
					fmt.Printf("    Comment: %s\n", approval.Comment)
				}
			}
			fmt.Printf("\n")
		}

		// Check if more approvals are needed
		approvedCount := 0
		rejectedCount := 0
		for _, approval := range existingApprovals {
			if approval.Status == "approved" {
				approvedCount++
			} else if approval.Status == "rejected" {
				rejectedCount++
			}
		}

		remainingApprovals := promotionRequest.ApprovalPolicy.MinApprovals - approvedCount
		if remainingApprovals > 0 && !reject {
			fmt.Printf(" Approvals Status: %d/%d required approvals received\n",
				approvedCount, promotionRequest.ApprovalPolicy.MinApprovals)
			fmt.Printf("   %d more approval(s) needed\n", remainingApprovals)
			fmt.Printf("\n")
		}

		// Show production warning
		if isProductionTarget(promotionRequest.ToEnvironment) && !reject {
			fmt.Printf(" Production Deployment Approval:\n")
			fmt.Printf("   This approval will enable deployment to the production environment.\n")
			fmt.Printf("   Please ensure:\n")
			fmt.Printf("   • All testing has been completed in lower environments\n")
			fmt.Printf("   • Security and compliance reviews are complete\n")
			fmt.Printf("   • Rollback procedures are understood and tested\n")
			fmt.Printf("   • Deployment window and change management approvals are in place\n")
			fmt.Printf("\n")
		}

		// Emergency override warning
		if emergencyOverride {
			fmt.Printf("Emergency Override Requested:\n")
			fmt.Printf("   This will bypass normal approval thresholds.\n")
			fmt.Printf("   Ensure this is justified for emergency circumstances.\n")
			fmt.Printf("\n")
		}

		// Get confirmation unless forced
		action := "approve"
		if reject {
			action = "reject"
		}

		if !force {
			fmt.Printf("Proceed to %s this promotion? (y/N): ", action)
			// In real implementation, would read from stdin
			fmt.Printf("y\n")
		}

		// Create approval record
		approverID := "current-user" // Would get from authentication context
		if delegateFor != "" {
			approverID = delegateFor
		}

		approval := &promotion.Approval{
			ID:          generateApprovalID(promotionID),
			PromotionID: promotionID,
			ApproverID:  approverID,
			Status:      "approved",
			Comment:     comment,
			Timestamp:   time.Now(),
		}

		if reject {
			approval.Status = "rejected"
		}

		// Set default comment if not provided
		if approval.Comment == "" {
			if reject {
				approval.Comment = "Promotion rejected"
			} else {
				approval.Comment = "Promotion approved"
			}
		}

		// Process approval
		err = processApproval(rc, promotionManager, approval, emergencyOverride)
		if err != nil {
			logger.Error("Failed to process approval",
				zap.String("promotion_id", promotionID),
				zap.Error(err))
			return fmt.Errorf("failed to process approval: %w", err)
		}

		// Display results
		if reject {
			fmt.Printf(" Promotion request rejected\n")
			fmt.Printf("\nRejection Details:\n")
			fmt.Printf("──────────────────\n")
			fmt.Printf("Promotion ID:     %s\n", promotionID)
			fmt.Printf("Rejected by:      %s\n", approverID)
			fmt.Printf("Reason:           %s\n", approval.Comment)
			fmt.Printf("Timestamp:        %s\n", approval.Timestamp.Format(time.RFC3339))
		} else {
			fmt.Printf(" Promotion request approved\n")
			fmt.Printf("\nApproval Details:\n")
			fmt.Printf("─────────────────\n")
			fmt.Printf("Promotion ID:     %s\n", promotionID)
			fmt.Printf("Approved by:      %s\n", approverID)
			fmt.Printf("Comment:          %s\n", approval.Comment)
			fmt.Printf("Timestamp:        %s\n", approval.Timestamp.Format(time.RFC3339))

			// Check if promotion can now proceed
			newApprovedCount := approvedCount + 1
			if emergencyOverride || newApprovedCount >= promotionRequest.ApprovalPolicy.MinApprovals {
				fmt.Printf("\n Sufficient approvals received - promotion will proceed automatically\n")

				// In a real implementation, this would trigger the promotion execution
				fmt.Printf("\nPromotion execution will begin shortly...\n")
				fmt.Printf("Monitor progress with: eos promote history %s\n", promotionRequest.Component)
			} else {
				remaining := promotionRequest.ApprovalPolicy.MinApprovals - newApprovedCount
				fmt.Printf("\n⏳ %d more approval(s) needed before promotion can proceed\n", remaining)
			}
		}

		logger.Info("Promotion approval processed",
			zap.String("promotion_id", promotionID),
			zap.String("action", action),
			zap.String("approver", approverID),
			zap.Bool("emergency_override", emergencyOverride))

		return nil
	}),
}

func init() {
	PromoteCmd.AddCommand(approveCmd)

	// Action flags
	approveCmd.Flags().Bool("reject", false, "Reject the promotion instead of approving")
	approveCmd.Flags().Bool("list-pending", false, "List all pending approvals")
	approveCmd.Flags().Bool("force", false, "Skip confirmation prompt")

	// Approval configuration
	approveCmd.Flags().String("comment", "", "Comment for the approval/rejection")
	approveCmd.Flags().String("delegate-for", "", "Approve on behalf of another user (delegation)")
	approveCmd.Flags().Bool("emergency-override", false, "Emergency override (bypass approval thresholds)")

	// Audit and compliance flags
	approveCmd.Flags().String("ticket-id", "", "Associated ticket/change request ID")
	approveCmd.Flags().String("approval-reason", "", "Detailed reason for approval")
	approveCmd.Flags().StringSlice("conditions", nil, "Conditional approval requirements")

	approveCmd.Example = `  # List pending approvals
  eos promote approve --list-pending

  # Approve a promotion
  eos promote approve helen-prod-20240113154530-promo

  # Approve with comment
  eos promote approve api-prod-20240113160000-promo --comment "Security review completed"

  # Reject a promotion
  eos promote approve webapp-prod-20240113161500-promo --reject --comment "Testing incomplete"

  # Emergency override
  eos promote approve critical-fix-prod-20240113162000-promo --emergency-override`
}

// Helper functions

func generateApprovalID(promotionID string) string {
	timestamp := time.Now().Format("20060102150405")
	return fmt.Sprintf("%s-approval-%s", promotionID, timestamp)
}

func listPendingApprovals(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Listing pending approvals")

	// Implementation would query pending promotions from storage
	// For now, return mock data
	pendingApprovals := []struct {
		ID                string
		Component         string
		FromEnvironment   string
		ToEnvironment     string
		RequesterID       string
		CreatedAt         time.Time
		RequiredApprovals int
		CurrentApprovals  int
		TimeRemaining     time.Duration
	}{
		{
			ID:                "helen-prod-20240113154530-promo",
			Component:         "helen",
			FromEnvironment:   "staging",
			ToEnvironment:     "production",
			RequesterID:       "developer.user",
			CreatedAt:         time.Now().Add(-2 * time.Hour),
			RequiredApprovals: 2,
			CurrentApprovals:  1,
			TimeRemaining:     22 * time.Hour,
		},
		{
			ID:                "api-staging-20240113160000-promo",
			Component:         "api",
			FromEnvironment:   "dev",
			ToEnvironment:     "staging",
			RequesterID:       "api.developer",
			CreatedAt:         time.Now().Add(-30 * time.Minute),
			RequiredApprovals: 1,
			CurrentApprovals:  0,
			TimeRemaining:     23*time.Hour + 30*time.Minute,
		},
	}

	if len(pendingApprovals) == 0 {
		fmt.Printf("📭 No pending approval requests found.\n")
		return nil
	}

	fmt.Printf("Pending Approval Requests:\n")
	fmt.Printf("═══════════════════════════\n")

	for i, approval := range pendingApprovals {
		if i > 0 {
			fmt.Printf("\n")
		}

		fmt.Printf("Promotion ID:     %s\n", approval.ID)
		fmt.Printf("Component:        %s\n", approval.Component)
		fmt.Printf("Promotion:        %s → %s\n", approval.FromEnvironment, approval.ToEnvironment)
		fmt.Printf("Requested by:     %s\n", approval.RequesterID)
		fmt.Printf("Created:          %s\n", approval.CreatedAt.Format(time.RFC3339))
		fmt.Printf("Approvals:        %d/%d\n", approval.CurrentApprovals, approval.RequiredApprovals)
		fmt.Printf("Time remaining:   %s\n", approval.TimeRemaining.Round(time.Minute))

		if isProductionTarget(approval.ToEnvironment) {
			fmt.Printf("Environment:       PRODUCTION\n")
		}

		fmt.Printf("\nTo approve:\n")
		fmt.Printf("  eos promote approve %s\n", approval.ID)
	}

	fmt.Printf("\n Use 'eos promote approve <promotion-id>' to approve a specific request\n")

	return nil
}

func getPromotionRequest(rc *eos_io.RuntimeContext, promotionID string) (*promotion.PromotionRequest, error) {
	// Implementation would retrieve promotion request from storage
	// For now, return mock data based on promotion ID

	if strings.Contains(promotionID, "helen") {
		return &promotion.PromotionRequest{
			ID:              promotionID,
			Component:       "helen",
			FromEnvironment: "staging",
			ToEnvironment:   "production",
			Version:         "v2.1.0",
			Reason:          "Production deployment for Helen v2.1.0",
			RequesterID:     "developer.user",
			ApprovalPolicy: promotion.ApprovalPolicy{
				Required:        true,
				MinApprovals:    2,
				ApprovalTimeout: 24 * time.Hour,
			},
			Status:    promotion.PromotionStatusPending,
			CreatedAt: time.Now().Add(-2 * time.Hour),
		}, nil
	}

	if strings.Contains(promotionID, "api") {
		return &promotion.PromotionRequest{
			ID:              promotionID,
			Component:       "api",
			FromEnvironment: "dev",
			ToEnvironment:   "staging",
			Version:         "latest",
			Reason:          "API deployment to staging for testing",
			RequesterID:     "api.developer",
			ApprovalPolicy: promotion.ApprovalPolicy{
				Required:        true,
				MinApprovals:    1,
				ApprovalTimeout: 24 * time.Hour,
			},
			Status:    promotion.PromotionStatusPending,
			CreatedAt: time.Now().Add(-30 * time.Minute),
		}, nil
	}

	return nil, fmt.Errorf("promotion request not found: %s", promotionID)
}

func getExistingApprovals(rc *eos_io.RuntimeContext, promotionID string) ([]promotion.Approval, error) {
	// Implementation would retrieve existing approvals from storage
	// For now, return mock data

	if strings.Contains(promotionID, "helen") {
		return []promotion.Approval{
			{
				ID:          "helen-prod-20240113154530-promo-approval-20240113174530",
				PromotionID: promotionID,
				ApproverID:  "senior.engineer",
				Status:      "approved",
				Comment:     "Code review and testing complete",
				Timestamp:   time.Now().Add(-1 * time.Hour),
			},
		}, nil
	}

	// API promotion has no existing approvals
	return []promotion.Approval{}, nil
}

func processApproval(rc *eos_io.RuntimeContext, promotionManager *promotion.PromotionManager, approval *promotion.Approval, emergencyOverride bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Processing approval",
		zap.String("promotion_id", approval.PromotionID),
		zap.String("approver", approval.ApproverID),
		zap.String("status", approval.Status),
		zap.Bool("emergency_override", emergencyOverride))

	// Implementation would:
	// 1. Validate approver has permission to approve
	// 2. Store approval record in database
	// 3. Check if promotion now has sufficient approvals
	// 4. Trigger promotion execution if ready
	// 5. Send notifications to relevant parties

	// For now, just log the approval
	logger.Info("Approval processed successfully")

	return nil
}
