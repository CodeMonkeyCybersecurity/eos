package promote

import (
	"github.com/spf13/cobra"
)

// PromoteCmd represents the promote command
var PromoteCmd = &cobra.Command{
	Use:   "promote",
	Short: "Promote applications between environments",
	Long: `Promote applications and components between environments in the Eos CI/CD system.

The promotion system enables safe deployment promotion across environments (dev → staging → production)
with comprehensive validation, approval workflows, and rollback capabilities. All promotions follow
the assessment→intervention→evaluation pattern to ensure reliable cross-environment deployments.

Promotion operations include:
- Individual component promotion with version tracking
- Stack-based batch promotions with dependency management
- Approval workflows with configurable policies
- Comprehensive validation and health checking
- Automated rollback plan generation
- Promotion history and audit trails

Available Commands:
  component    Promote a specific component between environments
  stack        Promote multiple components as a stack
  approve      Approve pending promotion requests
  history      View promotion history and audit trails
  rollback     Rollback a previous promotion

Examples:
  # Promote component from staging to production
  eos promote component helen --from staging --to production

  # Promote entire stack with approval
  eos promote stack webapp --from staging --to production --require-approval

  # View promotion history
  eos promote history helen --environment production

  # Approve pending promotion
  eos promote approve helen-prod-20240113

Security and Compliance:
- All promotions require proper environment access
- Production promotions enforce approval workflows
- Comprehensive audit logging for compliance
- Automated rollback plans for risk mitigation`,
	Aliases: []string{"deploy", "release"},
}

func init() {
	// This function will be called by the root command to register this command
}
