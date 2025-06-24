// cmd/delphi/prompts/prompts.go
package prompts

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PromptsCmd represents the 'prompts' command for managing system prompts
var PromptsCmd = &cobra.Command{
	Use:   "prompts",
	Short: "Manage Delphi system prompts for AI processing",
	Long: `The 'prompts' command provides functionality to manage system prompts used by the Delphi alerting pipeline.

System prompts define how AI models process and respond to security alerts. This includes:
- cybersobar: ISOBAR framework for structured security communications
- delphi-notify-long: Detailed user-friendly explanations for non-technical users
- delphi-notify-short: Concise alert explanations with risk indicators

Available operations:
- list: Show all available system prompts
- read: Display content of a specific prompt
- create: Create a new system prompt
- update: Modify an existing system prompt
- delete: Remove a system prompt
- validate: Check prompt formatting and requirements`,
	Aliases: []string{"prompt"},
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Prompts command called without subcommand",
			zap.String("command", "eos delphi prompts"),
		)
		shared.SafeHelp(cmd)
		return nil
	}),
}

func init() {
	// Add subcommands for prompt management
	PromptsCmd.AddCommand(NewListCmd())
	PromptsCmd.AddCommand(NewReadCmd())
	PromptsCmd.AddCommand(NewCreateCmd())
	PromptsCmd.AddCommand(NewUpdateCmd())
	PromptsCmd.AddCommand(NewDeleteCmd())
	PromptsCmd.AddCommand(NewValidateCmd())
}