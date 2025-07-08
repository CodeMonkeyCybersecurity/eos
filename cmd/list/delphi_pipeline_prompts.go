// cmd/delphi/prompts/list.go
package list

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/pipeline"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewValidateCmd creates the validate command
func NewValidateCmd() *cobra.Command {
	var (
		verbose bool
		fix     bool
	)

	cmd := &cobra.Command{
		Use:   "validate [prompt-name]",
		Short: "Validate system prompt formatting and content",
		Long: `Validate system prompt files for proper formatting, content quality, and adherence to best practices.

If no prompt name is specified, all prompts in the directory will be validated.

The validation checks include:
- File format and encoding
- Content length and structure
- Prompt clarity and instructions
- Best practices compliance
- Potential issues and improvements

Examples:
  eos delphi prompts validate
  eos delphi prompts validate cybersobar
  eos delphi prompts validate delphi-notify-long --verbose
  eos delphi prompts validate custom-prompt --fix`,
		Args: cobra.MaximumNArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			prompts, err := pipeline.ListSystemPrompts()
			if err != nil {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			var names []string
			for _, prompt := range prompts {
				names = append(names, prompt.Name)
			}
			return names, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

			if len(args) == 0 {
				// Validate all prompts
				logger.Info(" Validating all system prompts")
				return pipeline.ValidateAllPrompts(rc, verbose, fix)
			} else {
				// Validate specific prompt
				promptName := args[0]
				logger.Info(" Validating system prompt",
					zap.String("prompt_name", promptName))
				return pipeline.ValidateSinglePrompt(rc, promptName, verbose, fix)
			}
		}),
	}

	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show detailed validation information")
	cmd.Flags().BoolVar(&fix, "fix", false, "Attempt to fix common issues automatically")

	return cmd
}
