// cmd/list/delphi_pipeline_prompts.go
package list

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/pipeline"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var delphiPromptsValidateCmd = &cobra.Command{
	Use:   "delphi-prompts-validate [prompt-name]",
	Aliases: []string{"delphi-prompts", "validate-delphi-prompts"},
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
  eos list delphi-prompts-validate
  eos list delphi-prompts-validate cybersobar
  eos list delphi-prompts-validate delphi-notify-long --verbose
  eos list delphi-prompts-validate custom-prompt --fix`,
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

		verbose, _ := cmd.Flags().GetBool("verbose")
		fix, _ := cmd.Flags().GetBool("fix")

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

func init() {
	delphiPromptsValidateCmd.Flags().BoolP("verbose", "v", false, "Show detailed validation information")
	delphiPromptsValidateCmd.Flags().Bool("fix", false, "Attempt to fix common issues automatically")

	ListCmd.AddCommand(delphiPromptsValidateCmd)
}
