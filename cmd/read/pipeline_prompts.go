// cmd/read/read-pipeline-prompts.go
package read

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/pipeline"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
var (
	pipelinePromptsShowPath bool
)

// pipelinePromptsCmd displays the content of a system prompt
var pipelinePromptsCmd = &cobra.Command{
	Use:   "prompts <prompt-name>",
	Short: "Display the content of a system prompt",
	Long: `Display the content of a system prompt file.

The prompt name should be specified without the .txt extension.

Available prompts:
- cybersobar: ISOBAR framework for structured security communications
- delphi-notify-long: Detailed user-friendly explanations
- delphi-notify-short: Concise alert explanations

Examples:
  eos read prompts cybersobar
  eos read prompts delphi-notify-long --show-path`,
	Args: cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		prompts, err := pipeline.ListSystemPrompts()
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		var names []string
		for _, p := range prompts {
			names = append(names, p.Name)
		}
		return names, cobra.ShellCompDirectiveNoFileComp
	},
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		promptName := args[0]

		logger.Info(" Reading system prompt",
			zap.String("prompt_name", promptName))

		promptsDir, err := pipeline.GetSystemPromptsDir()
		if err != nil {
			return err
		}

		// Add .txt extension if not present
		filename := promptName
		if !strings.HasSuffix(filename, ".txt") {
			filename += ".txt"
		}

		promptPath := filepath.Join(promptsDir, filename)
		if !shared.FileExists(promptPath) {
			return fmt.Errorf("system prompt not found: %s", promptName)
		}

		content, err := os.ReadFile(promptPath)
		if err != nil {
			return fmt.Errorf("failed to read prompt file: %w", err)
		}

		if pipelinePromptsShowPath {
			logger.Info(" Prompt file location",
				zap.String("path", promptPath))
		}

		// Log prompt metadata
		stat, err := os.Stat(promptPath)
		if err == nil {
			logger.Info(" Prompt information",
				zap.String("name", promptName),
				zap.String("description", pipeline.GetPromptDescription(promptName)),
				zap.String("size", pipeline.FormatFileSize(stat.Size())),
				zap.String("modified", stat.ModTime().Format("2006-01-02 15:04:05")))
		}

		// Display content with proper formatting
		logger.Info(" Prompt content:")
		logger.Info("---")

		// Split content into lines for better logging
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			logger.Info(line)
		}

		logger.Info("---")
		logger.Info(" Prompt displayed successfully",
			zap.Int("lines", len(lines)),
			zap.Int("characters", len(content)))

		return nil
	}),
}

func init() {
	pipelinePromptsCmd.Flags().BoolVarP(&pipelinePromptsShowPath, "show-path", "p", false, "Show the full file path")
}
