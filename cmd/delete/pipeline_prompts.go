// cmd/delete/delete-pipeline-prompts.go
package delete

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/pipeline"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewDeleteCmd creates the delete command
func NewDeleteCmd() *cobra.Command {
	var (
		force  bool
		backup bool
	)

	cmd := &cobra.Command{
		Use:   "delete <prompt-name>",
		Short: "Delete a system prompt",
		Long: `Delete a system prompt file from the assets/system-prompts directory.

The prompt name should be specified without the .txt extension.

By default, the command will ask for confirmation before deleting the prompt.
Use --force to skip the confirmation prompt.

A backup of the deleted file can be created before deletion.

Examples:
  eos delphi prompts delete my-custom-prompt
  eos delphi prompts delete old-prompt --force
  eos delphi prompts delete temp-prompt --backup --force`,
		Args: cobra.ExactArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			prompts, err := ListSystemPrompts()
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
			promptName := args[0]

			logger.Info(" Deleting system prompt",
				zap.String("prompt_name", promptName))

			promptsDir, err := GetSystemPromptsDir()
			if err != nil {
				return err
			}

			// Add .txt extension if not present
			filename := promptName
			if !strings.HasSuffix(filename, ".txt") {
				filename += ".txt"
			}

			promptPath := filepath.Join(promptsDir, filename)

			// Check if prompt exists
			if !pipeline.FileExists(promptPath) {
				return fmt.Errorf("system prompt not found: %s", promptName)
			}

			// Get file info before deletion
			stat, err := os.Stat(promptPath)
			if err != nil {
				return fmt.Errorf("failed to get file info: %w", err)
			}

			logger.Info(" Prompt to delete",
				zap.String("name", promptName),
				zap.String("path", promptPath),
				zap.String("size", pipeline.FormatFileSize(stat.Size())),
				zap.String("modified", stat.ModTime().Format("2006-01-02 15:04:05")))

			// Check if this is a core system prompt
			corePrompts := []string{"cybersobar", "delphi-notify-long", "delphi-notify-short"}
			isCore := false
			for _, core := range corePrompts {
				if promptName == core {
					isCore = true
					break
				}
			}

			if isCore {
				logger.Warn("Warning: This is a core system prompt",
					zap.String("prompt_name", promptName),
					zap.String("warning", "Deleting core prompts may affect Delphi functionality"))
			}

			// Confirmation prompt (unless force is used)
			if !force {
				logger.Info("🤔 Confirmation required",
					zap.String("prompt_name", promptName),
					zap.Bool("is_core", isCore))

				if isCore {
					logger.Info("This is a core system prompt. Deletion may affect Delphi functionality.")
				}

				logger.Info(" Type 'yes' to confirm deletion:")

				var response string
				if _, err := fmt.Scanln(&response); err != nil {
					return fmt.Errorf("failed to read confirmation: %w", err)
				}

				if strings.ToLower(strings.TrimSpace(response)) != "yes" {
					logger.Info(" Deletion cancelled")
					return nil
				}
			}

			// Create backup if requested
			if backup {
				backupPath := promptPath + ".deleted." + time.Now().Format("20060102-150405")
				logger.Info(" Creating backup before deletion",
					zap.String("backup_path", backupPath))

				content, err := os.ReadFile(promptPath)
				if err != nil {
					return fmt.Errorf("failed to read file for backup: %w", err)
				}

				if err := os.WriteFile(backupPath, content, stat.Mode()); err != nil {
					return fmt.Errorf("failed to create backup: %w", err)
				}

				logger.Info(" Backup created successfully",
					zap.String("backup_path", backupPath))
			}

			// Delete the file
			logger.Info(" Deleting prompt file",
				zap.String("file_path", promptPath))

			if err := os.Remove(promptPath); err != nil {
				return fmt.Errorf("failed to delete prompt file: %w", err)
			}

			// Verify deletion
			if pipeline.FileExists(promptPath) {
				return fmt.Errorf("failed to delete prompt file: file still exists")
			}

			logger.Info(" Prompt deleted successfully",
				zap.String("name", promptName),
				zap.String("path", promptPath),
				zap.String("size_deleted", pipeline.FormatFileSize(stat.Size())),
				zap.Bool("backup_created", backup))

			if isCore {
				logger.Warn("Core system prompt deleted",
					zap.String("prompt_name", promptName),
					zap.String("recommendation", "Consider recreating this prompt to maintain Delphi functionality"))
			}

			return nil
		}),
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation prompt")
	cmd.Flags().BoolVarP(&backup, "backup", "b", false, "Create backup before deletion")

	return cmd
}
