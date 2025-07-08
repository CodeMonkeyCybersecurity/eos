// cmd/delphi/prompts/update.go
package update

import (
	"bufio"
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

// NewUpdateCmd creates the update command
func NewUpdateCmd() *cobra.Command {
	var (
		fromFile    string
		interactive bool
		backup      bool
		appendMode  bool
	)

	cmd := &cobra.Command{
		Use:   "update <prompt-name>",
		Short: "Update an existing system prompt",
		Long: `Update an existing system prompt file in the assets/system-prompts directory.

The prompt name should be specified without the .txt extension.

You can update prompts in several ways:
1. Interactive mode: Edit content directly in the terminal
2. From file: Replace content from an existing file
3. Append mode: Add content to the existing prompt

By default, a backup of the original file is created before updating.

Examples:
  eos delphi prompts update cybersobar --interactive
  eos delphi prompts update delphi-notify-long --from-file /path/to/new-content.txt
  eos delphi prompts update security-alert --append --interactive
  eos delphi prompts update incident-response --no-backup --from-file template.txt`,
		Args: cobra.ExactArgs(1),
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
			promptName := args[0]

			logger.Info(" Updating system prompt",
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

			// Check if prompt exists
			if !pipeline.FileExists(promptPath) {
				return fmt.Errorf("system prompt not found: %s", promptName)
			}

			// Get original file info
			originalStat, err := os.Stat(promptPath)
			if err != nil {
				return fmt.Errorf("failed to get file info: %w", err)
			}

			logger.Info(" Current prompt information",
				zap.String("name", promptName),
				zap.String("path", promptPath),
				zap.String("size", pipeline.FormatFileSize(originalStat.Size())),
				zap.String("modified", originalStat.ModTime().Format("2006-01-02 15:04:05")))

			// Create backup if requested
			if backup {
				backupPath := promptPath + ".backup." + time.Now().Format("20060102-150405")
				logger.Info(" Creating backup",
					zap.String("backup_path", backupPath))

				originalContent, err := os.ReadFile(promptPath)
				if err != nil {
					return fmt.Errorf("failed to read original file for backup: %w", err)
				}

				if err := os.WriteFile(backupPath, originalContent, originalStat.Mode()); err != nil {
					return fmt.Errorf("failed to create backup: %w", err)
				}

				logger.Info(" Backup created successfully",
					zap.String("backup_path", backupPath))
			}

			var newContent string

			if fromFile != "" {
				// Read content from file
				logger.Info(" Reading content from file",
					zap.String("source_file", fromFile))

				contentBytes, err := os.ReadFile(fromFile)
				if err != nil {
					return fmt.Errorf("failed to read source file: %w", err)
				}
				newContent = string(contentBytes)

				logger.Info(" Content loaded from file",
					zap.String("size", pipeline.FormatFileSize(int64(len(newContent)))))
			} else if interactive {
				// Interactive mode
				logger.Info(" Entering interactive mode")

				if appendMode {
					// Read existing content first
					existingContent, err := os.ReadFile(promptPath)
					if err != nil {
						return fmt.Errorf("failed to read existing content: %w", err)
					}

					logger.Info(" Current content:")
					logger.Info("---")
					existingLines := strings.Split(string(existingContent), "\n")
					for i, line := range existingLines {
						logger.Info(fmt.Sprintf("%3d: %s", i+1, line))
					}
					logger.Info("---")
					logger.Info(" Enter additional content to append (press Ctrl+D when finished):")

					var lines []string
					scanner := bufio.NewScanner(os.Stdin)
					for scanner.Scan() {
						lines = append(lines, scanner.Text())
					}

					if err := scanner.Err(); err != nil {
						return fmt.Errorf("error reading input: %w", err)
					}

					additionalContent := strings.Join(lines, "\n")
					newContent = string(existingContent)
					if !strings.HasSuffix(newContent, "\n") && additionalContent != "" {
						newContent += "\n"
					}
					newContent += additionalContent

					logger.Info(" Content appended interactively",
						zap.Int("new_lines", len(lines)),
						zap.Int("total_lines", len(strings.Split(newContent, "\n"))))
				} else {
					// Replace mode
					existingContent, err := os.ReadFile(promptPath)
					if err != nil {
						return fmt.Errorf("failed to read existing content: %w", err)
					}

					logger.Info(" Current content:")
					logger.Info("---")
					existingLines := strings.Split(string(existingContent), "\n")
					for i, line := range existingLines {
						logger.Info(fmt.Sprintf("%3d: %s", i+1, line))
					}
					logger.Info("---")
					logger.Info(" Enter new content (press Ctrl+D when finished):")

					var lines []string
					scanner := bufio.NewScanner(os.Stdin)
					for scanner.Scan() {
						lines = append(lines, scanner.Text())
					}

					if err := scanner.Err(); err != nil {
						return fmt.Errorf("error reading input: %w", err)
					}

					newContent = strings.Join(lines, "\n")
					logger.Info(" Content entered interactively",
						zap.Int("lines", len(lines)),
						zap.String("size", pipeline.FormatFileSize(int64(len(newContent)))))
				}
			} else {
				return fmt.Errorf("must specify either --interactive or --from-file")
			}

			// Handle append mode for file input
			if appendMode && fromFile != "" {
				existingContent, err := os.ReadFile(promptPath)
				if err != nil {
					return fmt.Errorf("failed to read existing content: %w", err)
				}

				combinedContent := string(existingContent)
				if !strings.HasSuffix(combinedContent, "\n") && newContent != "" {
					combinedContent += "\n"
				}
				combinedContent += newContent
				newContent = combinedContent

				logger.Info(" Content appended from file",
					zap.String("mode", "append"),
					zap.String("total_size", pipeline.FormatFileSize(int64(len(newContent)))))
			}

			// Write the updated prompt file
			logger.Info(" Writing updated prompt file",
				zap.String("file_path", promptPath),
				zap.String("new_size", pipeline.FormatFileSize(int64(len(newContent)))))

			if err := os.WriteFile(promptPath, []byte(newContent), originalStat.Mode()); err != nil {
				return fmt.Errorf("failed to write updated prompt file: %w", err)
			}

			// Verify file was updated successfully
			if stat, err := os.Stat(promptPath); err == nil {
				logger.Info(" Prompt updated successfully",
					zap.String("name", promptName),
					zap.String("path", promptPath),
					zap.String("old_size", pipeline.FormatFileSize(originalStat.Size())),
					zap.String("new_size", pipeline.FormatFileSize(stat.Size())),
					zap.String("size_change", pipeline.FormatSizeChange(originalStat.Size(), stat.Size())),
					zap.String("modified", stat.ModTime().Format("2006-01-02 15:04:05")))
			}

			return nil
		}),
	}

	cmd.Flags().StringVarP(&fromFile, "from-file", "f", "", "Update prompt from existing file")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Update content interactively")
	cmd.Flags().BoolVar(&backup, "backup", true, "Create backup before updating (default: true)")
	cmd.Flags().BoolVar(&backup, "no-backup", false, "Skip creating backup")
	cmd.Flags().BoolVarP(&appendMode, "append", "a", false, "Append to existing content instead of replacing")

	// Handle the no-backup flag
	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if cmd.Flag("no-backup").Changed {
			backup = false
		}
		return nil
	}

	return cmd
}
