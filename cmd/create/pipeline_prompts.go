// cmd/create/create-pipeline-prompts.go
package create

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/pipeline"
	eosuser "github.com/CodeMonkeyCybersecurity/eos/pkg/user"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	pipelinePromptFromFile    string
	pipelinePromptInteractive bool
	pipelinePromptDescription string
)

// createPipelinePromptsCmd creates a new system prompt
var createPipelinePromptsCmd = &cobra.Command{
	Use:   "create <prompt-name>",
	Short: "Create a new system prompt",
	Long: `Create a new system prompt file in the /srv/eos/system-prompts directory.

The prompt name should be specified without the .txt extension.

You can create prompts in several ways:
1. Interactive mode: Enter content directly in the terminal
2. From file: Copy content from an existing file
3. Template: Create from a predefined template

Examples:
  eos delphi prompts create my-custom-prompt --interactive
  eos delphi prompts create security-alert --from-file /path/to/template.txt
  eos delphi prompts create incident-response --description "Incident response prompt"`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		promptName := args[0]

		// Get system user (handles sudo properly)
		systemUser, err := eosuser.GetSystemUser(rc)
		if err != nil {
			logger.Error("Failed to get system user", zap.Error(err))
			return fmt.Errorf("failed to get system user: %w", err)
		}

		// Convert UID to integer
		uid, err := strconv.Atoi(systemUser.Uid)
		if err != nil {
			logger.Error("Failed to convert UID", zap.String("uid", systemUser.Uid), zap.Error(err))
			return fmt.Errorf("failed to convert UID: %w", err)
		}

		// Convert GID to integer
		gid, err := strconv.Atoi(systemUser.Gid)
		if err != nil {
			logger.Error("Failed to convert GID", zap.String("gid", systemUser.Gid), zap.Error(err))
			return fmt.Errorf("failed to convert GID: %w", err)
		}

		promptsDir := "/srv/eos/system-prompts"
		promptPath := filepath.Join(promptsDir, promptName+".txt")

		// Check if prompt already exists
		if _, err := os.Stat(promptPath); err == nil {
			logger.Error("Prompt already exists", zap.String("path", promptPath))
			return fmt.Errorf("prompt '%s' already exists at %s", promptName, promptPath)
		}

		// Ensure prompts directory exists
		if err := os.MkdirAll(promptsDir, 0755); err != nil {
			logger.Error("Failed to create prompts directory", zap.String("dir", promptsDir), zap.Error(err))
			return fmt.Errorf("failed to create prompts directory: %w", err)
		}

		var content string

		// Determine content source
		switch {
		case pipelinePromptFromFile != "":
			// Read content from file
			data, err := os.ReadFile(pipelinePromptFromFile)
			if err != nil {
				logger.Error("Failed to read source file", zap.String("file", pipelinePromptFromFile), zap.Error(err))
				return fmt.Errorf("failed to read source file: %w", err)
			}
			content = string(data)
			logger.Info("Read prompt content from file", zap.String("source", pipelinePromptFromFile))

		case pipelinePromptInteractive:
			// Interactive mode
			logger.Info("terminal prompt: Enter prompt content (press Ctrl+D when done):")
			fmt.Println("Enter prompt content (press Ctrl+D when done):")

			scanner := bufio.NewScanner(os.Stdin)
			var lines []string
			for scanner.Scan() {
				lines = append(lines, scanner.Text())
			}
			if err := scanner.Err(); err != nil {
				logger.Error("Failed to read user input", zap.Error(err))
				return fmt.Errorf("failed to read user input: %w", err)
			}
			content = strings.Join(lines, "\n")

		default:
			// Use template
			content = pipeline.CreatePromptTemplate(rc, promptName, pipelinePromptDescription)
			logger.Info("Created prompt from template", zap.String("name", promptName))
		}

		// Write the prompt file
		if err := os.WriteFile(promptPath, []byte(content), 0644); err != nil {
			logger.Error("Failed to write prompt file", zap.String("path", promptPath), zap.Error(err))
			return fmt.Errorf("failed to write prompt file: %w", err)
		}

		// Change ownership to the actual user
		if err := os.Chown(promptPath, uid, gid); err != nil {
			logger.Error("Failed to set ownership", zap.String("path", promptPath), zap.Error(err))
			return fmt.Errorf("failed to set ownership: %w", err)
		}

		logger.Info("Successfully created prompt", zap.String("name", promptName), zap.String("path", promptPath))
		fmt.Printf("Successfully created prompt '%s' at %s\n", promptName, promptPath)

		// TODO: Check if the prompts directory is already mounted to Delphi containers
		// This functionality needs to be implemented in the pipeline package
		// mounted, err := pipeline.IsPromptsDirectoryMounted(rc)
		// if err != nil {
		// 	logger.Warn("Failed to check if prompts directory is mounted", zap.Error(err))
		// } else if !mounted {
		// 	fmt.Println("\nNote: The prompts directory is not currently mounted to Delphi containers.")
		// 	fmt.Println("Run 'eos update delphi services' to mount the prompts directory.")
		// }

		return nil
	}),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// Validate flags
		if pipelinePromptFromFile != "" && pipelinePromptInteractive {
			return fmt.Errorf("cannot use both --from-file and --interactive flags")
		}
		return nil
	},
}

func init() {
	createPipelinePromptsCmd.Flags().StringVar(&pipelinePromptFromFile, "from-file", "", "Copy content from an existing file")
	createPipelinePromptsCmd.Flags().BoolVar(&pipelinePromptInteractive, "interactive", false, "Enter content interactively")
	createPipelinePromptsCmd.Flags().StringVar(&pipelinePromptDescription, "description", "", "Brief description of the prompt (used in template)")
}

// Helper functions have been migrated to:
// - pkg/user/system.go (GetSystemUser)
// - pkg/pipeline/prompts.go (CreatePromptTemplate, IsPromptsDirectoryMounted)
// - pkg/shared/strings/case.go (TitleCase)