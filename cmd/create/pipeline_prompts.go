// cmd/create/create-pipeline-prompts.go
package create

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/pipeline" // Import the new package
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewCreateCmd creates the create command
func NewCreateCmd() *cobra.Command {
	var (
		fromFile    string
		interactive bool
		description string
	)

	cmd := &cobra.Command{
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

			logger.Info("Creating new system prompt",
				zap.String("prompt_name", promptName))

			// Validate prompt name
			if err := validatePromptName(promptName); err != nil {
				return err
			}

			// The GetSystemPromptsDir function remains the same,
			// but we now use the eos_utils.DefaultSystemPromptsDir constant
			// and ensure the directory's existence and permissions.
			promptsDir, err := GetSystemPromptsDir()
			if err != nil {
				return err
			}

			// --- NEW INTEGRATION START ---
			// Ensure the system prompts directory exists and has correct permissions/ownership.
			// Assuming 'stanley' is the user and group that needs ownership, based on previous context.
			// You might want to make these owner details configurable in a real-world application.
			err = pipeline.EnsureSystemPromptsDirectory(
				pipeline.DefaultSystemPromptsDir,
				"stanley", // User for ownership
				"stanley", // Group for ownership
				0755,      // Directory permissions: rwx for owner, rx for group and others
				logger,
			)
			if err != nil {
				// This is a critical error, as the directory cannot be prepared.
				return fmt.Errorf("failed to ensure system prompts directory: %w", err)
			}
			// --- NEW INTEGRATION END ---

			// Add .txt extension if not present
			filename := promptName
			if !strings.HasSuffix(filename, ".txt") {
				filename += ".txt"
			}

			promptPath := filepath.Join(promptsDir, filename)

			// Check if prompt already exists
			if pipeline.FileExists(promptPath) {
				return fmt.Errorf("system prompt already exists: %s", promptName)
			}

			logger.Info("Output file determined",
				zap.String("file_path", promptPath),
				zap.String("directory", promptsDir),
				zap.Bool("exists", false))

			var content string

			if fromFile != "" {
				// Read content from file
				logger.Info("Reading content from file",
					zap.String("source_file", fromFile))

				contentBytes, err := os.ReadFile(fromFile)
				if err != nil {
					return fmt.Errorf("failed to read source file: %w", err)
				}
				content = string(contentBytes)

				logger.Info("Content loaded from file",
					zap.String("size", pipeline.FormatFileSize(int64(len(content)))))
			} else if interactive {
				// Interactive mode
				logger.Info("Entering interactive mode")
				logger.Info("Enter prompt content (press Ctrl+D when finished):")

				var lines []string
				scanner := bufio.NewScanner(os.Stdin)
				for scanner.Scan() {
					lines = append(lines, scanner.Text())
				}

				if err := scanner.Err(); err != nil {
					return fmt.Errorf("error reading input: %w", err)
				}

				content = strings.Join(lines, "\n")
				logger.Info("Content entered interactively",
					zap.Int("lines", len(lines)),
					zap.String("size", pipeline.FormatFileSize(int64(len(content)))))
			} else {
				// Create empty template
				content = createPromptTemplate(promptName, description)
				logger.Info("Created template content",
					zap.String("template_type", "default"))
			}

			// Write the prompt file
			logger.Info("Writing prompt file",
				zap.String("file_path", promptPath),
				zap.String("size", pipeline.FormatFileSize(int64(len(content)))))

			// Set file permissions to 0644 (rw-r--r--)
			if err := os.WriteFile(promptPath, []byte(content), 0644); err != nil {
				return fmt.Errorf("failed to write prompt file: %w", err)
			}

			// After writing the file, ensure its ownership is correct.
			// This is important because os.WriteFile might create the file with root ownership
			// if the command is run with sudo, but the prompt's intended user (stanley) might
			// need to read/write it later.
			usr, err := user.Lookup("stanley") // Look up the 'stanley' user
			if err != nil {
				logger.Warn("Failed to lookup 'stanley' user for chown, leaving file ownership as is.", zap.Error(err))
			} else {
				uid, _ := strconv.Atoi(usr.Uid)
				gid, _ := strconv.Atoi(usr.Gid)
				if err := os.Chown(promptPath, uid, gid); err != nil {
					logger.Warn("Failed to change ownership of new prompt file, leaving as is.",
						zap.String("file", promptPath),
						zap.Error(err),
					)
				} else {
					logger.Info("New prompt file ownership set",
						zap.String("file", promptPath),
						zap.String("owner", "stanley"),
						zap.String("group", "stanley"),
					)
				}
			}

			// Verify file was created successfully
			if stat, err := os.Stat(promptPath); err == nil {
				logger.Info("Prompt created successfully",
					zap.String("name", promptName),
					zap.String("path", promptPath),
					zap.String("size", pipeline.FormatFileSize(stat.Size())),
					zap.String("permissions", stat.Mode().String()))
			}

			return nil
		}),
	}

	cmd.Flags().StringVarP(&fromFile, "from-file", "f", "", "Create prompt from existing file")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Enter content interactively")
	cmd.Flags().StringVarP(&description, "description", "d", "", "Description for the prompt template")

	return cmd
}

// validatePromptName validates the prompt name
func validatePromptName(name string) error {
	if name == "" {
		return fmt.Errorf("prompt name cannot be empty")
	}

	// Check for invalid characters
	invalidChars := []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|"}
	for _, char := range invalidChars {
		if strings.Contains(name, char) {
			return fmt.Errorf("prompt name contains invalid character: %s", char)
		}
	}

	// Check for reserved names
	reserved := []string{".", "..", "con", "prn", "aux", "nul"}
	for _, res := range reserved {
		if strings.EqualFold(name, res) {
			return fmt.Errorf("prompt name is reserved: %s", name)
		}
	}

	return nil
}

// createPromptTemplate creates a basic template for a new prompt
func createPromptTemplate(name, description string) string {
	if description == "" {
		description = "Custom system prompt for Delphi AI processing"
	}

	return fmt.Sprintf(`# %s

## Description
%s

## Instructions
You are an AI assistant analyzing security alerts and incidents. Your role is to:

1. Analyze the provided security data
2. Identify potential threats and risks
3. Provide clear, actionable recommendations
4. Communicate findings in a user-friendly manner

## Response Format
- Be concise but comprehensive
- Use clear, non-technical language when possible
- Highlight critical information
- Provide specific next steps

## Context
This prompt is used by the Delphi alerting pipeline to process security events and generate user-friendly notifications.

---
Please provide your analysis based on the security data provided.
`, titleCase(strings.ReplaceAll(name, "-", " ")), description)
}

// titleCase converts a string to title case using proper Unicode handling
func titleCase(s string) string {
	if s == "" {
		return s
	}

	words := strings.Fields(s)
	for i, word := range words {
		if word == "" {
			continue
		}

		runes := []rune(word)
		runes[0] = unicode.ToUpper(runes[0])
		for j := 1; j < len(runes); j++ {
			runes[j] = unicode.ToLower(runes[j])
		}
		words[i] = string(runes)
	}

	return strings.Join(words, " ")
}
