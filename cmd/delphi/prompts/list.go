// cmd/delphi/prompts/list.go
package prompts

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PromptInfo contains metadata about a system prompt
type PromptInfo struct {
	Name        string
	Path        string
	Size        int64
	Modified    time.Time
	Description string
}

// GetSystemPromptsDir returns the system prompts directory path
func GetSystemPromptsDir() (string, error) {
	eosRoot := os.Getenv("EOS_ROOT")
	if eosRoot == "" {
		if pwd, err := os.Getwd(); err == nil && fileExists(filepath.Join(pwd, "assets")) {
			eosRoot = pwd
		} else {
			return "", fmt.Errorf("EOS_ROOT environment variable not set and cannot auto-detect Eos directory")
		}
	}
	return filepath.Join(eosRoot, "assets", "system-prompts"), nil
}

// GetPromptDescription returns a description for known prompts
func GetPromptDescription(name string) string {
	descriptions := map[string]string{
		"cybersobar":          "ISOBAR framework for structured security communications",
		"delphi-notify-long":  "Detailed user-friendly explanations for non-technical users",
		"delphi-notify-short": "Concise alert explanations with risk indicators",
	}
	if desc, exists := descriptions[name]; exists {
		return desc
	}
	return "Custom system prompt"
}

// ListSystemPrompts returns information about all system prompts
func ListSystemPrompts() ([]PromptInfo, error) {
	promptsDir, err := GetSystemPromptsDir()
	if err != nil {
		return nil, err
	}

	if !fileExists(promptsDir) {
		return nil, fmt.Errorf("system prompts directory not found: %s", promptsDir)
	}

	entries, err := os.ReadDir(promptsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read prompts directory: %w", err)
	}

	var prompts []PromptInfo
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".txt") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		name := strings.TrimSuffix(entry.Name(), ".txt")
		promptInfo := PromptInfo{
			Name:        name,
			Path:        filepath.Join(promptsDir, entry.Name()),
			Size:        info.Size(),
			Modified:    info.ModTime(),
			Description: GetPromptDescription(name),
		}
		prompts = append(prompts, promptInfo)
	}

	return prompts, nil
}

// NewListCmd creates the list command
func NewListCmd() *cobra.Command {
	var detailed bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all available system prompts",
		Long: `List all system prompts available in the assets/system-prompts directory.

This shows all .txt files in the system prompts directory with metadata including:
- Name and description
- File size and last modified time
- Full file path (with --detailed flag)

Examples:
  eos delphi prompts list
  eos delphi prompts list --detailed`,
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info(" Listing system prompts")

			prompts, err := ListSystemPrompts()
			if err != nil {
				return fmt.Errorf("failed to list system prompts: %w", err)
			}

			if len(prompts) == 0 {
				logger.Info(" No system prompts found")
				return nil
			}

			logger.Info(" Available system prompts",
				zap.Int("count", len(prompts)))

			for _, prompt := range prompts {
				if detailed {
					logger.Info(" System prompt details",
						zap.String("name", prompt.Name),
						zap.String("description", prompt.Description),
						zap.String("path", prompt.Path),
						zap.Int64("size_bytes", prompt.Size),
						zap.String("modified", prompt.Modified.Format("2006-01-02 15:04:05")))
				} else {
					logger.Info(" "+prompt.Name,
						zap.String("description", prompt.Description),
						zap.String("size", formatFileSize(prompt.Size)),
						zap.String("modified", formatRelativeTime(prompt.Modified)))
				}
			}

			return nil
		}),
	}

	cmd.Flags().BoolVarP(&detailed, "detailed", "d", false, "Show detailed information including full paths")
	return cmd
}

// formatFileSize formats file size in human readable format
func formatFileSize(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
}

// formatRelativeTime formats time relative to now
func formatRelativeTime(t time.Time) string {
	now := time.Now()
	diff := now.Sub(t)

	if diff < time.Hour {
		return fmt.Sprintf("%d minutes ago", int(diff.Minutes()))
	}
	if diff < 24*time.Hour {
		return fmt.Sprintf("%d hours ago", int(diff.Hours()))
	}
	if diff < 30*24*time.Hour {
		return fmt.Sprintf("%d days ago", int(diff.Hours()/24))
	}
	return t.Format("2006-01-02")
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
