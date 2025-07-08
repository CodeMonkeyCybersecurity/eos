// pkg/eos_utils/system_prompts.go

package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi_channels"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ServiceConfiguration represents a service configuration
type ServiceConfiguration struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Status       string   `json:"status"`
	Path         string   `json:"path"`
	WorkerFile   string   `json:"worker_file"`
	ServiceFile  string   `json:"service_file"`
	ConfigFiles  []string `json:"config_files"`
	Dependencies []string `json:"dependencies"`
}

// GetServiceConfigurations returns available service configurations
func GetServiceConfigurations() map[string]ServiceConfiguration {
	return map[string]ServiceConfiguration{
		"delphi-listener": {
			Name:         "delphi-listener",
			Description:  "Delphi event listener service",
			Status:       "active",
			Path:         "/opt/stackstorm/packs/delphi/delphi-listener.py",
			WorkerFile:   "/opt/stackstorm/packs/delphi/delphi-listener.py",
			ServiceFile:  "/etc/systemd/system/delphi-listener.service",
			ConfigFiles:  []string{"/opt/stackstorm/packs/delphi/.env"},
			Dependencies: []string{"python3", "requests", "psycopg2", "python-dotenv"},
		},
		"delphi-agent-enricher": {
			Name:         "delphi-agent-enricher",
			Description:  "Delphi agent enrichment service",
			Status:       "active",
			Path:         "/opt/stackstorm/packs/delphi/delphi-agent-enricher.py",
			WorkerFile:   "/opt/stackstorm/packs/delphi/delphi-agent-enricher.py",
			ServiceFile:  "/etc/systemd/system/delphi-agent-enricher.service",
			ConfigFiles:  []string{"/opt/stackstorm/packs/delphi/.env"},
			Dependencies: []string{"python3", "requests", "psycopg2", "python-dotenv"},
		},
		"llm-worker": {
			Name:         "llm-worker",
			Description:  "LLM processing worker",
			Status:       "active",
			Path:         "/opt/stackstorm/packs/delphi/llm-worker.py",
			WorkerFile:   "/opt/stackstorm/packs/delphi/llm-worker.py",
			ServiceFile:  "/etc/systemd/system/llm-worker.service",
			ConfigFiles:  []string{"/opt/stackstorm/packs/delphi/.env", "/srv/eos/system-prompts/default.txt"},
			Dependencies: []string{"python3", "requests", "psycopg2", "openai", "python-dotenv"},
		},
		"email-structurer": {
			Name:         "email-structurer",
			Description:  "Email structure processing service",
			Status:       "active",
			Path:         "/opt/stackstorm/packs/delphi/email-structurer.py",
			WorkerFile:   "/usr/local/bin/email-structurer.py",
			ServiceFile:  "/etc/systemd/system/email-structurer.service",
			ConfigFiles:  []string{"/opt/stackstorm/packs/delphi/.env"},
			Dependencies: []string{"python3", "psycopg2", "python-dotenv"},
		},
		"prompt-ab-tester": {
			Name:         "prompt-ab-tester",
			Description:  "Prompt A/B testing service",
			Status:       "active",
			Path:         "/opt/stackstorm/packs/delphi/prompt-ab-tester.py",
			WorkerFile:   "/usr/local/bin/prompt-ab-tester.py",
			ServiceFile:  "/etc/systemd/system/prompt-ab-tester.service",
			ConfigFiles:  []string{"/opt/stackstorm/packs/delphi/.env", "/opt/delphi/ab-test-config.json"},
			Dependencies: []string{"python3", "psycopg2", "python-dotenv"},
		},
	}
}

// ServiceWorkerInfo contains information about a service worker
type ServiceWorkerInfo struct {
	ServiceName string
	SourcePath  string
	TargetPath  string
	BackupPath  string
}

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
	// Use /srv as the working directory for prompts and other stateful information
	return "/srv/eos/system-prompts", nil
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

	if !FileExists(promptsDir) {
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

// ListPrompts creates the list command
func ListPrompts() *cobra.Command {
	var detailed bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all available system prompts",
		Long: `List all system prompts available in the /srv/eos/system-prompts directory.

This shows all .txt files in the system prompts directory with metadata including:
- Name and description
- File size and last modified time
- Full file path (with --detailed flag)

Examples:
  eos delphi prompts list
  eos delphi prompts list --detailed`,
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info("Listing system prompts")

			// --- NEW INTEGRATION START ---
			// Ensure the system prompts directory is ready before attempting to list prompts.
			// You might want to make "stanley" configurable via a flag or global config.
			// Default permissions for a directory are 0755, for files 0644.
			err := EnsureSystemPromptsDirectory(
				DefaultSystemPromptsDir,
				"stanley", // Assuming 'stanley' is the user, based on previous context.
				"stanley", // Assuming 'stanley' is the group.
				0644,      // rwx for owner, rx for group and others
				logger,
			)
			if err != nil {
				// This is a critical error, as the directory cannot be prepared.
				return fmt.Errorf("failed to ensure system prompts directory: %w", err)
			}
			// --- NEW INTEGRATION END ---

			prompts, err := ListSystemPrompts()
			if err != nil {
				return fmt.Errorf("failed to list system prompts: %w", err)
			}

			if len(prompts) == 0 {
				logger.Info("No system prompts found")
				return nil
			}

			logger.Info("Available system prompts",
				zap.Int("count", len(prompts)))

			for _, prompt := range prompts {
				if detailed {
					logger.Info("System prompt details",
						zap.String("name", prompt.Name),
						zap.String("description", prompt.Description),
						zap.String("path", prompt.Path),
						zap.Int64("size_bytes", prompt.Size),
						zap.String("modified", prompt.Modified.Format("2006-01-02 15:04:05")))
				} else {
					logger.Info(" "+prompt.Name,
						zap.String("description", prompt.Description),
						zap.String("size", FormatFileSize(prompt.Size)),
						zap.String("modified", FormatRelativeTime(prompt.Modified)))
				}
			}

			return nil
		}),
	}

	cmd.Flags().BoolVarP(&detailed, "detailed", "d", false, "Show detailed information including full paths")
	return cmd
}

// ValidationResult contains the results of prompt validation
type ValidationResult struct {
	PromptName  string
	IsValid     bool
	Errors      []string
	Warnings    []string
	Suggestions []string
	Statistics  PromptStatistics
}

// PromptStatistics contains statistical information about a prompt
type PromptStatistics struct {
	CharacterCount  int
	WordCount       int
	LineCount       int
	ParagraphCount  int
	HasTitle        bool
	HasInstructions bool
	HasExamples     bool
	ComplexityScore int
}

// ValidateAllPrompts validates all system prompts
func ValidateAllPrompts(rc *eos_io.RuntimeContext, verbose, fix bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	prompts, err := ListSystemPrompts()
	if err != nil {
		return fmt.Errorf("failed to list system prompts: %w", err)
	}

	if len(prompts) == 0 {
		logger.Info(" No system prompts found to validate")
		return nil
	}

	logger.Info(" Starting validation of all prompts",
		zap.Int("total_prompts", len(prompts)))

	var results []ValidationResult
	validCount := 0
	issueCount := 0

	for _, prompt := range prompts {
		result, err := validatePrompt(prompt.Name, verbose)
		if err != nil {
			logger.Error(" Failed to validate prompt",
				zap.String("prompt_name", prompt.Name),
				zap.Error(err))
			continue
		}

		results = append(results, result)
		if result.IsValid {
			validCount++
		} else {
			issueCount++
		}

		// Display individual results
		if result.IsValid {
			logger.Info(" Prompt validation passed",
				zap.String("prompt_name", result.PromptName))
		} else {
			logger.Warn("Prompt validation issues found",
				zap.String("prompt_name", result.PromptName),
				zap.Int("errors", len(result.Errors)),
				zap.Int("warnings", len(result.Warnings)))
		}

		if verbose {
			displayValidationDetails(logger, result)
		}

		// Apply fixes if requested
		if fix && !result.IsValid {
			if err := applyFixes(rc, result); err != nil {
				logger.Error(" Failed to apply fixes",
					zap.String("prompt_name", result.PromptName),
					zap.Error(err))
			} else {
				logger.Info(" Applied automatic fixes",
					zap.String("prompt_name", result.PromptName))
			}
		}
	}

	// Display summary
	logger.Info(" Validation summary",
		zap.Int("total_prompts", len(results)),
		zap.Int("valid_prompts", validCount),
		zap.Int("prompts_with_issues", issueCount),
		zap.Float64("success_rate", float64(validCount)/float64(len(results))*100))

	return nil
}

// validateSinglePrompt validates a single system prompt
func ValidateSinglePrompt(rc *eos_io.RuntimeContext, promptName string, verbose, fix bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	result, err := validatePrompt(promptName, verbose)
	if err != nil {
		return err
	}

	// Display results
	if result.IsValid {
		logger.Info(" Prompt validation passed",
			zap.String("prompt_name", result.PromptName))
	} else {
		logger.Warn("Prompt validation issues found",
			zap.String("prompt_name", result.PromptName),
			zap.Int("errors", len(result.Errors)),
			zap.Int("warnings", len(result.Warnings)))
	}

	displayValidationDetails(logger, result)

	// Apply fixes if requested
	if fix && !result.IsValid {
		if err := applyFixes(rc, result); err != nil {
			return fmt.Errorf("failed to apply fixes: %w", err)
		}
		logger.Info(" Applied automatic fixes",
			zap.String("prompt_name", result.PromptName))
	}

	return nil
}

// validatePrompt performs validation on a single prompt
func validatePrompt(promptName string, _ bool) (ValidationResult, error) {
	result := ValidationResult{
		PromptName:  promptName,
		IsValid:     true,
		Errors:      []string{},
		Warnings:    []string{},
		Suggestions: []string{},
	}

	promptsDir, err := GetSystemPromptsDir()
	if err != nil {
		return result, err
	}

	filename := promptName
	if !strings.HasSuffix(filename, ".txt") {
		filename += ".txt"
	}

	promptPath := filepath.Join(promptsDir, filename)
	if !FileExists(promptPath) {
		result.Errors = append(result.Errors, "Prompt file not found")
		result.IsValid = false
		return result, nil
	}

	// Read file content
	content, err := os.ReadFile(promptPath)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to read file: %v", err))
		result.IsValid = false
		return result, nil
	}

	contentStr := string(content)

	// Calculate statistics
	result.Statistics = calculateStatistics(contentStr)

	// Perform validation checks
	performValidationChecks(&result, contentStr)

	// Set overall validity
	result.IsValid = len(result.Errors) == 0

	return result, nil
}

// calculateStatistics calculates statistical information about the prompt
func calculateStatistics(content string) PromptStatistics {
	stats := PromptStatistics{}

	stats.CharacterCount = utf8.RuneCountInString(content)
	stats.LineCount = len(strings.Split(content, "\n"))

	// Count words (simple whitespace split)
	words := strings.Fields(content)
	stats.WordCount = len(words)

	// Count paragraphs (double newlines)
	paragraphs := strings.Split(content, "\n\n")
	stats.ParagraphCount = len(paragraphs)

	// Check for structural elements
	contentLower := strings.ToLower(content)
	stats.HasTitle = strings.Contains(contentLower, "#") ||
		regexp.MustCompile(`^[A-Z][^.!?]*$`).MatchString(strings.Split(content, "\n")[0])
	stats.HasInstructions = strings.Contains(contentLower, "instructions") ||
		strings.Contains(contentLower, "you are") ||
		strings.Contains(contentLower, "your role")
	stats.HasExamples = strings.Contains(contentLower, "example") ||
		strings.Contains(contentLower, "for example")

	// Calculate complexity score (simple heuristic)
	stats.ComplexityScore = calculateComplexityScore(content)

	return stats
}

// calculateComplexityScore calculates a simple complexity score
func calculateComplexityScore(content string) int {
	score := 0
	contentLower := strings.ToLower(content)

	// Points for various elements
	if strings.Contains(contentLower, "analyze") {
		score += 2
	}
	if strings.Contains(contentLower, "identify") {
		score += 2
	}
	if strings.Contains(contentLower, "evaluate") {
		score += 2
	}
	if strings.Contains(contentLower, "recommend") {
		score += 2
	}
	if strings.Contains(contentLower, "security") {
		score += 1
	}
	if strings.Contains(contentLower, "alert") {
		score += 1
	}
	if strings.Contains(contentLower, "incident") {
		score += 1
	}
	if strings.Contains(contentLower, "threat") {
		score += 1
	}

	// Points for structure
	if strings.Contains(content, "#") {
		score += 1
	}
	if strings.Contains(content, "1.") || strings.Contains(content, "- ") {
		score += 1
	}

	return score
}

// performValidationChecks performs various validation checks
func performValidationChecks(result *ValidationResult, content string) {
	// Check minimum length
	if len(content) < 50 {
		result.Errors = append(result.Errors, "Prompt is too short (minimum 50 characters)")
	}

	// Check maximum length
	if len(content) > 10000 {
		result.Warnings = append(result.Warnings, "Prompt is very long (over 10,000 characters)")
	}

	// Check for empty content
	if strings.TrimSpace(content) == "" {
		result.Errors = append(result.Errors, "Prompt content is empty")
	}

	// Check for clear instructions
	contentLower := strings.ToLower(content)
	if !strings.Contains(contentLower, "you are") && !strings.Contains(contentLower, "your role") {
		result.Warnings = append(result.Warnings, "Prompt should clearly define the AI's role")
	}

	// Check for examples or guidance
	if !result.Statistics.HasExamples && result.Statistics.ComplexityScore > 5 {
		result.Suggestions = append(result.Suggestions, "Consider adding examples for complex prompts")
	}

	// Check for security-specific terms (for Delphi prompts)
	securityTerms := []string{"security", "alert", "incident", "threat", "vulnerability"}
	hasSecurityTerms := false
	for _, term := range securityTerms {
		if strings.Contains(contentLower, term) {
			hasSecurityTerms = true
			break
		}
	}

	if !hasSecurityTerms {
		result.Suggestions = append(result.Suggestions, "Consider adding security-specific terminology for Delphi context")
	}

	// Check for proper formatting
	if !strings.Contains(content, "\n") {
		result.Warnings = append(result.Warnings, "Prompt appears to be a single line - consider breaking into paragraphs")
	}

	// Check for spelling/grammar issues (basic)
	if strings.Contains(content, "  ") {
		result.Suggestions = append(result.Suggestions, "Remove double spaces for better formatting")
	}

	// Check for inconsistent line endings
	if strings.Contains(content, "\r\n") && strings.Contains(content, "\n") {
		result.Warnings = append(result.Warnings, "Inconsistent line endings detected")
	}
}

// displayValidationDetails displays detailed validation information
func displayValidationDetails(logger otelzap.LoggerWithCtx, result ValidationResult) {
	// Display statistics
	logger.Info(" Prompt statistics",
		zap.String("prompt_name", result.PromptName),
		zap.Int("characters", result.Statistics.CharacterCount),
		zap.Int("words", result.Statistics.WordCount),
		zap.Int("lines", result.Statistics.LineCount),
		zap.Int("paragraphs", result.Statistics.ParagraphCount),
		zap.Int("complexity_score", result.Statistics.ComplexityScore),
		zap.Bool("has_title", result.Statistics.HasTitle),
		zap.Bool("has_instructions", result.Statistics.HasInstructions),
		zap.Bool("has_examples", result.Statistics.HasExamples))

	// Display errors
	for _, err := range result.Errors {
		logger.Error(" Error: " + err)
	}

	// Display warnings
	for _, warn := range result.Warnings {
		logger.Warn("Warning: " + warn)
	}

	// Display suggestions
	for _, suggestion := range result.Suggestions {
		logger.Info(" Suggestion: " + suggestion)
	}
}

// applyFixes attempts to automatically fix common issues
func applyFixes(rc *eos_io.RuntimeContext, result ValidationResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	promptsDir, err := GetSystemPromptsDir()
	if err != nil {
		return err
	}

	filename := result.PromptName
	if !strings.HasSuffix(filename, ".txt") {
		filename += ".txt"
	}

	promptPath := filepath.Join(promptsDir, filename)

	content, err := os.ReadFile(promptPath)
	if err != nil {
		return err
	}

	contentStr := string(content)
	modified := false

	// Fix double spaces
	if strings.Contains(contentStr, "  ") {
		contentStr = regexp.MustCompile(`\s{2,}`).ReplaceAllString(contentStr, " ")
		modified = true
		logger.Info(" Fixed double spaces")
	}

	// Normalize line endings
	if strings.Contains(contentStr, "\r\n") {
		contentStr = strings.ReplaceAll(contentStr, "\r\n", "\n")
		modified = true
		logger.Info(" Normalized line endings")
	}

	// Trim trailing whitespace
	originalLines := strings.Split(contentStr, "\n")
	var trimmedLines []string
	for _, line := range originalLines {
		trimmedLines = append(trimmedLines, strings.TrimRight(line, " \t"))
	}
	trimmedContent := strings.Join(trimmedLines, "\n")
	if trimmedContent != contentStr {
		contentStr = trimmedContent
		modified = true
		logger.Info(" Trimmed trailing whitespace")
	}

	// Write back if modified
	if modified {
		return os.WriteFile(promptPath, []byte(contentStr), 0644)
	}

	return nil
}

// DefaultSystemPromptsDir is the standard path for system prompts.
const DefaultSystemPromptsDir = "/srv/eos/system-prompts"

// EnsureSystemPromptsDirectory ensures the system prompts directory exists
// and has the specified ownership and permissions.
//
// Arguments:
//
//	dirPath: The full path to the directory (e.g., "/srv/eos/system-prompts").
//	ownerUser: The desired username for the directory owner (e.g., "stanley").
//	ownerGroup: The desired group name for the directory owner (e.g., "stanley").
//	dirPerms: The desired file mode for the directory (e.g., 0755).
//	logger: An otelzap.LoggerWithCtx for logging.
//
// Returns:
//
//	An error if the directory cannot be created, permissions cannot be set,
//	or ownership cannot be changed.
//
// EnsureSystemPromptsDirectory ensures the system prompts directory exists
// and has the specified ownership and permissions.
//
// Arguments:
//
//	dirPath: The full path to the directory (e.g., "/srv/eos/system-prompts").
//	ownerUser: The desired username for the directory owner (e.g., "stanley").
//	ownerGroup: The desired group name for the directory owner (e.g., "stanley").
//	dirPerms: The desired file mode for the directory (e.g., 0755).
//	logger: An otelzap.LoggerWithCtx for logging.
//
// Returns:
//
//	An error if the directory cannot be created, permissions cannot be set,
//	or ownership cannot be changed.
func EnsureSystemPromptsDirectory(
	dirPath string,
	ownerUser string,
	ownerGroup string,
	dirPerms os.FileMode,
	logger otelzap.LoggerWithCtx,
) error {
	logger.Info("Ensuring system prompts directory exists and has correct permissions",
		zap.String("path", dirPath),
		zap.String("owner_user", ownerUser),
		zap.String("owner_group", ownerGroup),
		zap.String("permissions", fmt.Sprintf("%o", dirPerms)),
	)

	// Step 1: Check if the directory exists. If not, create it.
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		logger.Info("System prompts directory does not exist, creating it", zap.String("path", dirPath))
		if err := os.MkdirAll(dirPath, dirPerms); err != nil {
			return fmt.Errorf("failed to create system prompts directory '%s': %w", dirPath, err)
		}
		logger.Info("System prompts directory created", zap.String("path", dirPath))
	} else if err != nil {
		// Other error than not existing (e.g., permissions to stat)
		return fmt.Errorf("failed to stat system prompts directory '%s': %w", dirPath, err)
	}

	// Step 2: Set the correct permissions for the directory.
	// This ensures the initial permissions are correct, or updates them if they're wrong.
	if err := os.Chmod(dirPath, dirPerms); err != nil {
		return fmt.Errorf("failed to set permissions for directory '%s': %w", dirPath, err)
	}
	logger.Debug("Directory permissions set",
		zap.String("path", dirPath),
		zap.String("permissions", fmt.Sprintf("%o", dirPerms)),
	)

	// Step 3: Get UID and GID for the specified ownerUser and ownerGroup.
	usr, err := user.Lookup(ownerUser)
	if err != nil {
		return fmt.Errorf("failed to lookup user '%s': %w", ownerUser, err)
	}
	uid, err := strconv.Atoi(usr.Uid)
	if err != nil {
		return fmt.Errorf("failed to parse UID for user '%s': %w", ownerUser, err)
	}

	grp, err := user.LookupGroup(ownerGroup)
	if err != nil {
		return fmt.Errorf("failed to lookup group '%s': %w", ownerGroup, err)
	}
	gid, err := strconv.Atoi(grp.Gid)
	if err != nil {
		return fmt.Errorf("failed to parse GID for group '%s': %w", ownerGroup, err)
	}

	// Step 4: Set the ownership for the directory.
	if err := os.Chown(dirPath, uid, gid); err != nil {
		return fmt.Errorf("failed to change ownership of directory '%s' to %s:%s: %w", dirPath, ownerUser, ownerGroup, err)
	}
	logger.Info("Directory ownership set",
		zap.String("path", dirPath),
		zap.String("owner", ownerUser),
		zap.String("group", ownerGroup),
	)

	// Step 5: (Optional but recommended) Iterate over existing files and set ownership/permissions.
	// This ensures consistency for any files already placed there manually.
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		logger.Warn("Failed to read directory entries to set file permissions/ownership, continuing", zap.Error(err))
		// Not a fatal error for the directory setup itself, but worth logging.
	} else {
		for _, entry := range entries {
			filePath := filepath.Join(dirPath, entry.Name())
			// Set ownership for files (directories handled by MkdirAll and Chown on dirPath)
			if !entry.IsDir() {
				if err := os.Chown(filePath, uid, gid); err != nil {
					logger.Warn("Failed to change ownership of file, continuing",
						zap.String("file", filePath),
						zap.String("owner", ownerUser),
						zap.String("group", ownerGroup),
						zap.Error(err),
					)
				}
				// Set read permissions for .txt files for the owner and group, others read-only
				if filepath.Ext(filePath) == ".txt" {
					if err := os.Chmod(filePath, 0644); err != nil {
						logger.Warn("Failed to set permissions for file, continuing",
							zap.String("file", filePath),
							zap.String("permissions", "0644"),
							zap.Error(err),
						)
					}
				}
			}
		}
	}

	logger.Info("System prompts directory and its contents ensured successfully", zap.String("path", dirPath))
	return nil
}

// FileExists checks if a file exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// FormatFileSize formats file size in human readable format
func FormatFileSize(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
}

// formatRelativeTime formats time relative to now
func FormatRelativeTime(t time.Time) string {
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

// FormatSizeChange formats the size change between old and new file sizes
func FormatSizeChange(oldSize, newSize int64) string {
	diff := newSize - oldSize
	if diff == 0 {
		return "no change"
	} else if diff > 0 {
		return fmt.Sprintf("+%s", FormatFileSize(diff))
	} else {
		return fmt.Sprintf("-%s", FormatFileSize(-diff))
	}
}

// RunAnalysis analyzes worker configurations without making changes
func RunAnalysis(standardizer *delphi_channels.ChannelStandardizer, outputJSON bool, logger otelzap.LoggerWithCtx) error {
	logger.Info("Analyzing current worker channel configurations")

	infos, err := standardizer.AnalyzeWorkers()
	if err != nil {
		logger.Error("Failed to analyze workers", zap.Error(err))
		return fmt.Errorf("analysis failed: %v", err)
	}

	if outputJSON {
		return outputWorkerAnalysisJSON(infos)
	} else {
		return outputWorkerAnalysisText(infos)
	}
}

// RunStandardization performs channel standardization
func RunStandardization(standardizer *delphi_channels.ChannelStandardizer, outputJSON, dryRun bool, logger otelzap.LoggerWithCtx) error {
	if dryRun {
		logger.Info("Running in dry-run mode - no changes will be made")
	} else {
		logger.Info("Standardizing notification channels")
	}

	result := standardizer.StandardizeAll()

	if outputJSON {
		return outputStandardizationJSON(result)
	} else {
		return outputStandardizationText(result, dryRun)
	}
}

// outputWorkerAnalysisJSON outputs worker analysis in JSON format
func outputWorkerAnalysisJSON(infos []delphi_channels.WorkerChannelInfo) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(map[string]interface{}{
		"analysis":          infos,
		"standard_channels": delphi_channels.StandardChannels,
	})
}

// outputWorkerAnalysisText outputs worker analysis in human-readable format
func outputWorkerAnalysisText(infos []delphi_channels.WorkerChannelInfo) error {
	fmt.Println("Delphi Notification Channel Analysis")
	fmt.Println(strings.Repeat("=", 50))

	correctCount := 0
	for _, info := range infos {
		fmt.Printf("\n%s\n", info.Filename)

		if info.IsCorrect {
			fmt.Println("    Configuration is correct")
			correctCount++
		} else {
			fmt.Println("   Configuration needs fixing")
		}

		if len(info.ListenChannels) > 0 {
			fmt.Printf("   Listen: %s\n", strings.Join(info.ListenChannels, ", "))
		}

		if len(info.NotifyChannels) > 0 {
			fmt.Printf("   Notify: %s\n", strings.Join(info.NotifyChannels, ", "))
		}

		if len(info.Issues) > 0 {
			fmt.Println("    Issues:")
			for _, issue := range info.Issues {
				fmt.Printf("      • %s\n", issue)
			}
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Printf("Summary: %d/%d workers correctly configured\n", correctCount, len(infos))

	if correctCount < len(infos) {
		fmt.Println("\nTo fix issues, run: eos update delphi-notification-channels")
	}

	fmt.Println("\nSTANDARD NOTIFICATION FLOW:")
	for channel, description := range delphi_channels.StandardChannels {
		fmt.Printf("   %-18s → %s\n", channel, description)
	}
	fmt.Println(strings.Repeat("=", 50))

	return nil
}

// outputStandardizationJSON outputs standardization results in JSON format
func outputStandardizationJSON(result *delphi_channels.StandardizationResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// outputStandardizationText outputs standardization results in human-readable format
func outputStandardizationText(result *delphi_channels.StandardizationResult, dryRun bool) error {
	if dryRun {
		fmt.Println("Notification Channel Standardization (DRY RUN)")
	} else {
		fmt.Println("Notification Channel Standardization")
	}
	fmt.Println(strings.Repeat("=", 50))

	// Show changes
	if len(result.Changes) > 0 {
		if dryRun {
			fmt.Printf("\nCHANGES THAT WOULD BE MADE (%d):\n", len(result.Changes))
		} else {
			fmt.Printf("\nCHANGES MADE (%d):\n", len(result.Changes))
		}

		changesByFile := groupChangesByFile(result.Changes)
		for file, changes := range changesByFile {
			fmt.Printf("   %s:\n", file)
			for _, change := range changes {
				fmt.Printf("      %s: %s → %s\n",
					getChangeTypeEmoji(change.Type),
					change.OldValue,
					change.NewValue)
			}
		}
	}

	// Show files updated
	if len(result.FilesUpdated) > 0 {
		if dryRun {
			fmt.Printf("\nFILES THAT WOULD BE UPDATED (%d):\n", len(result.FilesUpdated))
		} else {
			fmt.Printf("\nFILES UPDATED (%d):\n", len(result.FilesUpdated))
		}
		for _, file := range result.FilesUpdated {
			fmt.Printf("   ✓ %s\n", file)
		}
	}

	// Show files skipped
	if len(result.FilesSkipped) > 0 {
		fmt.Printf("\nFILES SKIPPED (%d):\n", len(result.FilesSkipped))
		for _, file := range result.FilesSkipped {
			fmt.Printf("   • %s\n", file)
		}
	}

	// Show backups created
	if len(result.BackupsCreated) > 0 && !dryRun {
		fmt.Printf("\nBACKUPS CREATED (%d):\n", len(result.BackupsCreated))
		for _, backup := range result.BackupsCreated {
			fmt.Printf("   %s\n", backup)
		}
	}

	// Show errors
	if len(result.Errors) > 0 {
		fmt.Printf("\nERRORS (%d):\n", len(result.Errors))
		for _, err := range result.Errors {
			fmt.Printf("   • %s\n", err)
		}
	}

	// Summary
	fmt.Println("\n" + strings.Repeat("=", 50))

	if result.Success {
		if len(result.Changes) == 0 {
			fmt.Println("All workers already use correct notification channels!")
		} else if dryRun {
			fmt.Printf("Analysis complete: %d changes needed\n", len(result.Changes))
			fmt.Println("Run without --dry-run to apply changes")
		} else {
			fmt.Printf("Standardization complete: %d changes applied\n", len(result.Changes))
		}
	} else {
		fmt.Println("Standardization completed with errors")
		if !dryRun {
			os.Exit(1)
		}
	}

	if !dryRun && len(result.Changes) == 0 {
		fmt.Println("\nSTANDARD NOTIFICATION FLOW:")
		for channel, description := range delphi_channels.StandardChannels {
			fmt.Printf("   %-18s → %s\n", channel, description)
		}
	}

	fmt.Println(strings.Repeat("=", 50))
	return nil
}

// Helper functions
func groupChangesByFile(changes []delphi_channels.ChannelChange) map[string][]delphi_channels.ChannelChange {
	grouped := make(map[string][]delphi_channels.ChannelChange)
	for _, change := range changes {
		filename := change.File
		if strings.Contains(filename, "/") {
			// Extract just the filename from the path
			parts := strings.Split(filename, "/")
			filename = parts[len(parts)-1]
		}
		grouped[filename] = append(grouped[filename], change)
	}
	return grouped
}

func getChangeTypeEmoji(changeType string) string {
	switch changeType {
	case "listen_channel":
		return "📥"
	case "notify_channel":
		return "📤"
	case "pg_notify":
		return "🔔"
	case "listen_statement":
		return "👂"
	default:
		return ""
	}
}
