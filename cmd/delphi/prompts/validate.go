// cmd/delphi/prompts/validate.go
package prompts

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ValidationResult contains the results of prompt validation
type ValidationResult struct {
	PromptName   string
	IsValid      bool
	Errors       []string
	Warnings     []string
	Suggestions  []string
	Statistics   PromptStatistics
}

// PromptStatistics contains statistical information about a prompt
type PromptStatistics struct {
	CharacterCount   int
	WordCount        int
	LineCount        int
	ParagraphCount   int
	HasTitle         bool
	HasInstructions  bool
	HasExamples      bool
	ComplexityScore  int
}

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

			if len(args) == 0 {
				// Validate all prompts
				logger.Info("🔍 Validating all system prompts")
				return validateAllPrompts(rc, verbose, fix)
			} else {
				// Validate specific prompt
				promptName := args[0]
				logger.Info("🔍 Validating system prompt",
					zap.String("prompt_name", promptName))
				return validateSinglePrompt(rc, promptName, verbose, fix)
			}
		}),
	}

	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show detailed validation information")
	cmd.Flags().BoolVar(&fix, "fix", false, "Attempt to fix common issues automatically")

	return cmd
}

// validateAllPrompts validates all system prompts
func validateAllPrompts(rc *eos_io.RuntimeContext, verbose, fix bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	prompts, err := ListSystemPrompts()
	if err != nil {
		return fmt.Errorf("failed to list system prompts: %w", err)
	}

	if len(prompts) == 0 {
		logger.Info("ℹ️ No system prompts found to validate")
		return nil
	}

	logger.Info("📊 Starting validation of all prompts",
		zap.Int("total_prompts", len(prompts)))

	var results []ValidationResult
	validCount := 0
	issueCount := 0

	for _, prompt := range prompts {
		result, err := validatePrompt(prompt.Name, verbose)
		if err != nil {
			logger.Error("❌ Failed to validate prompt",
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
			logger.Info("✅ Prompt validation passed",
				zap.String("prompt_name", result.PromptName))
		} else {
			logger.Warn("⚠️ Prompt validation issues found",
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
				logger.Error("❌ Failed to apply fixes",
					zap.String("prompt_name", result.PromptName),
					zap.Error(err))
			} else {
				logger.Info("🔧 Applied automatic fixes",
					zap.String("prompt_name", result.PromptName))
			}
		}
	}

	// Display summary
	logger.Info("📋 Validation summary",
		zap.Int("total_prompts", len(results)),
		zap.Int("valid_prompts", validCount),
		zap.Int("prompts_with_issues", issueCount),
		zap.Float64("success_rate", float64(validCount)/float64(len(results))*100))

	return nil
}

// validateSinglePrompt validates a single system prompt
func validateSinglePrompt(rc *eos_io.RuntimeContext, promptName string, verbose, fix bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	result, err := validatePrompt(promptName, verbose)
	if err != nil {
		return err
	}

	// Display results
	if result.IsValid {
		logger.Info("✅ Prompt validation passed",
			zap.String("prompt_name", result.PromptName))
	} else {
		logger.Warn("⚠️ Prompt validation issues found",
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
		logger.Info("🔧 Applied automatic fixes",
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
	if !fileExists(promptPath) {
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
	if strings.Contains(contentLower, "analyze") { score += 2 }
	if strings.Contains(contentLower, "identify") { score += 2 }
	if strings.Contains(contentLower, "evaluate") { score += 2 }
	if strings.Contains(contentLower, "recommend") { score += 2 }
	if strings.Contains(contentLower, "security") { score += 1 }
	if strings.Contains(contentLower, "alert") { score += 1 }
	if strings.Contains(contentLower, "incident") { score += 1 }
	if strings.Contains(contentLower, "threat") { score += 1 }

	// Points for structure
	if strings.Contains(content, "#") { score += 1 }
	if strings.Contains(content, "1.") || strings.Contains(content, "- ") { score += 1 }

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
	logger.Info("📊 Prompt statistics",
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
		logger.Error("❌ Error: " + err)
	}

	// Display warnings
	for _, warn := range result.Warnings {
		logger.Warn("⚠️ Warning: " + warn)
	}

	// Display suggestions
	for _, suggestion := range result.Suggestions {
		logger.Info("💡 Suggestion: " + suggestion)
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
		logger.Info("🔧 Fixed double spaces")
	}

	// Normalize line endings
	if strings.Contains(contentStr, "\r\n") {
		contentStr = strings.ReplaceAll(contentStr, "\r\n", "\n")
		modified = true
		logger.Info("🔧 Normalized line endings")
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
		logger.Info("🔧 Trimmed trailing whitespace")
	}

	// Write back if modified
	if modified {
		return os.WriteFile(promptPath, []byte(contentStr), 0644)
	}

	return nil
}