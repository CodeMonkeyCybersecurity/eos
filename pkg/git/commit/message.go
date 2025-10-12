// Package commit provides Git commit functionality
package commit

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/git"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GenerateSmartMessage generates an intelligent commit message based on changes.
// It follows the Assess → Intervene → Evaluate pattern.
func GenerateSmartMessage(rc *eos_io.RuntimeContext, status *git.GitStatus) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Get diff stats
	diffOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "git",
		Args:    []string{"diff", "--stat", "--cached"},
	})
	if err != nil {
		logger.Debug("Failed to get diff stats, using simple message", zap.Error(err))
		return GenerateSimpleMessage(status), nil
	}

	// INTERVENE - Analyze changes
	analysis := AnalyzeChanges(status, diffOutput)

	// EVALUATE - Generate message based on analysis
	message := BuildCommitMessage(analysis)

	// Add standard footer
	message += "\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>"

	logger.Debug("Generated commit message", zap.String("message", message))
	return message, nil
}

// AnalyzeChanges analyzes Git changes to determine commit message content
func AnalyzeChanges(status *git.GitStatus, diffStats string) *git.ChangeAnalysis {
	analysis := &git.ChangeAnalysis{
		FileTypes: make(map[string]int),
		Packages:  []string{},
	}

	allFiles := append(append(status.Staged, status.Modified...), status.Untracked...)
	analysis.TotalFiles = len(allFiles)

	packageMap := make(map[string]bool)

	for _, file := range allFiles {
		// Analyze file types
		ext := strings.ToLower(filepath.Ext(file))
		if ext == "" {
			ext = "no-ext"
		}
		analysis.FileTypes[ext]++

		// Check for special file types
		base := strings.ToLower(filepath.Base(file))
		if strings.Contains(base, "test") || strings.HasSuffix(base, "_test.go") {
			analysis.HasTests = true
		}
		if strings.Contains(base, "readme") || strings.Contains(base, ".md") {
			analysis.HasDocs = true
		}
		if strings.Contains(base, "config") || strings.Contains(base, ".yaml") || strings.Contains(base, ".json") {
			analysis.HasConfig = true
		}

		// Extract package names from Go files
		if ext == ".go" && strings.Contains(file, "/") {
			parts := strings.Split(file, "/")
			if len(parts) >= 2 && (parts[0] == "pkg" || parts[0] == "cmd") {
				packageName := parts[1]
				if !packageMap[packageName] {
					packageMap[packageName] = true
					analysis.Packages = append(analysis.Packages, packageName)
				}
			}
		}
	}

	// Parse diff stats for line counts
	lines := strings.Split(diffStats, "\n")
	for _, line := range lines {
		if strings.Contains(line, "insertion") || strings.Contains(line, "deletion") {
			// Parse line like "5 files changed, 123 insertions(+), 45 deletions(-)"
			parts := strings.Fields(line)
			for i, part := range parts {
				if strings.Contains(part, "insertion") && i > 0 {
					_, _ = fmt.Sscanf(parts[i-1], "%d", &analysis.LinesAdded)
				}
				if strings.Contains(part, "deletion") && i > 0 {
					_, _ = fmt.Sscanf(parts[i-1], "%d", &analysis.LinesRemoved)
				}
			}
			break
		}
	}

	// Determine primary action
	if len(status.Untracked) > len(status.Modified) {
		analysis.PrimaryAction = "Add"
	} else if analysis.LinesRemoved > analysis.LinesAdded {
		analysis.PrimaryAction = "Remove"
	} else if analysis.HasTests {
		analysis.PrimaryAction = "Test"
	} else if analysis.HasDocs {
		analysis.PrimaryAction = "Document"
	} else if analysis.HasConfig {
		analysis.PrimaryAction = "Configure"
	} else {
		analysis.PrimaryAction = "Update"
	}

	return analysis
}

// BuildCommitMessage builds a commit message from the change analysis
func BuildCommitMessage(analysis *git.ChangeAnalysis) string {
	var parts []string

	// Primary action
	action := strings.ToLower(analysis.PrimaryAction)

	// Subject matter
	var subject string
	if len(analysis.Packages) == 1 {
		subject = analysis.Packages[0] + " package"
	} else if len(analysis.Packages) > 1 && len(analysis.Packages) <= 3 {
		subject = strings.Join(analysis.Packages, ", ") + " packages"
	} else if len(analysis.Packages) > 3 {
		subject = "multiple packages"
	} else {
		// Determine by file types
		if count, exists := analysis.FileTypes[".go"]; exists && count > 0 {
			subject = "Go code"
		} else if count, exists := analysis.FileTypes[".md"]; exists && count > 0 {
			subject = "documentation"
		} else if count, exists := analysis.FileTypes[".yaml"]; exists && count > 0 {
			subject = "configuration"
		} else {
			subject = "project files"
		}
	}

	// Build title
	title := fmt.Sprintf("%s %s", strings.ToUpper(action[:1])+action[1:], subject)

	// Add details based on analysis
	if analysis.HasTests {
		parts = append(parts, "- Add/update tests")
	}
	if analysis.HasDocs {
		parts = append(parts, "- Update documentation")
	}
	if analysis.HasConfig {
		parts = append(parts, "- Modify configuration")
	}

	// Add file statistics
	if analysis.TotalFiles > 0 {
		parts = append(parts, fmt.Sprintf("- Modified %d file(s)", analysis.TotalFiles))
	}
	if analysis.LinesAdded > 0 || analysis.LinesRemoved > 0 {
		parts = append(parts, fmt.Sprintf("- +%d/-%d lines", analysis.LinesAdded, analysis.LinesRemoved))
	}

	if len(parts) > 0 {
		return title + "\n\n" + strings.Join(parts, "\n")
	}

	return title
}

// GenerateSimpleMessage generates a simple commit message when analysis fails
func GenerateSimpleMessage(status *git.GitStatus) string {
	totalFiles := len(status.Staged) + len(status.Modified) + len(status.Untracked)

	if len(status.Untracked) > 0 {
		return fmt.Sprintf("Add new files and update existing code\n\n- %d files modified", totalFiles)
	}

	return fmt.Sprintf("Update project files\n\n- %d files modified", totalFiles)
}
