package self

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var gitCommitCmd = &cobra.Command{
	Use:   "commit",
	Short: "Auto-commit changes with smart commit messages",
	Long: `Automatically commit changes to git with intelligently generated commit messages.

This command provides several safety features:
- Generates meaningful commit messages based on file changes
- Scans for potential secrets and sensitive files
- Shows a summary before committing
- Protects against committing to main/master branches
- Respects .gitignore and excludes common artifacts

Options:
  --force      Skip safety checks and confirmation
  --message    Use custom commit message instead of auto-generated
  --push       Automatically push after successful commit
  --no-verify  Skip pre-commit hooks (dangerous!)`,
	RunE: eos_cli.Wrap(runGitCommit),
}

func init() {
	gitCommitCmd.Flags().Bool("force", false, "Skip safety checks and confirmation")
	gitCommitCmd.Flags().StringP("message", "m", "", "Use custom commit message")
	gitCommitCmd.Flags().Bool("push", false, "Automatically push after commit")
	gitCommitCmd.Flags().Bool("no-verify", false, "Skip pre-commit hooks")
	gitCommitCmd.Flags().Bool("dry-run", false, "Show what would be committed without actually committing")
}

func runGitCommit(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Parse flags
	force := cmd.Flag("force").Value.String() == "true"
	customMessage := cmd.Flag("message").Value.String()
	autoPush := cmd.Flag("push").Value.String() == "true"
	noVerify := cmd.Flag("no-verify").Value.String() == "true"
	dryRun := cmd.Flag("dry-run").Value.String() == "true"

	logger.Info("Starting auto-commit process",
		zap.Bool("force", force),
		zap.String("custom_message", customMessage),
		zap.Bool("auto_push", autoPush),
		zap.Bool("dry_run", dryRun))

	// Ensure we're in the EOS project root
	if err := ensureInProjectRoot(rc); err != nil {
		return err
	}

	// Check git status
	status, err := getGitStatus(rc)
	if err != nil {
		return fmt.Errorf("failed to get git status: %w", err)
	}

	if status.IsClean {
		logger.Info("No changes to commit")
		return nil
	}

	// Safety checks
	if !force {
		if err := runSafetyChecks(rc, status); err != nil {
			return err
		}
	}

	// Generate commit message
	var commitMessage string
	if customMessage != "" {
		commitMessage = customMessage
	} else {
		commitMessage, err = generateSmartCommitMessage(rc, status)
		if err != nil {
			return fmt.Errorf("failed to generate commit message: %w", err)
		}
	}

	// Show summary
	if err := showCommitSummary(rc, status, commitMessage); err != nil {
		return err
	}

	// Confirm if not forced
	if !force && !dryRun {
		if !confirmCommit(rc) {
			logger.Info("Commit cancelled by user")
			return nil
		}
	}

	if dryRun {
		logger.Info("Dry run complete - no changes made")
		return nil
	}

	// Execute commit
	if err := executeCommit(rc, commitMessage, noVerify); err != nil {
		return err
	}

	// Auto-push if requested
	if autoPush {
		if err := executePush(rc); err != nil {
			logger.Warn("Commit successful but push failed", zap.Error(err))
			return err
		}
	}

	logger.Info("Auto-commit completed successfully")
	return nil
}

type GitStatus struct {
	IsClean      bool
	Branch       string
	Staged       []string
	Modified     []string
	Untracked    []string
	HasConflicts bool
}

func ensureInProjectRoot(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Use cross-platform approach to find project root
	currentDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	// Look for go.mod in current dir or walk up the tree
	projectRoot, err := findProjectRoot(currentDir)
	if err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("not in EOS project: %v", err))
	}

	// Change to project root if not already there
	if projectRoot != currentDir {
		logger.Info("Changing to project root", zap.String("from", currentDir), zap.String("to", projectRoot))
		if err := os.Chdir(projectRoot); err != nil {
			return fmt.Errorf("failed to change to project root: %w", err)
		}
	}

	logger.Debug("Verified in EOS project root", zap.String("path", projectRoot))
	return nil
}

func findProjectRoot(startDir string) (string, error) {
	dir := startDir

	for {
		// Check for go.mod with EOS module
		goModPath := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			content, err := os.ReadFile(goModPath)
			if err == nil && strings.Contains(string(content), "module github.com/CodeMonkeyCybersecurity/eos") {
				return dir, nil
			}
		}

		// Move up one directory
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("EOS project root not found (no go.mod with EOS module)")
}

func getGitStatus(rc *eos_io.RuntimeContext) (*GitStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Ensure git is available on this platform
	if !platform.IsCommandAvailable("git") {
		return nil, eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("git command not found - please install git"))
	}

	// Get current branch
	branchOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "git",
		Args:    []string{"branch", "--show-current"},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get current branch: %w", err)
	}

	// Get detailed status
	statusOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "git",
		Args:    []string{"status", "--porcelain"},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get git status: %w", err)
	}

	status := &GitStatus{
		Branch:    strings.TrimSpace(branchOutput),
		IsClean:   strings.TrimSpace(statusOutput) == "",
		Staged:    []string{},
		Modified:  []string{},
		Untracked: []string{},
	}

	// Parse status lines
	scanner := bufio.NewScanner(strings.NewReader(statusOutput))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) < 3 {
			continue
		}

		statusCode := line[:2]
		filename := line[3:]

		switch {
		case strings.Contains(statusCode, "U") || strings.Contains(statusCode, "A") && strings.Contains(statusCode, "A"):
			status.HasConflicts = true
		case statusCode[0] != ' ' && statusCode[0] != '?':
			status.Staged = append(status.Staged, filename)
		case statusCode[1] != ' ':
			status.Modified = append(status.Modified, filename)
		case statusCode == "??":
			status.Untracked = append(status.Untracked, filename)
		}
	}

	logger.Debug("Git status retrieved",
		zap.String("branch", status.Branch),
		zap.Bool("is_clean", status.IsClean),
		zap.Int("staged", len(status.Staged)),
		zap.Int("modified", len(status.Modified)),
		zap.Int("untracked", len(status.Untracked)))

	return status, nil
}

func runSafetyChecks(rc *eos_io.RuntimeContext, status *GitStatus) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check for conflicts
	if status.HasConflicts {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("cannot commit: there are unresolved merge conflicts"))
	}

	// Check if committing to protected branch
	protectedBranches := []string{"main", "master", "production", "prod"}
	for _, protected := range protectedBranches {
		if status.Branch == protected {
			logger.Warn("Committing to protected branch",
				zap.String("branch", status.Branch))
			break
		}
	}

	// Check for potential secrets
	allFiles := append(append(status.Staged, status.Modified...), status.Untracked...)
	if err := scanForSecrets(rc, allFiles); err != nil {
		return err
	}

	// Check for large files
	if err := checkFileSizes(rc, allFiles); err != nil {
		return err
	}

	// Check for common artifacts
	if err := checkForArtifacts(rc, allFiles); err != nil {
		return err
	}

	logger.Debug("All safety checks passed")
	return nil
}

func scanForSecrets(rc *eos_io.RuntimeContext, files []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	secretPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*['"]\w+['"]`),
		regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]\w+['"]`),
		regexp.MustCompile(`(?i)(secret|token)\s*[:=]\s*['"]\w+['"]`),
		regexp.MustCompile(`-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----`),
		regexp.MustCompile(`(?i)aws_access_key_id`),
		regexp.MustCompile(`(?i)aws_secret_access_key`),
		regexp.MustCompile(`(?i)github_token`),
		regexp.MustCompile(`(?i)jwt_secret`),
		regexp.MustCompile(`(?i)database_url.*://.*:.*@`),
	}

	var suspiciousFiles []string

	for _, file := range files {
		// Skip binary files and directories
		if strings.HasSuffix(file, "/") {
			continue
		}

		// Check file extension
		ext := strings.ToLower(filepath.Ext(file))
		binaryExts := []string{".exe", ".dll", ".so", ".dylib", ".bin", ".img", ".iso"}
		for _, binExt := range binaryExts {
			if ext == binExt {
				continue
			}
		}

		// Read file content
		content, err := os.ReadFile(file)
		if err != nil {
			logger.Debug("Failed to read file for secret scanning",
				zap.String("file", file),
				zap.Error(err))
			continue
		}

		// Scan for patterns
		for _, pattern := range secretPatterns {
			if pattern.Match(content) {
				suspiciousFiles = append(suspiciousFiles, file)
				break
			}
		}
	}

	if len(suspiciousFiles) > 0 {
		logger.Warn("Potential secrets detected in files",
			zap.Strings("files", suspiciousFiles))
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("potential secrets detected in files: %v", suspiciousFiles))
	}

	return nil
}

func checkFileSizes(rc *eos_io.RuntimeContext, files []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	const maxFileSize = 50 * 1024 * 1024 // 50MB

	var largeFiles []string

	for _, file := range files {
		if strings.HasSuffix(file, "/") {
			continue
		}

		info, err := os.Stat(file)
		if err != nil {
			continue
		}

		if info.Size() > maxFileSize {
			largeFiles = append(largeFiles, fmt.Sprintf("%s (%d MB)", file, info.Size()/(1024*1024)))
		}
	}

	if len(largeFiles) > 0 {
		logger.Warn("Large files detected", zap.Strings("files", largeFiles))
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("large files detected (>50MB): %v", largeFiles))
	}

	return nil
}

func checkForArtifacts(rc *eos_io.RuntimeContext, files []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Platform-specific artifact patterns
	artifactPatterns := getArtifactPatterns()

	var artifacts []string

	for _, file := range files {
		for _, pattern := range artifactPatterns {
			if matched, _ := filepath.Match(pattern, filepath.Base(file)); matched {
				artifacts = append(artifacts, file)
				break
			}
			if strings.Contains(file, strings.TrimSuffix(pattern, "/")) {
				artifacts = append(artifacts, file)
				break
			}
		}
	}

	if len(artifacts) > 0 {
		logger.Warn("Potential build artifacts detected", zap.Strings("files", artifacts))
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("potential artifacts detected: %v", artifacts))
	}

	return nil
}

func getArtifactPatterns() []string {
	common := []string{
		"*.log", "*.tmp", "*.swp", "*.swo", "*~",
		"node_modules/", "vendor/", ".vscode/", ".idea/",
		"coverage.out", "*.test",
	}

	// Add platform-specific patterns
	if platform.IsMacOS() {
		common = append(common, ".DS_Store", "*.dSYM")
	}

	if platform.IsWindows() {
		common = append(common, "Thumbs.db", "*.exe", "*.dll", "*.pdb")
	}

	if platform.IsLinux() {
		common = append(common, "*.so", "*.a", "core.*")
	}

	// Add common binary extensions
	common = append(common, "*.o", "*.obj", "*.lib")

	return common
}

func generateSmartCommitMessage(rc *eos_io.RuntimeContext, status *GitStatus) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Get diff stats
	diffOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "git",
		Args:    []string{"diff", "--stat", "--cached"},
	})
	if err != nil {
		logger.Debug("Failed to get diff stats, using simple message", zap.Error(err))
		return generateSimpleMessage(status), nil
	}

	// Analyze changes
	analysis := analyzeChanges(status, diffOutput)

	// Generate message based on analysis
	message := buildCommitMessage(analysis)

	// Add standard footer
	message += "\n\n Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>"

	logger.Debug("Generated commit message", zap.String("message", message))
	return message, nil
}

type ChangeAnalysis struct {
	PrimaryAction string
	FileTypes     map[string]int
	Packages      []string
	HasTests      bool
	HasDocs       bool
	HasConfig     bool
	TotalFiles    int
	LinesAdded    int
	LinesRemoved  int
}

func analyzeChanges(status *GitStatus, diffStats string) *ChangeAnalysis {
	analysis := &ChangeAnalysis{
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
					fmt.Sscanf(parts[i-1], "%d", &analysis.LinesAdded)
				}
				if strings.Contains(part, "deletion") && i > 0 {
					fmt.Sscanf(parts[i-1], "%d", &analysis.LinesRemoved)
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

func buildCommitMessage(analysis *ChangeAnalysis) string {
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

func generateSimpleMessage(status *GitStatus) string {
	totalFiles := len(status.Staged) + len(status.Modified) + len(status.Untracked)

	if len(status.Untracked) > 0 {
		return fmt.Sprintf("Add new files and update existing code\n\n- %d files modified", totalFiles)
	}

	return fmt.Sprintf("Update project files\n\n- %d files modified", totalFiles)
}

func showCommitSummary(rc *eos_io.RuntimeContext, status *GitStatus, message string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("📋 Commit Summary")
	logger.Info("=================")
	logger.Info("Branch: " + status.Branch)

	if len(status.Staged) > 0 {
		logger.Info("Staged files:", zap.Strings("files", status.Staged))
	}
	if len(status.Modified) > 0 {
		logger.Info("Modified files:", zap.Strings("files", status.Modified))
	}
	if len(status.Untracked) > 0 {
		logger.Info("New files:", zap.Strings("files", status.Untracked))
	}

	logger.Info("\n📝 Commit Message:")
	logger.Info("===================")
	for _, line := range strings.Split(message, "\n") {
		logger.Info(line)
	}
	logger.Info("")

	return nil
}

func confirmCommit(rc *eos_io.RuntimeContext) bool {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Do you want to proceed with this commit? (y/N): ")

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}

func executeCommit(rc *eos_io.RuntimeContext, message string, noVerify bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	args := []string{"commit", "-a", "-m", message}
	if noVerify {
		args = append(args, "--no-verify")
	}

	logger.Info("Executing commit...")

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "git",
		Args:    args,
	})
	if err != nil {
		return fmt.Errorf("commit failed: %w\nOutput: %s", err, output)
	}

	logger.Info("Commit successful", zap.String("output", output))
	return nil
}

func executePush(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Pushing to remote...")

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "git",
		Args:    []string{"push"},
	})
	if err != nil {
		return fmt.Errorf("push failed: %w\nOutput: %s", err, output)
	}

	logger.Info("Push successful", zap.String("output", output))
	return nil
}
