// pkg/git/preflight.go
//
// Git preflight checks - validates git environment before operations
// Follows fail-fast principle: detect issues BEFORE interactive prompts

package git

import (
	"context"
	"fmt"
	"net/mail"
	"os/exec"
	"strings"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GitPreflightConfig defines configuration for git preflight checks
type GitPreflightConfig struct {
	RequireGitInstalled bool // Default: true
	RequireIdentity     bool // Default: true
	CheckGlobalConfig   bool // Also check global config (not just local/system)
}

// DefaultGitPreflightConfig returns standard configuration for repository operations
func DefaultGitPreflightConfig() GitPreflightConfig {
	return GitPreflightConfig{
		RequireGitInstalled: true,
		RequireIdentity:     true,
		CheckGlobalConfig:   true,
	}
}

// RunGitPreflightChecks performs all preflight checks for git operations
// HUMAN-CENTRIC (P0 #13): Offers interactive fallback instead of hard failure
//
// Pattern: ASSESS → OFFER TO HELP → then proceed with user interaction
func RunGitPreflightChecks(ctx context.Context, config GitPreflightConfig) error {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Running git preflight checks",
		zap.Bool("require_installed", config.RequireGitInstalled),
		zap.Bool("require_identity", config.RequireIdentity))

	// Check 1: Git is installed
	if config.RequireGitInstalled {
		if err := CheckGitInstalled(ctx); err != nil {
			return err
		}
	}

	// Check 2: Git identity is configured
	if config.RequireIdentity {
		if err := CheckGitIdentity(ctx, config.CheckGlobalConfig); err != nil {
			// P0 #13: Don't fail immediately - offer to help configure
			logger.Info("Git identity not configured - offering interactive setup")
			return err // Return original error (will be handled by caller)
		}
	}

	logger.Info("Git preflight checks passed")
	return nil
}

// CheckGitInstalled verifies git command is available in PATH
func CheckGitInstalled(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	gitPath, err := exec.LookPath("git")
	if err != nil {
		return fmt.Errorf("git is not installed or not in PATH\n\n" +
			"Git is required to create repositories.\n\n" +
			"To install:\n" +
			"  Ubuntu/Debian: sudo apt-get install git\n" +
			"  macOS:         brew install git\n" +
			"  Or visit:      https://git-scm.com/downloads\n\n" +
			"After installing, verify with:\n" +
			"  git --version")
	}

	// Verify git can actually run
	cmd := exec.CommandContext(ctx, "git", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git is installed at %s but failed to execute: %w\n"+
			"Output: %s\n\n"+
			"This may indicate a permissions or installation issue.\n"+
			"Try: ls -l %s",
			gitPath, err, string(output), gitPath)
	}

	version := strings.TrimSpace(string(output))
	logger.Debug("Git is installed",
		zap.String("path", gitPath),
		zap.String("version", version))

	return nil
}

// CheckGitIdentity verifies git user.name and user.email are configured
// SECURITY: Validates email format (RFC 5322) to prevent:
// - CI/CD pipeline failures (many expect valid email format)
// - Gitea/GitHub API failures (some services validate email)
// - Audit log pollution (forensics needs valid contact info)
func CheckGitIdentity(ctx context.Context, checkGlobal bool) error {
	logger := otelzap.Ctx(ctx)

	// Check user.name
	userName, err := getGitConfig(ctx, "user.name", checkGlobal)
	if err != nil {
		return formatIdentityError("user.name", "", err)
	}
	userName = strings.TrimSpace(userName)
	if userName == "" {
		return formatIdentityError("user.name", "", fmt.Errorf("configured but empty"))
	}

	// Check user.email
	userEmail, err := getGitConfig(ctx, "user.email", checkGlobal)
	if err != nil {
		return formatIdentityError("user.email", userName, err)
	}
	userEmail = strings.TrimSpace(userEmail)
	if userEmail == "" {
		return formatIdentityError("user.email", userName, fmt.Errorf("configured but empty"))
	}

	// Validate email format (RFC 5322)
	// This catches common mistakes: "not-an-email", "../../../etc/passwd", "'; DROP TABLE;"
	if _, err := mail.ParseAddress(userEmail); err != nil {
		return fmt.Errorf("git user.email '%s' is not a valid email address\n\n"+
			"Current configuration:\n"+
			"  user.name:  %s\n"+
			"  user.email: %s (INVALID)\n\n"+
			"Fix with:\n"+
			"  git config --global user.email \"your.email@example.com\"\n\n"+
			"Email validation error: %v",
			userEmail, userName, userEmail, err)
	}

	logger.Debug("Git identity is configured",
		zap.String("user.name", userName),
		zap.String("user.email", userEmail))

	return nil
}

// getGitConfig retrieves a git config value
// If checkGlobal is true, checks for global config; otherwise checks any configured value
func getGitConfig(ctx context.Context, key string, checkGlobal bool) (string, error) {
	args := []string{"config"}
	if checkGlobal {
		args = append(args, "--global")
	} else {
		args = append(args, "--get")
	}
	args = append(args, key)

	cmd := exec.CommandContext(ctx, "git", args...)
	output, err := cmd.CombinedOutput()

	// git config returns exit code 1 if key not found (not an error condition)
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return "", fmt.Errorf("not configured")
		}
		return "", fmt.Errorf("failed to check: %w", err)
	}

	return strings.TrimSpace(string(output)), nil
}

// formatIdentityError creates a user-friendly error message for missing git identity
func formatIdentityError(key, userName string, originalErr error) error {
	var currentConfig string
	if userName != "" {
		currentConfig = fmt.Sprintf("\nCurrent configuration:\n  user.name: %s\n  %s: NOT SET\n", userName, key)
	}

	return fmt.Errorf("git identity not configured: %s\n\n"+
		"%s"+
		"Git requires both user.name and user.email to create commits.\n\n"+
		"Configure your identity:\n"+
		"  git config --global user.name \"Your Name\"\n"+
		"  git config --global user.email \"your.email@example.com\"\n\n"+
		"Or configure only for specific repositories:\n"+
		"  cd /path/to/repo\n"+
		"  git config user.name \"Your Name\"\n"+
		"  git config user.email \"your.email@example.com\"\n\n"+
		"Underlying issue: %v",
		key, currentConfig, originalErr)
}

// CheckGitIdentityForPath checks git identity for a specific repository path
// This is useful when you want to check local repo config before operations
func CheckGitIdentityForPath(ctx context.Context, repoPath string) error {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Checking git identity for repository",
		zap.String("path", repoPath))

	// Check user.name with -C flag to specify repository
	nameCmd := exec.CommandContext(ctx, "git", "-C", repoPath, "config", "user.name")
	nameOutput, nameErr := nameCmd.CombinedOutput()

	// Check user.email
	emailCmd := exec.CommandContext(ctx, "git", "-C", repoPath, "config", "user.email")
	emailOutput, emailErr := emailCmd.CombinedOutput()

	if nameErr != nil || emailErr != nil {
		return fmt.Errorf("git identity not configured for this repository\n\n"+
			"Repository: %s\n\n"+
			"Configure identity for this repository:\n"+
			"  cd %s\n"+
			"  git config user.name \"Your Name\"\n"+
			"  git config user.email \"your.email@example.com\"\n\n"+
			"Or configure globally:\n"+
			"  git config --global user.name \"Your Name\"\n"+
			"  git config --global user.email \"your.email@example.com\"",
			repoPath, repoPath)
	}

	userName := strings.TrimSpace(string(nameOutput))
	userEmail := strings.TrimSpace(string(emailOutput))

	if userName == "" || userEmail == "" {
		return fmt.Errorf("git identity is empty for this repository\n"+
			"Repository: %s\n"+
			"user.name: %s\n"+
			"user.email: %s\n\n"+
			"Please configure valid identity",
			repoPath, userName, userEmail)
	}

	// Validate email format
	if _, err := mail.ParseAddress(userEmail); err != nil {
		return fmt.Errorf("git user.email '%s' is not valid in repository %s\n\n"+
			"Fix with:\n"+
			"  cd %s\n"+
			"  git config user.email \"your.email@example.com\"",
			userEmail, repoPath, repoPath)
	}

	logger.Debug("Git identity verified for repository",
		zap.String("path", repoPath),
		zap.String("user.name", userName),
		zap.String("user.email", userEmail))

	return nil
}
