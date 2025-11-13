package repository

import (
	"bytes"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// GitWrapper executes git CLI commands in a specific working directory.
type GitWrapper struct {
	Path string
}

// invalidBranchChars matches characters that are invalid in git branch names
// Git branch names cannot contain: \, ?, *, [, ], ~, ^, :, @{, .., //, leading/trailing dots, ending with .lock
var invalidBranchChars = regexp.MustCompile(`[\\?*\[\]~^:]|@\{|\.\.|\/{2,}|^\.|\.$|\.lock$`)

// ValidateBranchName checks if a branch name is valid according to git rules.
// Returns an error with helpful message if invalid.
// Based on git-check-ref-format rules (man git-check-ref-format).
func ValidateBranchName(branch string) error {
	if branch == "" {
		return fmt.Errorf("branch name cannot be empty")
	}

	// Check for single @ character (git rule #9)
	if branch == "@" {
		return fmt.Errorf("branch name cannot be the single character '@'")
	}

	// Check for whitespace (space, tab, newline, etc.) - git rule #4
	// Git spec: "cannot have ASCII control characters (i.e. bytes whose values
	// are lower than \040, or \177 DEL), space, tilde ~, caret ^, or colon : anywhere"
	if strings.ContainsAny(branch, " \t\n\r\v\f") {
		return fmt.Errorf("branch name '%s' contains whitespace characters\n"+
			"Git branch names cannot contain spaces or tabs\n"+
			"Example: Use 'feature-branch' instead of 'feature branch'", branch)
	}

	// Check for invalid characters (git rules #4, #5)
	if invalidBranchChars.MatchString(branch) {
		return fmt.Errorf("branch name '%s' contains invalid characters\n"+
			"Git branch names cannot contain: \\ ? * [ ] ~ ^ : @{ .. // leading/trailing dots, or end with .lock\n"+
			"Example valid names: main, develop, feature/my-feature", branch)
	}

	// Check for control characters (ASCII < 32 or DEL 127) - git rule #4
	for _, r := range branch {
		if r < 32 || r == 127 {
			return fmt.Errorf("branch name '%s' contains control characters", branch)
		}
	}

	// Check length (practical limit for cross-platform compatibility)
	const maxBranchNameLength = 255
	if len(branch) > maxBranchNameLength {
		return fmt.Errorf("branch name too long (%d bytes, max %d)\n"+
			"Current: %s...\n"+
			"Use a shorter name for better compatibility",
			len(branch), maxBranchNameLength, branch[:min(50, len(branch))])
	}

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ValidateRepoName checks if a repository name is valid according to Gitea rules.
// SECURITY: Validates against path traversal (../..), reserved names, and invalid characters.
// Gitea has specific naming requirements that differ from git branch rules.
func ValidateRepoName(name string) error {
	if name == "" {
		return fmt.Errorf("repository name cannot be empty")
	}

	// Length check (Gitea's limit)
	const maxRepoNameLength = 100
	if len(name) > maxRepoNameLength {
		return fmt.Errorf("repository name too long (max %d characters)\n"+
			"Current length: %d", maxRepoNameLength, len(name))
	}

	// Gitea reserved names (case-insensitive)
	// These are reserved by Gitea for internal routing and special pages
	reserved := map[string]bool{
		".":        true,
		"..":       true,
		"-":        true,
		"_":        true,
		"assets":   true,
		"avatars":  true,
		"user":     true,
		"org":      true,
		"explore":  true,
		"repo":     true,
		"api":      true,
		"admin":    true,
		"new":      true,
		"issues":   true,
		"pulls":    true,
		"commits":  true,
		"releases": true,
		"wiki":     true,
		"activity": true,
		"stars":    true,
		"forks":    true,
	}
	if reserved[strings.ToLower(name)] {
		return fmt.Errorf("repository name '%s' is reserved by Gitea\n"+
			"Reserved names: ., .., -, _, assets, avatars, user, org, api, admin, etc.\n"+
			"Choose a different name", name)
	}

	// Path traversal protection (consecutive dots)
	if strings.Contains(name, "..") {
		return fmt.Errorf("repository name cannot contain consecutive dots '..'\n"+
			"This is blocked for security (path traversal prevention)\n"+
			"Current: %s", name)
	}

	// Pattern validation (alphanumeric, dash, underscore, dot)
	// Gitea is more restrictive than git - only allows: a-z A-Z 0-9 . - _
	validRepoName := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	if !validRepoName.MatchString(name) {
		return fmt.Errorf("repository name '%s' contains invalid characters\n"+
			"Only letters, numbers, dots, dashes, and underscores are allowed\n"+
			"Example: my-project-123, web.app, data_pipeline", name)
	}

	// Check for leading/trailing special characters (Gitea rejects these)
	if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "-") || strings.HasPrefix(name, "_") {
		return fmt.Errorf("repository name cannot start with ., -, or _\n"+
			"Current: %s", name)
	}
	if strings.HasSuffix(name, ".") || strings.HasSuffix(name, "-") || strings.HasSuffix(name, "_") {
		return fmt.Errorf("repository name cannot end with ., -, or _\n"+
			"Current: %s", name)
	}

	return nil
}

// IsRepository returns true if the path contains a Git repository.
func (g *GitWrapper) IsRepository() bool {
	if g.Path == "" {
		return false
	}
	gitDir := filepath.Join(g.Path, ".git")
	info, err := os.Stat(gitDir)
	return err == nil && info.IsDir()
}

// InitRepository initializes a repository if missing.
func (g *GitWrapper) InitRepository() error {
	_, err := g.run("init")
	return err
}

// SetDefaultBranch updates HEAD to point at the desired default branch.
func (g *GitWrapper) SetDefaultBranch(branch string) error {
	if branch == "" {
		return nil
	}
	if err := ValidateBranchName(branch); err != nil {
		return err
	}
	_, err := g.run("symbolic-ref", "HEAD", fmt.Sprintf("refs/heads/%s", branch))
	return err
}

// EnsureBranch ensures the working tree is on the desired branch.
func (g *GitWrapper) EnsureBranch(branch string) error {
	if branch == "" {
		return nil
	}

	if err := ValidateBranchName(branch); err != nil {
		return err
	}

	current, err := g.CurrentBranch()
	if err == nil && current == branch {
		return nil
	}

	exists, err := g.branchExists(branch)
	if err != nil {
		return err
	}

	if exists {
		_, err = g.run("checkout", branch)
		return err
	}

	_, err = g.run("checkout", "-b", branch)
	return err
}

// HasCommits returns true if HEAD resolves successfully.
func (g *GitWrapper) HasCommits() (bool, error) {
	_, err := g.run("rev-parse", "HEAD")
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 128 {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// CreateInitialCommit adds all files and creates a commit, allowing empty commits.
func (g *GitWrapper) CreateInitialCommit(message string) error {
	if message == "" {
		message = "Initial commit (created by EOS)"
	}

	// Check if git identity is configured
	if err := g.ensureGitIdentity(); err != nil {
		return err
	}

	if _, err := g.run("add", "--all"); err != nil {
		return err
	}

	_, err := g.run("commit", "-m", message, "--allow-empty")
	return err
}

// ensureGitIdentity checks if git user.name and user.email are configured.
// Returns a helpful error if not configured.
// SECURITY: Validates email format (RFC 5322) to prevent:
// - CI/CD pipeline failures (many expect valid email format)
// - Gitea/GitHub API failures (some services validate email)
// - Audit log pollution (forensics needs valid contact info)
func (g *GitWrapper) ensureGitIdentity() error {
	// Check user.name exists and is not empty
	userName, err := g.run("config", "user.name")
	if err != nil {
		return fmt.Errorf("git identity not configured\n\n"+
			"Git requires user.name and user.email to create commits.\n\n"+
			"Configure your identity:\n"+
			"  git config --global user.name \"Your Name\"\n"+
			"  git config --global user.email \"your.email@example.com\"\n\n"+
			"Or configure only for this repository:\n"+
			"  cd %s\n"+
			"  git config user.name \"Your Name\"\n"+
			"  git config user.email \"your.email@example.com\"", g.Path)
	}
	userName = strings.TrimSpace(userName)
	if userName == "" {
		return fmt.Errorf("git user.name is empty\n\n"+
			"Configure your name:\n"+
			"  git config --global user.name \"Your Name\"\n\n"+
			"Or for this repository only:\n"+
			"  cd %s\n"+
			"  git config user.name \"Your Name\"", g.Path)
	}

	// Check user.email exists and is not empty
	userEmail, err := g.run("config", "user.email")
	if err != nil {
		return fmt.Errorf("git identity not configured\n\n"+
			"Git requires user.name and user.email to create commits.\n\n"+
			"Configure your identity:\n"+
			"  git config --global user.name \"Your Name\"\n"+
			"  git config --global user.email \"your.email@example.com\"\n\n"+
			"Or configure only for this repository:\n"+
			"  cd %s\n"+
			"  git config user.name \"Your Name\"\n"+
			"  git config user.email \"your.email@example.com\"", g.Path)
	}
	userEmail = strings.TrimSpace(userEmail)
	if userEmail == "" {
		return fmt.Errorf("git user.email is empty\n\n"+
			"Configure your email:\n"+
			"  git config --global user.email \"your.email@example.com\"\n\n"+
			"Or for this repository only:\n"+
			"  cd %s\n"+
			"  git config user.email \"your.email@example.com\"", g.Path)
	}

	// Validate email format (RFC 5322)
	// This catches common mistakes: "not-an-email", "../../../etc/passwd", "'; DROP TABLE;"
	if _, err := mail.ParseAddress(userEmail); err != nil {
		return fmt.Errorf("git user.email '%s' is not a valid email address\n\n"+
			"Current value: %s\n\n"+
			"Fix with:\n"+
			"  git config --global user.email \"your.email@example.com\"\n\n"+
			"Or for this repository only:\n"+
			"  cd %s\n"+
			"  git config user.email \"your.email@example.com\"\n\n"+
			"Email validation error: %v", userEmail, userEmail, g.Path, err)
	}

	return nil
}

// RemoteExists determines whether the remote is already configured.
func (g *GitWrapper) RemoteExists(name string) (bool, error) {
	_, err := g.run("remote", "get-url", name)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return false, nil
		}
		if strings.Contains(err.Error(), "No such remote") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// AddRemote adds a new remote.
func (g *GitWrapper) AddRemote(name, url string) error {
	_, err := g.run("remote", "add", name, url)
	return err
}

// SetRemote updates the URL for an existing remote.
func (g *GitWrapper) SetRemote(name, url string) error {
	_, err := g.run("remote", "set-url", name, url)
	return err
}

// Push pushes the current branch to the remote with upstream tracking.
func (g *GitWrapper) Push(remote, branch string) error {
	if remote == "" {
		remote = "origin"
	}
	if branch == "" {
		branch = "main"
	}
	_, err := g.run("push", "-u", remote, branch)
	return err
}

// CurrentBranch returns the name of the checked out branch.
func (g *GitWrapper) CurrentBranch() (string, error) {
	out, err := g.run("rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func (g *GitWrapper) branchExists(branch string) (bool, error) {
	_, err := g.run("rev-parse", "--verify", fmt.Sprintf("refs/heads/%s", branch))
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && (exitErr.ExitCode() == 128 || exitErr.ExitCode() == 1) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// run executes a git command and returns its stdout as a string.
func (g *GitWrapper) run(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = g.Path
	cmd.Env = os.Environ()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("git %s failed: %w\n%s", strings.Join(args, " "), err, stderr.String())
	}

	return stdout.String(), nil
}
