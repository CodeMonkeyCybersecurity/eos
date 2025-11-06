// pkg/git_management/git.go
package git_management

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// IsGitRepository checks if the specified path is a Git repository following Assess → Intervene → Evaluate pattern
func IsGitRepository(rc *eos_io.RuntimeContext, path string) bool {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	if path == "" {
		path = "."
	}

	logger.Debug("Checking if directory is a Git repository", zap.String("path", path))

	// INTERVENE
	cmd := exec.Command("git", "rev-parse", "--is-inside-work-tree")
	cmd.Dir = path
	err := cmd.Run()

	// EVALUATE
	isRepo := err == nil
	logger.Debug("Git repository check completed",
		zap.String("path", path),
		zap.Bool("is_repository", isRepo))

	return isRepo
}

// GetRepositoryInfo retrieves comprehensive information about a Git repository following Assess → Intervene → Evaluate pattern
func GetRepositoryInfo(rc *eos_io.RuntimeContext, path string) (*GitRepository, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing Git repository information request", zap.String("path", path))

	if !IsGitRepository(rc, path) {
		return nil, fmt.Errorf("not a git repository: %s", path)
	}

	// INTERVENE
	logger.Info("Gathering Git repository information", zap.String("path", path))

	repo := &GitRepository{
		Path:       path,
		RemoteURLs: make(map[string]string),
	}

	// Get remote URLs
	remotes, err := getRemotes(path)
	if err != nil {
		logger.Warn("Failed to get remotes", zap.Error(err))
	} else {
		repo.RemoteURLs = remotes
	}

	// Get branches
	branches, err := getBranches(path)
	if err != nil {
		logger.Warn("Failed to get branches", zap.Error(err))
	} else {
		repo.Branches = branches
	}

	// Get status
	status, err := GetStatus(rc, path)
	if err != nil {
		logger.Warn("Failed to get status", zap.Error(err))
	} else {
		repo.Status = status
	}

	// EVALUATE
	logger.Info("Git repository information gathered successfully",
		zap.String("path", path),
		zap.Int("remote_count", len(repo.RemoteURLs)),
		zap.Int("branch_count", len(repo.Branches)))

	return repo, nil
}

// GetStatus retrieves the current status of a Git repository following Assess → Intervene → Evaluate pattern
func GetStatus(rc *eos_io.RuntimeContext, path string) (*GitStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing Git status request", zap.String("path", path))

	if path == "" {
		path = "."
	}

	// INTERVENE
	logger.Info("Getting Git repository status", zap.String("path", path))

	status := &GitStatus{}

	// Get current branch
	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	cmd.Dir = path
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get current branch: %w", err)
	}
	status.Branch = strings.TrimSpace(string(output))

	// Get status --porcelain
	cmd = exec.Command("git", "status", "--porcelain")
	cmd.Dir = path
	output, err = cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get git status: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if len(line) < 3 {
			continue
		}
		statusCode := line[:2]
		fileName := line[3:]

		switch {
		case statusCode[0] != ' ' && statusCode[0] != '?':
			status.Staged = append(status.Staged, fileName)
		case statusCode[1] != ' ' && statusCode[1] != '?':
			status.Modified = append(status.Modified, fileName)
		case statusCode == "??":
			status.Untracked = append(status.Untracked, fileName)
		}
	}

	status.IsClean = len(status.Staged) == 0 && len(status.Modified) == 0 && len(status.Untracked) == 0

	// Get ahead/behind count
	cmd = exec.Command("git", "rev-list", "--count", "--left-right", "@{upstream}...HEAD")
	cmd.Dir = path
	output, err = cmd.Output()
	if err == nil {
		parts := strings.Fields(strings.TrimSpace(string(output)))
		if len(parts) == 2 {
			if behind, err := strconv.Atoi(parts[0]); err == nil {
				status.BehindCount = behind
			}
			if ahead, err := strconv.Atoi(parts[1]); err == nil {
				status.AheadCount = ahead
			}
		}
	}

	// Get last commit info
	cmd = exec.Command("git", "log", "-1", "--format=%H|%cd", "--date=iso")
	cmd.Dir = path
	output, err = cmd.Output()
	if err == nil {
		parts := strings.Split(strings.TrimSpace(string(output)), "|")
		if len(parts) == 2 {
			status.LastCommitHash = parts[0]
			status.LastCommitDate = parts[1]
		}
	}

	// EVALUATE
	logger.Info("Git status retrieved successfully",
		zap.String("path", path),
		zap.String("branch", status.Branch),
		zap.Bool("is_clean", status.IsClean),
		zap.Int("staged_files", len(status.Staged)),
		zap.Int("modified_files", len(status.Modified)),
		zap.Int("untracked_files", len(status.Untracked)))

	return status, nil
}

// ConfigureGit sets up Git configuration following Assess → Intervene → Evaluate pattern
func ConfigureGit(rc *eos_io.RuntimeContext, config *GitConfig, global bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	scope := "--local"
	if global {
		scope = "--global"
	}

	logger.Info("Assessing Git configuration requirements",
		zap.String("scope", scope),
		zap.String("name", config.Name),
		zap.String("email", config.Email))

	// INTERVENE
	logger.Info("Configuring Git", zap.String("scope", scope))

	// Set user name
	if config.Name != "" {
		if err := runGitCommand("", "config", scope, "user.name", config.Name); err != nil {
			return fmt.Errorf("failed to set user name: %w", err)
		}
	}

	// Set user email
	if config.Email != "" {
		if err := runGitCommand("", "config", scope, "user.email", config.Email); err != nil {
			return fmt.Errorf("failed to set user email: %w", err)
		}
	}

	// Set default branch
	if config.DefaultBranch != "" {
		if err := runGitCommand("", "config", scope, "init.defaultBranch", config.DefaultBranch); err != nil {
			return fmt.Errorf("failed to set default branch: %w", err)
		}
	}

	// Set pull rebase
	rebaseValue := "false"
	if config.PullRebase {
		rebaseValue = "true"
	}
	if err := runGitCommand("", "config", scope, "pull.rebase", rebaseValue); err != nil {
		return fmt.Errorf("failed to set pull rebase: %w", err)
	}

	// Set color UI
	colorValue := "auto"
	if !config.ColorUI {
		colorValue = "false"
	}
	if err := runGitCommand("", "config", scope, "color.ui", colorValue); err != nil {
		return fmt.Errorf("failed to set color UI: %w", err)
	}

	// Set custom configuration
	for key, value := range config.Custom {
		if err := runGitCommand("", "config", scope, key, value); err != nil {
			logger.Warn("Failed to set custom config", zap.String("key", key), zap.Error(err))
		}
	}

	// EVALUATE
	logger.Info("Git configuration completed successfully", zap.String("scope", scope))
	return nil
}

// InitRepository initializes a new Git repository following Assess → Intervene → Evaluate pattern
func InitRepository(rc *eos_io.RuntimeContext, options *GitInitOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	if options.Path == "" {
		options.Path = "."
	}

	logger.Info("Assessing Git repository initialization", zap.String("path", options.Path))

	// INTERVENE
	logger.Info("Initializing Git repository", zap.String("path", options.Path))

	// Ensure directory exists
	if err := os.MkdirAll(options.Path, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Initialize repository
	if err := runGitCommand(options.Path, "init"); err != nil {
		return fmt.Errorf("failed to initialize repository: %w", err)
	}

	// Set default branch if specified
	if options.DefaultBranch != "" {
		if err := runGitCommand(options.Path, "config", "init.defaultBranch", options.DefaultBranch); err != nil {
			logger.Warn("Failed to set default branch", zap.Error(err))
		}
	}

	// Add remote if specified
	if options.RemoteURL != "" {
		remoteName := options.RemoteName
		if remoteName == "" {
			remoteName = "origin"
		}
		if err := runGitCommand(options.Path, "remote", "add", remoteName, options.RemoteURL); err != nil {
			return fmt.Errorf("failed to add remote: %w", err)
		}
	}

	// Initial commit if requested
	if options.InitialCommit {
		if err := runGitCommand(options.Path, "add", "."); err != nil {
			return fmt.Errorf("failed to add files: %w", err)
		}

		commitMessage := options.CommitMessage
		if commitMessage == "" {
			commitMessage = "Initial commit"
		}
		if err := runGitCommand(options.Path, "commit", "-m", commitMessage); err != nil {
			return fmt.Errorf("failed to create initial commit: %w", err)
		}
	}

	// EVALUATE
	logger.Info("Git repository initialized successfully", zap.String("path", options.Path))
	return nil
}

// CommitAndPush commits changes and optionally pushes to remote following Assess → Intervene → Evaluate pattern
func CommitAndPush(rc *eos_io.RuntimeContext, path string, options *GitCommitOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	if path == "" {
		path = "."
	}

	logger.Info("Assessing commit and push requirements",
		zap.String("path", path),
		zap.String("message", options.Message),
		zap.Bool("push", options.Push))

	// INTERVENE
	logger.Info("Committing and pushing changes",
		zap.String("path", path),
		zap.Bool("add_all", options.AddAll))

	// Add files if requested
	if options.AddAll {
		if err := runGitCommand(path, "add", "."); err != nil {
			return fmt.Errorf("failed to add files: %w", err)
		}
	}

	// Commit changes
	if err := runGitCommand(path, "commit", "-m", options.Message); err != nil {
		return fmt.Errorf("failed to commit changes: %w", err)
	}

	// Push changes if requested
	if options.Push {
		remote := options.Remote
		if remote == "" {
			remote = "origin"
		}
		branch := options.Branch
		if branch == "" {
			branch = "HEAD"
		}

		args := []string{"push", remote, branch}
		if options.Force {
			args = []string{"push", "--force", remote, branch}
		}

		if err := runGitCommand(path, args...); err != nil {
			return fmt.Errorf("failed to push changes: %w", err)
		}
	}

	// EVALUATE
	logger.Info("Commit and push completed successfully",
		zap.String("path", path),
		zap.String("message", options.Message))
	return nil
}

// ManageRemote manages Git remotes following Assess → Intervene → Evaluate pattern
func ManageRemote(rc *eos_io.RuntimeContext, path string, operation *GitRemoteOperation) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	if path == "" {
		path = "."
	}

	logger.Info("Assessing Git remote operation",
		zap.String("operation", operation.Operation),
		zap.String("name", operation.Name),
		zap.String("url", operation.URL))

	// INTERVENE
	logger.Info("Managing Git remote",
		zap.String("path", path),
		zap.String("operation", operation.Operation))

	var err error
	switch operation.Operation {
	case "add":
		err = runGitCommand(path, "remote", "add", operation.Name, operation.URL)
	case "remove":
		err = runGitCommand(path, "remote", "remove", operation.Name)
	case "set-url":
		err = runGitCommand(path, "remote", "set-url", operation.Name, operation.URL)
	case "rename":
		err = runGitCommand(path, "remote", "rename", operation.Name, operation.NewName)
	default:
		return fmt.Errorf("unsupported remote operation: %s", operation.Operation)
	}

	// EVALUATE
	if err != nil {
		return fmt.Errorf("remote operation %s failed: %w", operation.Operation, err)
	}

	logger.Info("Git remote operation completed successfully",
		zap.String("operation", operation.Operation),
		zap.String("name", operation.Name))
	return nil
}

// DeployWithGit performs Git-based deployment operations following Assess → Intervene → Evaluate pattern
func DeployWithGit(rc *eos_io.RuntimeContext, options *GitDeploymentOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Assessing Git deployment requirements",
		zap.String("repository", options.RepositoryPath),
		zap.String("branch", options.Branch),
		zap.Bool("dry_run", options.DryRun))

	if !IsGitRepository(rc, options.RepositoryPath) {
		return fmt.Errorf("not a git repository: %s", options.RepositoryPath)
	}

	// INTERVENE
	if options.DryRun {
		logger.Info("Dry run: would perform Git deployment",
			zap.String("repository", options.RepositoryPath))
		return nil
	}

	logger.Info("Starting Git deployment", zap.String("repository", options.RepositoryPath))

	// Pull latest changes
	if err := runGitCommand(options.RepositoryPath, "pull", "origin", options.Branch); err != nil {
		return fmt.Errorf("failed to pull latest changes: %w", err)
	}

	// Merge branch if specified
	if options.MergeBranch != "" {
		if err := runGitCommand(options.RepositoryPath, "merge", options.MergeBranch); err != nil {
			return fmt.Errorf("failed to merge branch: %w", err)
		}
	}

	// Push changes
	args := []string{"push", "origin", options.Branch}
	if options.Force {
		args = []string{"push", "--force", "origin", options.Branch}
	}
	if err := runGitCommand(options.RepositoryPath, args...); err != nil {
		return fmt.Errorf("failed to push changes: %w", err)
	}

	// EVALUATE
	logger.Info("Git deployment completed successfully",
		zap.String("repository", options.RepositoryPath),
		zap.String("branch", options.Branch))
	return nil
}

// GetConfig retrieves current Git configuration following Assess → Intervene → Evaluate pattern
func GetConfig(rc *eos_io.RuntimeContext, path string, global bool) (*GitConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	scope := "--local"
	if global {
		scope = "--global"
	}

	logger.Info("Assessing Git configuration retrieval",
		zap.String("path", path),
		zap.String("scope", scope))

	// INTERVENE
	logger.Info("Getting Git configuration", zap.String("scope", scope))

	config := &GitConfig{
		Custom: make(map[string]string),
	}

	// Get user name
	if name, err := runGitCommandWithOutput(path, "config", scope, "user.name"); err == nil {
		config.Name = name
	}

	// Get user email
	if email, err := runGitCommandWithOutput(path, "config", scope, "user.email"); err == nil {
		config.Email = email
	}

	// Get default branch
	if branch, err := runGitCommandWithOutput(path, "config", scope, "init.defaultBranch"); err == nil {
		config.DefaultBranch = branch
	}

	// Get pull rebase setting
	if rebase, err := runGitCommandWithOutput(path, "config", scope, "pull.rebase"); err == nil {
		config.PullRebase = rebase == "true"
	}

	// Get color UI setting
	if color, err := runGitCommandWithOutput(path, "config", scope, "color.ui"); err == nil {
		config.ColorUI = color == "auto" || color == "true"
	}

	// EVALUATE
	logger.Info("Git configuration retrieved successfully",
		zap.String("scope", scope),
		zap.String("name", config.Name),
		zap.String("email", config.Email))

	return config, nil
}

// Helper functions

func runGitCommand(dir string, args ...string) error {
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	return cmd.Run()
}

func runGitCommandWithOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	output, err := cmd.Output()
	return strings.TrimSpace(string(output)), err
}

func getRemotes(path string) (map[string]string, error) {
	cmd := exec.Command("git", "remote", "-v")
	cmd.Dir = path
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	remotes := make(map[string]string)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			remotes[parts[0]] = parts[1]
		}
	}
	return remotes, nil
}

func getBranches(path string) ([]string, error) {
	cmd := exec.Command("git", "branch", "-a")
	cmd.Dir = path
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var branches []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Remove markers like * and -> origin/HEAD
		line = strings.TrimPrefix(line, "* ")
		line = strings.TrimPrefix(line, "  ")
		if !strings.Contains(line, "->") {
			branches = append(branches, line)
		}
	}
	return branches, nil
}
