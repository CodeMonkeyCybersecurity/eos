// pkg/gitea/git.go
// Git remote configuration for Gitea repositories
// Handles adding, updating, and managing git remotes

package gitea

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AddRemote adds a git remote pointing to the Gitea repository
func AddRemote(rc *eos_io.RuntimeContext, instance *InstanceConfig, config *GitRemoteConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Build the remote URL using SSH config host alias
	hostAlias := instance.SSHConfigHost
	if hostAlias == "" {
		hostAlias = fmt.Sprintf("gitea-%s", instance.Name)
	}

	org := config.Organization
	if org == "" {
		org = instance.Organization
	}

	remoteURL := fmt.Sprintf("git@%s:%s/%s.git", hostAlias, org, config.RepoName)

	logger.Info("Adding git remote",
		zap.String("name", config.RemoteName),
		zap.String("url", remoteURL),
		zap.String("repo_path", config.RepoPath))

	// Check if remote already exists
	cmd := exec.Command("git", "remote", "get-url", config.RemoteName)
	cmd.Dir = config.RepoPath

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err == nil {
		// Remote exists - check if URL matches
		existingURL := strings.TrimSpace(stdout.String())
		if existingURL == remoteURL {
			logger.Info("Remote already configured correctly",
				zap.String("name", config.RemoteName),
				zap.String("url", existingURL))
			return nil
		}

		// Update existing remote
		logger.Info("Updating existing remote URL",
			zap.String("name", config.RemoteName),
			zap.String("old_url", existingURL),
			zap.String("new_url", remoteURL))

		cmd = exec.Command("git", "remote", "set-url", config.RemoteName, remoteURL)
		cmd.Dir = config.RepoPath

		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to update remote: %s: %w", stderr.String(), err)
		}

		logger.Info("Remote URL updated", zap.String("name", config.RemoteName))
		return nil
	}

	// Add new remote
	cmd = exec.Command("git", "remote", "add", config.RemoteName, remoteURL)
	cmd.Dir = config.RepoPath

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add remote: %s: %w", stderr.String(), err)
	}

	logger.Info("Remote added successfully",
		zap.String("name", config.RemoteName),
		zap.String("url", remoteURL))

	return nil
}

// PushToRemote pushes the current branch to the remote
func PushToRemote(rc *eos_io.RuntimeContext, repoPath, remoteName, branch string, setUpstream bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	args := []string{"push"}
	if setUpstream {
		args = append(args, "-u")
	}
	args = append(args, remoteName, branch)

	logger.Info("Pushing to remote",
		zap.String("remote", remoteName),
		zap.String("branch", branch),
		zap.Bool("set_upstream", setUpstream))

	cmd := exec.Command("git", args...)
	cmd.Dir = repoPath

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		output := stdout.String() + stderr.String()
		return fmt.Errorf("push failed: %s\n%w", output, err)
	}

	logger.Info("Push completed successfully",
		zap.String("output", stdout.String()+stderr.String()))

	return nil
}

// GetCurrentBranch returns the current git branch
func GetCurrentBranch(repoPath string) (string, error) {
	cmd := exec.Command("git", "branch", "--show-current")
	cmd.Dir = repoPath

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to get current branch: %w", err)
	}

	return strings.TrimSpace(stdout.String()), nil
}

// IsGitRepo checks if the given path is a git repository
func IsGitRepo(path string) bool {
	cmd := exec.Command("git", "rev-parse", "--git-dir")
	cmd.Dir = path

	return cmd.Run() == nil
}

// GetRemoteURL returns the URL for a given remote
func GetRemoteURL(repoPath, remoteName string) (string, error) {
	cmd := exec.Command("git", "remote", "get-url", remoteName)
	cmd.Dir = repoPath

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("remote '%s' not found", remoteName)
	}

	return strings.TrimSpace(stdout.String()), nil
}

// ListRemotes returns all configured remotes
func ListRemotes(repoPath string) (map[string]string, error) {
	cmd := exec.Command("git", "remote", "-v")
	cmd.Dir = repoPath

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to list remotes: %w", err)
	}

	remotes := make(map[string]string)
	lines := strings.Split(stdout.String(), "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 2 && strings.HasSuffix(parts[2], "(push)") {
			remotes[parts[0]] = parts[1]
		}
	}

	return remotes, nil
}

// GenerateGitRemoteURL generates the SSH URL for a Gitea repository
func GenerateGitRemoteURL(instance *InstanceConfig, org, repoName string) string {
	hostAlias := instance.SSHConfigHost
	if hostAlias == "" {
		hostAlias = fmt.Sprintf("gitea-%s", instance.Name)
	}

	if org == "" {
		org = instance.Organization
	}

	return fmt.Sprintf("git@%s:%s/%s.git", hostAlias, org, repoName)
}
