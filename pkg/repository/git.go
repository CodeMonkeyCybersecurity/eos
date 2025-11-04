package repository

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// GitWrapper executes git CLI commands in a specific working directory.
type GitWrapper struct {
	Path string
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
	_, err := g.run("symbolic-ref", "HEAD", fmt.Sprintf("refs/heads/%s", branch))
	return err
}

// EnsureBranch ensures the working tree is on the desired branch.
func (g *GitWrapper) EnsureBranch(branch string) error {
	if branch == "" {
		return nil
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
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 128 {
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

	if _, err := g.run("add", "--all"); err != nil {
		return err
	}

	_, err := g.run("commit", "-m", message, "--allow-empty")
	return err
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
