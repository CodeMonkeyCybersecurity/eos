// pkg/git_management/types.go
package git_management

import (
	"time"
)

// GitRepository represents a Git repository with its configuration
type GitRepository struct {
	Path       string            `json:"path"`
	RemoteURLs map[string]string `json:"remote_urls"`
	Branches   []string          `json:"branches"`
	Status     *GitStatus        `json:"status,omitempty"`
}

// GitStatus represents the current status of a Git repository
type GitStatus struct {
	Branch          string   `json:"branch"`
	Staged          []string `json:"staged"`
	Modified        []string `json:"modified"`
	Untracked       []string `json:"untracked"`
	AheadCount      int      `json:"ahead_count"`
	BehindCount     int      `json:"behind_count"`
	IsClean         bool     `json:"is_clean"`
	LastCommitHash  string   `json:"last_commit_hash"`
	LastCommitDate  string   `json:"last_commit_date"`
}

// GitConfig represents Git configuration settings
type GitConfig struct {
	Name         string            `json:"name"`
	Email        string            `json:"email"`
	DefaultBranch string           `json:"default_branch"`
	PullRebase   bool              `json:"pull_rebase"`
	ColorUI      bool              `json:"color_ui"`
	Custom       map[string]string `json:"custom,omitempty"`
}

// GitCommitOptions represents options for committing changes
type GitCommitOptions struct {
	Message     string `json:"message"`
	AddAll      bool   `json:"add_all"`
	Push        bool   `json:"push"`
	Remote      string `json:"remote"`
	Branch      string `json:"branch"`
	Force       bool   `json:"force"`
	Interactive bool   `json:"interactive"`
}

// GitInitOptions represents options for initializing a repository
type GitInitOptions struct {
	Path           string `json:"path"`
	InitialCommit  bool   `json:"initial_commit"`
	CommitMessage  string `json:"commit_message"`
	RemoteURL      string `json:"remote_url"`
	RemoteName     string `json:"remote_name"`
	DefaultBranch  string `json:"default_branch"`
	SetupGitHub    bool   `json:"setup_github"`
}

// GitRemoteOperation represents a remote repository operation
type GitRemoteOperation struct {
	Operation string `json:"operation"` // add, remove, set-url, rename
	Name      string `json:"name"`
	URL       string `json:"url"`
	NewName   string `json:"new_name,omitempty"`
}

// GitDeploymentOptions represents options for Git deployment wrapper
type GitDeploymentOptions struct {
	RepositoryPath string `json:"repository_path"`
	Branch         string `json:"branch"`
	MergeBranch    string `json:"merge_branch,omitempty"`
	LogFile        string `json:"log_file"`
	DryRun         bool   `json:"dry_run"`
	Force          bool   `json:"force"`
}

// GitLogEntry represents a Git commit log entry
type GitLogEntry struct {
	Hash        string    `json:"hash"`
	ShortHash   string    `json:"short_hash"`
	Author      string    `json:"author"`
	Email       string    `json:"email"`
	Date        time.Time `json:"date"`
	Message     string    `json:"message"`
	Files       []string  `json:"files,omitempty"`
}

// GitBranchInfo represents information about a Git branch
type GitBranchInfo struct {
	Name      string `json:"name"`
	Current   bool   `json:"current"`
	Remote    string `json:"remote,omitempty"`
	LastCommit string `json:"last_commit"`
	Ahead     int    `json:"ahead"`
	Behind    int    `json:"behind"`
}

// GitRemoteInfo represents information about a Git remote
type GitRemoteInfo struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Type     string `json:"type"` // fetch or push
}

// GitOperationResult represents the result of a Git operation
type GitOperationResult struct {
	Success   bool                   `json:"success"`
	Message   string                 `json:"message"`
	Output    string                 `json:"output,omitempty"`
	Error     string                 `json:"error,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}