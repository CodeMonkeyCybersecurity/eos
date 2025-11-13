package repository

import "path/filepath"

// GiteaConfig holds connection details for the Gitea API.
type GiteaConfig struct {
	URL       string
	Token     string
	Username  string
	UseVault  bool
	VaultPath string
}

// RepoOptions describes options supplied by the user for repository creation.
type RepoOptions struct {
    Path           string
    Name           string
    Description    string
    Private        bool
    Organization   string
    Remote         string
    Branch         string
    DryRun         bool
    NoPush         bool
    NonInteractive bool
    SaveConfig     bool
    // Auth controls preferred remote URL type: "ssh" or "https" (default: ssh)
    Auth               string
    // AutoFixOwnership attempts to change repo ownership to the invoking user when run via sudo
    AutoFixOwnership   bool
    // SSHGenerateKey will generate an ed25519 SSH key if missing when Auth=ssh
    SSHGenerateKey     bool
    // ConfigureCredHelper sets a platform-appropriate credential.helper when Auth=https
    ConfigureCredHelper bool
}

// ApplyDefaults populates empty option fields with values from preferences or path.
func (o *RepoOptions) ApplyDefaults(prefs *RepoPreferences) {
	if o.Remote == "" && prefs != nil && prefs.Remote != "" {
		o.Remote = prefs.Remote
	}
	if o.Branch == "" && prefs != nil && prefs.Branch != "" {
		o.Branch = prefs.Branch
	}
	if o.Organization == "" && prefs != nil && prefs.Organization != "" {
		o.Organization = prefs.Organization
	}
	if prefs != nil && prefs.RememberPrivate {
		o.Private = prefs.DefaultPrivate
	}
}

// EnsurePathDefaults ensures path derived defaults for required fields.
func (o *RepoOptions) EnsurePathDefaults() {
	if o.Path == "" {
		o.Path = "."
	}
	if o.Name == "" {
		o.Name = filepath.Base(o.Path)
	}
	if o.Remote == "" {
		o.Remote = "origin"
	}
	if o.Branch == "" {
		o.Branch = "main"
	}
}

// CreationResult captures the outcome of the repository creation workflow.
type CreationResult struct {
	Name      string
	Owner     string
	HTMLURL   string
	CloneURL  string
	Remote    string
	Branch    string
	Pushed    bool
	WasNewGit bool
}

// RepoPreferences holds persisted defaults for interactive prompts.
type RepoPreferences struct {
	Remote          string `yaml:"remote,omitempty"`
	Branch          string `yaml:"branch,omitempty"`
	Organization    string `yaml:"organization,omitempty"`
	DefaultPrivate  bool   `yaml:"default_private,omitempty"`
	RememberPrivate bool   `yaml:"remember_private"`
}
