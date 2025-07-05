package container_management

import (
	"time"
)

// ComposeProject represents a Docker Compose project
type ComposeProject struct {
	Path        string    `json:"path"`
	Name        string    `json:"name"`
	Services    []string  `json:"services"`
	ComposeFile string    `json:"compose_file"` // docker-compose.yml or docker-compose.yaml
	Status      string    `json:"status"`       // running, stopped, partial, unknown
	LastSeen    time.Time `json:"last_seen"`
}

// ComposeSearchResult contains results of searching for compose projects
type ComposeSearchResult struct {
	SearchPaths    []string         `json:"search_paths"`
	Projects       []ComposeProject `json:"projects"`
	TotalFound     int              `json:"total_found"`
	Timestamp      time.Time        `json:"timestamp"`
	SearchDuration time.Duration    `json:"search_duration"`
}

// ComposeOperation represents a compose management operation
type ComposeOperation struct {
	Operation  string         `json:"operation"` // up, down, stop, start, restart
	Project    ComposeProject `json:"project"`
	Success    bool           `json:"success"`
	Message    string         `json:"message"`
	Output     string         `json:"output,omitempty"`
	Timestamp  time.Time      `json:"timestamp"`
	Duration   time.Duration  `json:"duration"`
	DryRun     bool           `json:"dry_run"`
}

// ContainerInfo represents information about a running container
type ContainerInfo struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Image   string            `json:"image"`
	Status  string            `json:"status"`
	State   string            `json:"state"`
	Ports   map[string]string `json:"ports"`
	Labels  map[string]string `json:"labels"`
	Project string            `json:"project,omitempty"`
}

// ContainerListResult contains results of listing containers
type ContainerListResult struct {
	Containers []ContainerInfo `json:"containers"`
	Total      int             `json:"total"`
	Running    int             `json:"running"`
	Stopped    int             `json:"stopped"`
	Timestamp  time.Time       `json:"timestamp"`
}

// ComposeStopOptions contains options for stopping compose projects
type ComposeStopOptions struct {
	SearchPaths      []string `json:"search_paths"`
	ConfirmEach      bool     `json:"confirm_each"`
	Force            bool     `json:"force"`
	StopContainers   bool     `json:"stop_containers"`
	IgnoreRunning    bool     `json:"ignore_running"`
	DryRun           bool     `json:"dry_run"`
	RemoveVolumes    bool     `json:"remove_volumes"`
	RemoveImages     bool     `json:"remove_images"`
	Timeout          int      `json:"timeout"` // seconds
}

// DefaultComposeStopOptions returns options with sensible defaults
func DefaultComposeStopOptions() *ComposeStopOptions {
	return &ComposeStopOptions{
		SearchPaths:    []string{},
		ConfirmEach:    true,
		Force:          false,
		StopContainers: true,
		IgnoreRunning:  false,
		DryRun:         false,
		RemoveVolumes:  false,
		RemoveImages:   false,
		Timeout:        30,
	}
}

// ComposeConfig contains configuration for container management
type ComposeConfig struct {
	DefaultSearchPaths []string `json:"default_search_paths" mapstructure:"default_search_paths"`
	MaxDepth           int      `json:"max_depth" mapstructure:"max_depth"`
	FollowSymlinks     bool     `json:"follow_symlinks" mapstructure:"follow_symlinks"`
	ExcludePatterns    []string `json:"exclude_patterns" mapstructure:"exclude_patterns"`
	ComposeFileNames   []string `json:"compose_file_names" mapstructure:"compose_file_names"`
	CheckStatus        bool     `json:"check_status" mapstructure:"check_status"`
	Verbose            bool     `json:"verbose" mapstructure:"verbose"`
}

// DefaultComposeConfig returns a configuration with sensible defaults
func DefaultComposeConfig() *ComposeConfig {
	return &ComposeConfig{
		DefaultSearchPaths: []string{
			"$HOME",
			"/opt",
			"/srv",
			"/home",
		},
		MaxDepth:        5,
		FollowSymlinks:  false,
		ExcludePatterns: []string{
			".git",
			"node_modules",
			".cache",
			".tmp",
			"vendor",
		},
		ComposeFileNames: []string{
			"docker-compose.yaml",
			"docker-compose.yml",
			"compose.yaml",
			"compose.yml",
		},
		CheckStatus: true,
		Verbose:     true,
	}
}

// ComposeStopSummary provides a summary of stop operations
type ComposeStopSummary struct {
	TotalProjects    int      `json:"total_projects"`
	ProjectsStopped  int      `json:"projects_stopped"`
	ProjectsSkipped  int      `json:"projects_skipped"`
	ProjectsFailed   int      `json:"projects_failed"`
	ContainersStopped int     `json:"containers_stopped"`
	Errors           []string `json:"errors"`
	Duration         time.Duration `json:"duration"`
	Success          bool     `json:"success"`
}

// ComposeMultiStopResult contains results of stopping multiple projects
type ComposeMultiStopResult struct {
	Operations []ComposeOperation `json:"operations"`
	Summary    ComposeStopSummary `json:"summary"`
	Timestamp  time.Time          `json:"timestamp"`
}