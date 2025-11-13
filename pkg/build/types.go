package build

import (
	"time"
)

// Builder handles various types of build operations
type Builder struct {
	workDir    string
	hugoPath   string
	dockerPath string
}

// HugoBuilder handles Hugo static site generation
type HugoBuilder struct {
	// All fields removed - unused struct kept for potential future use
}

// DockerBuilder handles Docker image building and management
type DockerBuilder struct {
	// All fields removed - unused struct kept for potential future use
}

// BuildContext contains information about the current build
type BuildContext struct {
	WorkDir     string            `json:"work_dir"`
	SourceDir   string            `json:"source_dir"`
	OutputDir   string            `json:"output_dir"`
	BuildID     string            `json:"build_id"`
	Timestamp   time.Time         `json:"timestamp"`
	Environment map[string]string `json:"environment"`
	Tags        []string          `json:"tags"`
}

// HugoBuildOptions contains Hugo-specific build options
type HugoBuildOptions struct {
	Environment    string            `json:"environment"`
	Minify         bool              `json:"minify"`
	OutputDir      string            `json:"output_dir"`
	ConfigFile     string            `json:"config_file"`
	BaseURL        string            `json:"base_url"`
	Theme          string            `json:"theme"`
	Draft          bool              `json:"draft"`
	Future         bool              `json:"future"`
	Expired        bool              `json:"expired"`
	GC             bool              `json:"gc"`
	CleanupEnabled bool              `json:"cleanup_enabled"`
	ExtraArgs      []string          `json:"extra_args"`
	EnvVars        map[string]string `json:"env_vars"`
}

// DockerBuildOptions contains Docker-specific build options
type DockerBuildOptions struct {
	Dockerfile  string            `json:"dockerfile"`
	Context     string            `json:"context"`
	Registry    string            `json:"registry"`
	Repository  string            `json:"repository"`
	Tags        []string          `json:"tags"`
	BuildArgs   map[string]string `json:"build_args"`
	Labels      map[string]string `json:"labels"`
	Target      string            `json:"target"`
	NoCache     bool              `json:"no_cache"`
	Pull        bool              `json:"pull"`
	Squash      bool              `json:"squash"`
	Platform    string            `json:"platform"`
	SecurityOpt []string          `json:"security_opt"`
	ExtraArgs   []string          `json:"extra_args"`
}

// BuildMetrics contains build performance metrics
type BuildMetrics struct {
	StartTime      time.Time     `json:"start_time"`
	EndTime        time.Time     `json:"end_time"`
	Duration       time.Duration `json:"duration"`
	CPUUsage       float64       `json:"cpu_usage"`
	MemoryUsage    int64         `json:"memory_usage"`
	DiskUsage      int64         `json:"disk_usage"`
	CacheHitRatio  float64       `json:"cache_hit_ratio"`
	ArtifactSize   int64         `json:"artifact_size"`
	FilesProcessed int           `json:"files_processed"`
}

// BuildValidation contains validation settings for build artifacts
type BuildValidation struct {
	EnableChecksums     bool     `json:"enable_checksums"`
	EnableSizeCheck     bool     `json:"enable_size_check"`
	MaxArtifactSize     int64    `json:"max_artifact_size"`
	RequiredFiles       []string `json:"required_files"`
	ForbiddenPatterns   []string `json:"forbidden_patterns"`
	SecurityScanEnabled bool     `json:"security_scan_enabled"`
	LintingEnabled      bool     `json:"linting_enabled"`
}

// SecurityScanResult contains results from security scanning
type SecurityScanResult struct {
	Scanner         string              `json:"scanner"`
	ScanTime        time.Time           `json:"scan_time"`
	Vulnerabilities []VulnerabilityInfo `json:"vulnerabilities"`
	Passed          bool                `json:"passed"`
	ReportPath      string              `json:"report_path"`
}

// VulnerabilityInfo contains information about a detected vulnerability
type VulnerabilityInfo struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Package     string `json:"package"`
	Version     string `json:"version"`
	Description string `json:"description"`
	FixVersion  string `json:"fix_version,omitempty"`
}

// LintResult contains results from linting operations
type LintResult struct {
	Tool     string      `json:"tool"`
	LintTime time.Time   `json:"lint_time"`
	Issues   []LintIssue `json:"issues"`
	Passed   bool        `json:"passed"`
}

// LintIssue represents a single linting issue
type LintIssue struct {
	File       string `json:"file"`
	Line       int    `json:"line"`
	Column     int    `json:"column"`
	Severity   string `json:"severity"`
	Rule       string `json:"rule"`
	Message    string `json:"message"`
	Suggestion string `json:"suggestion,omitempty"`
}

// BuildError represents an error during the build process
type BuildError struct {
	Type      string                 `json:"type"`
	Stage     string                 `json:"stage"`
	Message   string                 `json:"message"`
	Cause     error                  `json:"cause,omitempty"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp time.Time              `json:"timestamp"`
	Retryable bool                   `json:"retryable"`
}

func (e *BuildError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

// BuildStatus represents the current status of a build
type BuildStatus string

const (
	BuildStatusPending   BuildStatus = "pending"
	BuildStatusRunning   BuildStatus = "running"
	BuildStatusSucceeded BuildStatus = "succeeded"
	BuildStatusFailed    BuildStatus = "failed"
	BuildStatusCancelled BuildStatus = "cancelled"
)

// ArtifactType represents the type of build artifact
type ArtifactType string

const (
	ArtifactTypeStaticSite   ArtifactType = "static_site"
	ArtifactTypeDockerImage  ArtifactType = "docker_image"
	ArtifactTypeArchive      ArtifactType = "archive"
	ArtifactTypeManifest     ArtifactType = "manifest"
	ArtifactTypeSecurityScan ArtifactType = "security_scan"
	ArtifactTypeLintReport   ArtifactType = "lint_report"
)

// BuildCache manages build caching for performance optimization
type BuildCache struct {
	Enabled    bool              `json:"enabled"`
	Provider   string            `json:"provider"` // local, redis, s3
	Config     map[string]string `json:"config"`
	TTL        time.Duration     `json:"ttl"`
	MaxSize    int64             `json:"max_size"`
	HitRate    float64           `json:"hit_rate"`
	LastPurged time.Time         `json:"last_purged"`
}

// BuildNotification contains notification settings for build events
type BuildNotification struct {
	Enabled    bool                  `json:"enabled"`
	Channels   []NotificationChannel `json:"channels"`
	Events     []BuildEvent          `json:"events"`
	Templates  map[string]string     `json:"templates"`
	Recipients []string              `json:"recipients"`
}

// NotificationChannel represents a notification delivery channel
type NotificationChannel struct {
	Type   string            `json:"type"` // slack, email, webhook
	Config map[string]string `json:"config"`
}

// BuildEvent represents events that can trigger notifications
type BuildEvent string

const (
	BuildEventStarted   BuildEvent = "started"
	BuildEventCompleted BuildEvent = "completed"
	BuildEventFailed    BuildEvent = "failed"
	BuildEventCancelled BuildEvent = "cancelled"
)

// DefaultHugoBuildOptions returns default Hugo build options
func DefaultHugoBuildOptions() *HugoBuildOptions {
	return &HugoBuildOptions{
		Environment:    "production",
		Minify:         true,
		OutputDir:      "public",
		ConfigFile:     "config.yaml",
		GC:             true,
		CleanupEnabled: true,
		Draft:          false,
		Future:         false,
		Expired:        false,
		EnvVars: map[string]string{
			"HUGO_ENV": "production",
		},
	}
}

// DefaultDockerBuildOptions returns default Docker build options
func DefaultDockerBuildOptions() *DockerBuildOptions {
	return &DockerBuildOptions{
		Dockerfile: "Dockerfile",
		Context:    ".",
		Tags:       []string{"latest"},
		Pull:       true,
		NoCache:    false,
		Squash:     false,
		Platform:   "linux/amd64",
		SecurityOpt: []string{
			"no-new-privileges:true",
		},
		BuildArgs: map[string]string{
			"BUILDKIT_INLINE_CACHE": "1",
		},
		Labels: map[string]string{
			"maintainer":   "eos-build-system",
			"build-system": "eos",
		},
	}
}

// DefaultBuildValidation returns default build validation settings
func DefaultBuildValidation() *BuildValidation {
	return &BuildValidation{
		EnableChecksums:     true,
		EnableSizeCheck:     true,
		MaxArtifactSize:     1024 * 1024 * 1024, // 1GB
		SecurityScanEnabled: true,
		LintingEnabled:      true,
		RequiredFiles: []string{
			"Dockerfile",
		},
		ForbiddenPatterns: []string{
			"*.tmp",
			"*.log",
			".git/**",
			"node_modules/**",
		},
	}
}

// DefaultBuildCache returns default cache configuration
func DefaultBuildCache() *BuildCache {
	return &BuildCache{
		Enabled:  true,
		Provider: "local",
		TTL:      24 * time.Hour,
		MaxSize:  5 * 1024 * 1024 * 1024, // 5GB
		Config: map[string]string{
			"cache_dir": "/tmp/eos-build-cache",
		},
	}
}

// Validate validates Hugo build options
func (opts *HugoBuildOptions) Validate() error {
	if opts.Environment == "" {
		return &BuildError{
			Type:      "validation",
			Stage:     "hugo_options",
			Message:   "environment cannot be empty",
			Timestamp: time.Now(),
		}
	}

	if opts.OutputDir == "" {
		return &BuildError{
			Type:      "validation",
			Stage:     "hugo_options",
			Message:   "output directory cannot be empty",
			Timestamp: time.Now(),
		}
	}

	return nil
}

// Validate validates Docker build options
func (opts *DockerBuildOptions) Validate() error {
	if opts.Dockerfile == "" {
		return &BuildError{
			Type:      "validation",
			Stage:     "docker_options",
			Message:   "dockerfile path cannot be empty",
			Timestamp: time.Now(),
		}
	}

	if opts.Context == "" {
		return &BuildError{
			Type:      "validation",
			Stage:     "docker_options",
			Message:   "build context cannot be empty",
			Timestamp: time.Now(),
		}
	}

	if len(opts.Tags) == 0 {
		return &BuildError{
			Type:      "validation",
			Stage:     "docker_options",
			Message:   "at least one tag must be specified",
			Timestamp: time.Now(),
		}
	}

	return nil
}
