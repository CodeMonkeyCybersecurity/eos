// pkg/backup/config.go

package backup

import (
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// Config represents the backup configuration
type Config struct {
	// Default repository to use if not specified
	DefaultRepository string `yaml:"default_repository"`

	// Repository configurations
	Repositories map[string]Repository `yaml:"repositories"`

	// Backup profiles
	Profiles map[string]Profile `yaml:"profiles"`

	// Global settings
	Settings Settings `yaml:"settings"`
}

// Repository represents a restic repository configuration
type Repository struct {
	Name        string            `yaml:"name"`
	Backend     string            `yaml:"backend"` // local, sftp, s3, b2, azure, gs
	URL         string            `yaml:"url"`
	Environment map[string]string `yaml:"environment,omitempty"` // Backend-specific env vars
}

// Profile represents a backup profile configuration
type Profile struct {
	Name        string     `yaml:"name"`
	Description string     `yaml:"description"`
	Repository  string     `yaml:"repository"` // Reference to repository name
	Paths       []string   `yaml:"paths"`
	Excludes    []string   `yaml:"excludes,omitempty"`
	Tags        []string   `yaml:"tags,omitempty"`
	Host        string     `yaml:"host,omitempty"`
	Retention   *Retention `yaml:"retention,omitempty"`
	Schedule    *Schedule  `yaml:"schedule,omitempty"`
	Hooks       *Hooks     `yaml:"hooks,omitempty"`
}

// Retention defines retention policy
type Retention struct {
	KeepLast    int `yaml:"keep_last,omitempty"`
	KeepDaily   int `yaml:"keep_daily,omitempty"`
	KeepWeekly  int `yaml:"keep_weekly,omitempty"`
	KeepMonthly int `yaml:"keep_monthly,omitempty"`
	KeepYearly  int `yaml:"keep_yearly,omitempty"`
}

// Schedule defines backup scheduling
type Schedule struct {
	Cron       string `yaml:"cron,omitempty"`        // Cron expression
	OnCalendar string `yaml:"on_calendar,omitempty"` // Systemd OnCalendar format
}

// Hooks defines pre/post backup hooks
type Hooks struct {
	PreBackup  []string `yaml:"pre_backup,omitempty"`
	PostBackup []string `yaml:"post_backup,omitempty"`
	OnError    []string `yaml:"on_error,omitempty"`
}

// Settings contains global backup settings
type Settings struct {
	// Parallelism for backup operations
	Parallelism int `yaml:"parallelism,omitempty"`

	// Check repository health periodically
	CheckInterval string `yaml:"check_interval,omitempty"`

	// Default retention if not specified in profile
	DefaultRetention *Retention `yaml:"default_retention,omitempty"`

	// Notification settings
	Notifications Notifications `yaml:"notifications,omitempty"`
}

// Notifications defines notification settings
type Notifications struct {
	OnSuccess bool   `yaml:"on_success"`
	OnFailure bool   `yaml:"on_failure"`
	Method    string `yaml:"method"` // email, slack, webhook
	Target    string `yaml:"target"` // email address, webhook URL, etc.
}

// Snapshot represents a restic snapshot
type Snapshot struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	Tree     string    `json:"tree"`
	Paths    []string  `json:"paths"`
	Hostname string    `json:"hostname"`
	Username string    `json:"username"`
	Tags     []string  `json:"tags,omitempty"`
	Parent   string    `json:"parent,omitempty"`
}

// LoadConfig loads the backup configuration
func LoadConfig(rc *eos_io.RuntimeContext) (*Config, error) {
	logger := otelzap.Ctx(rc.Ctx)

	configPath := "/etc/eos/backup.yaml"
	logger.Info("Loading backup configuration",
		zap.String("path", configPath))

	// Check if config exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		logger.Info("No configuration file found, using defaults")
		return defaultConfig(), nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	logger.Info("Configuration loaded successfully",
		zap.Int("repositories", len(config.Repositories)),
		zap.Int("profiles", len(config.Profiles)))

	return &config, nil
}

// SaveConfig saves the backup configuration
func SaveConfig(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	configPath := "/etc/eos/backup.yaml"
	logger.Info("Saving backup configuration",
		zap.String("path", configPath))

	// Ensure directory exists
	if err := os.MkdirAll("/etc/eos", 0755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	// Validate before saving
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0640); err != nil {
		return fmt.Errorf("writing config file: %w", err)
	}

	logger.Info("Configuration saved successfully")
	return nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Check repositories
	if len(c.Repositories) == 0 {
		return fmt.Errorf("no repositories configured")
	}

	for name, repo := range c.Repositories {
		if repo.URL == "" {
			return fmt.Errorf("repository %q missing URL", name)
		}
		if repo.Backend == "" {
			return fmt.Errorf("repository %q missing backend type", name)
		}
	}

	// Check profiles
	for name, profile := range c.Profiles {
		if len(profile.Paths) == 0 {
			return fmt.Errorf("profile %q has no paths configured", name)
		}

		// Verify repository exists
		if profile.Repository != "" {
			if _, exists := c.Repositories[profile.Repository]; !exists {
				return fmt.Errorf("profile %q references unknown repository %q", name, profile.Repository)
			}
		}
	}

	// Check default repository
	if c.DefaultRepository != "" {
		if _, exists := c.Repositories[c.DefaultRepository]; !exists {
			return fmt.Errorf("default repository %q does not exist", c.DefaultRepository)
		}
	}

	return nil
}

// defaultConfig returns a default configuration
func defaultConfig() *Config {
	hostname, _ := os.Hostname()

	return &Config{
		DefaultRepository: "local",
		Repositories: map[string]Repository{
			"local": {
				Name:    "local",
				Backend: "local",
				URL:     "/var/lib/eos/backups",
			},
		},
		Profiles: map[string]Profile{
			"system": {
				Name:        "system",
				Description: "System configuration backup",
				Repository:  "local",
				Paths: []string{
					"/etc",
					"/var/lib/eos",
					"/opt/eos",
				},
				Excludes: []string{
					"/etc/ssl/private",
					"*.tmp",
					"*.cache",
				},
				Tags: []string{"system", hostname},
				Retention: &Retention{
					KeepLast:    7,
					KeepDaily:   7,
					KeepWeekly:  4,
					KeepMonthly: 12,
				},
			},
			"home": {
				Name:        "home",
				Description: "Home directories backup",
				Repository:  "local",
				Paths: []string{
					"/home",
				},
				Excludes: []string{
					"*/.cache",
					"*/.local/share/Trash",
					"*/Downloads",
					"*.tmp",
				},
				Tags: []string{"home", hostname},
				Retention: &Retention{
					KeepLast:    3,
					KeepDaily:   7,
					KeepWeekly:  4,
					KeepMonthly: 6,
				},
			},
		},
		Settings: Settings{
			Parallelism:   2,
			CheckInterval: "weekly",
			DefaultRetention: &Retention{
				KeepLast:    7,
				KeepDaily:   7,
				KeepWeekly:  4,
				KeepMonthly: 12,
			},
			Notifications: Notifications{
				OnSuccess: false,
				OnFailure: true,
			},
		},
	}
}
