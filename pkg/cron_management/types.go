package cron_management

import (
	"time"
)

// CronJob represents a crontab entry
type CronJob struct {
	ID          string    `json:"id"`
	Schedule    string    `json:"schedule"`
	Command     string    `json:"command"`
	Comment     string    `json:"comment,omitempty"`
	Environment []string  `json:"environment,omitempty"`
	User        string    `json:"user"`
	Enabled     bool      `json:"enabled"`
	LastRun     *time.Time `json:"last_run,omitempty"`
	NextRun     *time.Time `json:"next_run,omitempty"`
}

// CronListResult contains results of listing cron jobs
type CronListResult struct {
	Jobs      []CronJob `json:"jobs"`
	Count     int       `json:"count"`
	User      string    `json:"user"`
	Timestamp time.Time `json:"timestamp"`
	HasCrontab bool     `json:"has_crontab"`
}

// CronOperation represents a cron management operation
type CronOperation struct {
	Operation string    `json:"operation"`
	Job       *CronJob  `json:"job,omitempty"`
	JobCount  int       `json:"job_count,omitempty"`
	Success   bool      `json:"success"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	DryRun    bool      `json:"dry_run"`
	User      string    `json:"user"`
}

// CronConfig contains configuration for cron management
type CronConfig struct {
	DryRun      bool   `json:"dry_run" mapstructure:"dry_run"`
	User        string `json:"user" mapstructure:"user"`
	CreateBackup bool   `json:"create_backup" mapstructure:"create_backup"`
	BackupDir   string `json:"backup_dir" mapstructure:"backup_dir"`
	Verbose     bool   `json:"verbose" mapstructure:"verbose"`
}

// DefaultCronConfig returns a configuration with sensible defaults
func DefaultCronConfig() *CronConfig {
	return &CronConfig{
		DryRun:       false,
		User:         "", // Current user
		CreateBackup: true,
		BackupDir:    "/tmp/eos-cron-backups",
		Verbose:      true,
	}
}

// CronSchedulePresets defines common cron schedule patterns
var CronSchedulePresets = map[string]string{
	"hourly":   "0 * * * *",
	"daily":    "0 0 * * *",
	"weekly":   "0 0 * * 0",
	"monthly":  "0 0 1 * *",
	"yearly":   "0 0 1 1 *",
	"reboot":   "@reboot",
	"midnight": "@midnight",
}

// CronValidationResult represents the result of validating a cron expression
type CronValidationResult struct {
	Valid       bool      `json:"valid"`
	Expression  string    `json:"expression"`
	Description string    `json:"description"`
	NextRuns    []time.Time `json:"next_runs,omitempty"`
	Error       string    `json:"error,omitempty"`
}

// CronBackup represents a backup of crontab
type CronBackup struct {
	User      string    `json:"user"`
	Timestamp time.Time `json:"timestamp"`
	FilePath  string    `json:"file_path"`
	JobCount  int       `json:"job_count"`
}

// CronJobTemplate represents a template for creating cron jobs
type CronJobTemplate struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Schedule    string            `json:"schedule"`
	Command     string            `json:"command"`
	Variables   map[string]string `json:"variables,omitempty"`
	Category    string            `json:"category"`
}

// Common cron job templates
var CommonCronTemplates = []CronJobTemplate{
	{
		Name:        "system_backup",
		Description: "Daily system backup",
		Schedule:    "0 2 * * *",
		Command:     "/usr/local/bin/backup-system.sh",
		Category:    "backup",
	},
	{
		Name:        "log_rotation",
		Description: "Weekly log rotation",
		Schedule:    "0 0 * * 0",
		Command:     "/usr/sbin/logrotate /etc/logrotate.conf",
		Category:    "maintenance",
	},
	{
		Name:        "disk_cleanup",
		Description: "Daily temporary file cleanup",
		Schedule:    "0 1 * * *",
		Command:     "/usr/bin/find /tmp -type f -atime +7 -delete",
		Category:    "maintenance",
	},
	{
		Name:        "certificate_renewal",
		Description: "Daily SSL certificate renewal check",
		Schedule:    "0 3 * * *",
		Command:     "/usr/bin/certbot renew --quiet",
		Category:    "security",
	},
}

// CronFilterOptions defines filtering options for cron jobs
type CronFilterOptions struct {
	Enabled  *bool  `json:"enabled,omitempty"`
	Pattern  string `json:"pattern,omitempty"`
	Category string `json:"category,omitempty"`
}