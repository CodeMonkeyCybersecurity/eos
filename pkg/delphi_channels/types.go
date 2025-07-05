package delphi_channels

import (
	"time"
)

// StandardChannels defines the expected notification channels for the Delphi pipeline
var StandardChannels = map[string]string{
	"new_alert":        "delphi-listener → delphi-agent-enricher",
	"agent_enriched":   "delphi-agent-enricher → llm-worker",
	"new_response":     "llm-worker → email-structurer",
	"alert_structured": "email-structurer → email-formatter",
	"alert_formatted":  "email-formatter → email-sender",
	"alert_sent":       "email-sender → final (archive/metrics)",
}

// WorkerConfig defines the notification channel configuration for a worker
type WorkerConfig struct {
	NotifyChannels []string `json:"notify_channels" mapstructure:"notify_channels"`
	ListenChannels []string `json:"listen_channels" mapstructure:"listen_channels"`
}

// StandardWorkerConfigs defines the expected channel configuration for each worker
var StandardWorkerConfigs = map[string]WorkerConfig{
	"delphi-listener.py": {
		NotifyChannels: []string{"new_alert"},
		ListenChannels: []string{},
	},
	"delphi-agent-enricher.py": {
		NotifyChannels: []string{"agent_enriched"},
		ListenChannels: []string{"new_alert"},
	},
	"llm-worker.py": {
		NotifyChannels: []string{"new_response"},
		ListenChannels: []string{"agent_enriched"},
	},
	"email-structurer.py": {
		NotifyChannels: []string{"alert_structured"},
		ListenChannels: []string{"new_response"},
	},
	"email-formatter.py": {
		NotifyChannels: []string{"alert_formatted"},
		ListenChannels: []string{"alert_structured"},
	},
	"email-sender.py": {
		NotifyChannels: []string{"alert_sent"},
		ListenChannels: []string{"alert_formatted"},
	},
}

// ChannelChange represents a change made to a worker file
type ChannelChange struct {
	File        string    `json:"file"`
	Type        string    `json:"type"` // listen_channel, notify_channel, pg_notify, listen_statement
	OldValue    string    `json:"old_value"`
	NewValue    string    `json:"new_value"`
	LineNumber  int       `json:"line_number,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// StandardizationResult contains the results of channel standardization
type StandardizationResult struct {
	Success       bool            `json:"success"`
	Timestamp     time.Time       `json:"timestamp"`
	WorkersDir    string          `json:"workers_dir"`
	Changes       []ChannelChange `json:"changes"`
	Errors        []string        `json:"errors"`
	FilesUpdated  []string        `json:"files_updated"`
	FilesSkipped  []string        `json:"files_skipped"`
	BackupsCreated []string       `json:"backups_created"`
}

// ChannelPattern represents a regex pattern for finding and replacing channel references
type ChannelPattern struct {
	Pattern     string
	Replacement string
	Type        string // listen_channel, notify_channel, pg_notify, listen_statement
}

// WorkerChannelInfo contains information about a worker's current channel configuration
type WorkerChannelInfo struct {
	Filename       string   `json:"filename"`
	ListenChannels []string `json:"listen_channels"`
	NotifyChannels []string `json:"notify_channels"`
	IsCorrect      bool     `json:"is_correct"`
	Issues         []string `json:"issues"`
}

// ChannelStandardizerConfig contains configuration for the channel standardizer
type ChannelStandardizerConfig struct {
	WorkersDir      string            `json:"workers_dir" mapstructure:"workers_dir"`
	CreateBackups   bool              `json:"create_backups" mapstructure:"create_backups"`
	DryRun          bool              `json:"dry_run" mapstructure:"dry_run"`
	ExcludePatterns []string          `json:"exclude_patterns" mapstructure:"exclude_patterns"`
	CustomChannels  map[string]string `json:"custom_channels,omitempty" mapstructure:"custom_channels"`
}

// DefaultChannelStandardizerConfig returns a configuration with sensible defaults
func DefaultChannelStandardizerConfig() *ChannelStandardizerConfig {
	return &ChannelStandardizerConfig{
		WorkersDir:      "/opt/stackstorm/packs/delphi/actions/python_workers",
		CreateBackups:   true,
		DryRun:          false,
		ExcludePatterns: []string{"*.bak", "*.old", "__pycache__", ".git"},
	}
}