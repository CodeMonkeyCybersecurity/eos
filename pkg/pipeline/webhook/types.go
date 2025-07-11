package webhook

import "time"

// WebhookStatus represents the status of webhook deployment
// Migrated from cmd/read/pipeline_webhook_status.go WebhookStatus
type WebhookStatus struct {
	Timestamp       time.Time         `json:"timestamp"`
	Deployed        bool              `json:"deployed"`
	ConfigPresent   bool              `json:"config_present"`
	FilesPresent    map[string]bool   `json:"files_present"`
	Permissions     map[string]string `json:"permissions"`
	EnvironmentVars map[string]bool   `json:"environment_vars"`
	Connectivity    bool              `json:"connectivity"`
	Issues          []string          `json:"issues"`
}