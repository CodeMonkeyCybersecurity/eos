// Package backups provides Wazuh MSSP backup management functionality.
package backups

import "time"

// BackupListItem represents a single backup in the MSSP platform.
type BackupListItem struct {
	BackupID    string        `json:"backup_id"`
	CustomerID  string        `json:"customer_id"`
	CompanyName string        `json:"company_name"`
	Type        string        `json:"type"`
	Status      string        `json:"status"`
	SizeGB      float64       `json:"size_gb"`
	CreatedAt   time.Time     `json:"created_at"`
	Duration    time.Duration `json:"duration"`
	Location    string        `json:"location"`
}

// BackupList represents a list of backups with summary information.
type BackupList struct {
	Backups   []BackupListItem `json:"backups"`
	Total     int              `json:"total"`
	Summary   BackupSummary    `json:"summary"`
	Timestamp time.Time        `json:"timestamp"`
}

// BackupSummary provides summary statistics for backups.
type BackupSummary struct {
	TotalBackups int       `json:"total_backups"`
	TotalSizeGB  float64   `json:"total_size_gb"`
	OldestBackup time.Time `json:"oldest_backup"`
	LatestBackup time.Time `json:"latest_backup"`
}
