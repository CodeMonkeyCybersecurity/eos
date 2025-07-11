package alerts

import (
	"time"
)

// Alert represents an alert record for display
// Migrated from cmd/read/pipeline_alerts.go Alert struct
type Alert struct {
	ID                 int64      `json:"id"`
	AgentID            string     `json:"agent_id"`
	RuleID             int        `json:"rule_id"`
	RuleLevel          int        `json:"rule_level"`
	RuleDesc           string     `json:"rule_desc"`
	IngestTimestamp    time.Time  `json:"ingest_timestamp"`
	State              string     `json:"state"`
	PromptSentAt       *time.Time `json:"prompt_sent_at"`
	ResponseReceivedAt *time.Time `json:"response_received_at"`
	AlertSentAt        *time.Time `json:"alert_sent_at"`
}