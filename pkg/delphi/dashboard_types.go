/* pkg/delphi/dashboard_types.go */

package delphi

import (
	"database/sql/driver"
	"time"
)

// ViewType represents different monitoring views available in the dashboard
type ViewType int

const (
	ViewPipelineHealth ViewType = iota
	ViewBottlenecks
	ViewParserPerformance
	ViewRecentFailures
	ViewDailySummary
)

// String returns the human-readable name for each view type
func (v ViewType) String() string {
	switch v {
	case ViewPipelineHealth:
		return "Pipeline Health"
	case ViewBottlenecks:
		return "Bottlenecks"
	case ViewParserPerformance:
		return "Parser Performance"
	case ViewRecentFailures:
		return "Recent Failures"
	case ViewDailySummary:
		return "Daily Summary"
	default:
		return "Unknown"
	}
}

// AlertState represents the possible states in the pipeline flow
type AlertState string

const (
	AlertStateNew        AlertState = "new"
	AlertStateEnriched   AlertState = "enriched"
	AlertStateAnalyzed   AlertState = "analyzed"
	AlertStateStructured AlertState = "structured"
	AlertStateFormatted  AlertState = "formatted"
	AlertStateSent       AlertState = "sent"
	AlertStateFailed     AlertState = "failed"
	AlertStateArchived   AlertState = "archived"
)

// Value implements the driver.Valuer interface for database operations
func (as AlertState) Value() (driver.Value, error) {
	return string(as), nil
}

// PipelineHealth represents data from the pipeline_health view
type PipelineHealth struct {
	State           AlertState `db:"state" json:"state"`
	Count           int        `db:"count" json:"count"`
	AvgAgeSeconds   float64    `db:"avg_age_seconds" json:"avg_age_seconds"`
	HealthStatus    string     `db:"health_status" json:"health_status"`
	OldestTimestamp time.Time  `db:"oldest_timestamp" json:"oldest_timestamp"`
}

// PipelineBottleneck represents data from the pipeline_bottlenecks view
type PipelineBottleneck struct {
	State              AlertState `db:"state" json:"state"`
	Count              int        `db:"count" json:"count"`
	AvgProcessingTime  float64    `db:"avg_processing_time" json:"avg_processing_time"`
	MaxProcessingTime  float64    `db:"max_processing_time" json:"max_processing_time"`
	BottleneckSeverity string     `db:"bottleneck_severity" json:"bottleneck_severity"`
}

// ParserPerformance represents data from the parser_performance view
type ParserPerformance struct {
	ParsedCount       int       `db:"parsed_count" json:"parsed_count"`
	SuccessfulCount   int       `db:"successful_count" json:"successful_count"`
	ErrorCount        int       `db:"error_count" json:"error_count"`
	SuccessRate       float64   `db:"success_rate" json:"success_rate"`
	AvgProcessingTime float64   `db:"avg_processing_time" json:"avg_processing_time"`
	LastParsed        time.Time `db:"last_parsed" json:"last_parsed"`
}

// RecentFailure represents data from the recent_failures view
type RecentFailure struct {
	ID           int        `db:"id" json:"id"`
	State        AlertState `db:"state" json:"state"`
	ErrorMessage string     `db:"error_message" json:"error_message"`
	FailedAt     time.Time  `db:"failed_at" json:"failed_at"`
	RetryCount   int        `db:"retry_count" json:"retry_count"`
	AgentName    string     `db:"agent_name" json:"agent_name"`
	AlertLevel   string     `db:"alert_level" json:"alert_level"`
	RuleID       string     `db:"rule_id" json:"rule_id"`
}

// DailyOperationsSummary represents data from the daily operations summary
type DailyOperationsSummary struct {
	Date                  time.Time `db:"date" json:"date"`
	TotalAlertsProcessed  int       `db:"total_alerts_processed" json:"total_alerts_processed"`
	TotalAlertsSuccessful int       `db:"total_alerts_successful" json:"total_alerts_successful"`
	TotalAlertsFailed     int       `db:"total_alerts_failed" json:"total_alerts_failed"`
	SuccessRate           float64   `db:"success_rate" json:"success_rate"`
	AvgProcessingTime     float64   `db:"avg_processing_time" json:"avg_processing_time"`
	TopFailureReasons     []string  `db:"top_failure_reasons" json:"top_failure_reasons"`
	PeakHour              int       `db:"peak_hour" json:"peak_hour"`
	PeakHourAlertCount    int       `db:"peak_hour_alert_count" json:"peak_hour_alert_count"`
}

// DashboardData aggregates all the monitoring data for the dashboard
type DashboardData struct {
	PipelineHealth    []PipelineHealth        `json:"pipeline_health"`
	Bottlenecks       []PipelineBottleneck    `json:"bottlenecks"`
	ParserPerformance *ParserPerformance      `json:"parser_performance"`
	RecentFailures    []RecentFailure         `json:"recent_failures"`
	DailySummary      *DailyOperationsSummary `json:"daily_summary"`
	LastUpdated       time.Time               `json:"last_updated"`
}

// HealthStatusIcon returns an icon for the health status
func (ph PipelineHealth) HealthStatusIcon() string {
	switch ph.HealthStatus {
	case "Healthy":
		return "✓"
	case "Monitor":
		return "⚠"
	case "Critical":
		return "✗"
	default:
		return "?"
	}
}

// SeverityIcon returns an icon for bottleneck severity
func (pb PipelineBottleneck) SeverityIcon() string {
	switch pb.BottleneckSeverity {
	case "Low":
		return "▵"
	case "Medium":
		return "⚠"
	case "High":
		return "▲"
	case "Critical":
		return ""
	default:
		return "?"
	}
}

// FormatDuration formats seconds into human-readable duration
func FormatDuration(seconds float64) string {
	if seconds < 1 {
		return "<1s"
	} else if seconds < 60 {
		return "%.0fs"
	} else if seconds < 3600 {
		return "%.1fm"
	} else if seconds < 86400 {
		return "%.1fh"
	} else {
		return "%.1fd"
	}
}

// FormatAge formats timestamp age into human-readable duration
func FormatAge(timestamp time.Time) string {
	age := time.Since(timestamp)
	return FormatDuration(age.Seconds())
}
