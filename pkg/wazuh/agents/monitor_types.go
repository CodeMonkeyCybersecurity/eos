// Package agents provides agent monitoring and management functionality for Wazuh.
package agents

import "time"

// AgentMonitor represents an agent record for real-time monitoring and display.
// This type is used specifically for the agents monitoring/watch functionality
// and includes all fields needed for the monitoring dashboard.
type AgentMonitor struct {
	ID                string     `json:"id"`
	Name              *string    `json:"name"`
	IP                *string    `json:"ip"`
	OS                *string    `json:"os"`
	Registered        *time.Time `json:"registered"`
	LastSeen          *time.Time `json:"last_seen"`
	AgentVersion      *string    `json:"agent_version"`
	StatusText        *string    `json:"status_text"`
	NodeName          *string    `json:"node_name"`
	DisconnectionTime *time.Time `json:"disconnection_time"`
	APIFetchTimestamp *time.Time `json:"api_fetch_timestamp"`
}

// WatchConfig contains configuration for the agents watch/monitoring functionality.
type WatchConfig struct {
	DSN     string // PostgreSQL connection string
	Limit   int    // Number of agents to display
	Refresh int    // Refresh interval in seconds
}

// AgentStats contains summary statistics about agent status.
type AgentStats struct {
	Active  int // Number of active agents
	Total   int // Total number of agents
	Showing int // Number of agents currently displayed
}
