package system_services

import (
	"time"
)

// ServiceState represents the state of a systemd service
type ServiceState string

const (
	ServiceStateActive       ServiceState = "active"
	ServiceStateInactive     ServiceState = "inactive"
	ServiceStateFailed       ServiceState = "failed"
	ServiceStateActivating   ServiceState = "activating"
	ServiceStateDeactivating ServiceState = "deactivating"
)

// ServiceInfo represents information about a systemd service
type ServiceInfo struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	State       ServiceState `json:"state"`
	Enabled     bool         `json:"enabled"`
	Running     bool         `json:"running"`
	LoadState   string       `json:"load_state"`
	ActiveState string       `json:"active_state"`
	SubState    string       `json:"sub_state"`
	UnitFile    string       `json:"unit_file,omitempty"`
}

// ServiceOperation represents an operation performed on a service
type ServiceOperation struct {
	Service   string    `json:"service"`
	Operation string    `json:"operation"`
	Success   bool      `json:"success"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	DryRun    bool      `json:"dry_run"`
}

// ServiceListResult contains results of listing services
type ServiceListResult struct {
	Services  []ServiceInfo `json:"services"`
	Count     int           `json:"count"`
	Filter    string        `json:"filter,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
}

// ServiceConfig contains configuration for service management
type ServiceConfig struct {
	DryRun       bool     `json:"dry_run" mapstructure:"dry_run"`
	Sudo         bool     `json:"sudo" mapstructure:"sudo"`
	Timeout      int      `json:"timeout" mapstructure:"timeout"`
	ShowAll      bool     `json:"show_all" mapstructure:"show_all"`
	FollowLogs   bool     `json:"follow_logs" mapstructure:"follow_logs"`
	LogLines     int      `json:"log_lines" mapstructure:"log_lines"`
	ServiceTypes []string `json:"service_types" mapstructure:"service_types"`
}

// DefaultServiceConfig returns a configuration with sensible defaults
func DefaultServiceConfig() *ServiceConfig {
	return &ServiceConfig{
		DryRun:       false,
		Sudo:         true,
		Timeout:      30,
		ShowAll:      false,
		FollowLogs:   false,
		LogLines:     50,
		ServiceTypes: []string{"service"},
	}
}

// ServiceFilterOptions defines filtering options for service listing
type ServiceFilterOptions struct {
	State       []ServiceState `json:"state,omitempty"`
	Enabled     *bool          `json:"enabled,omitempty"`
	Running     *bool          `json:"running,omitempty"`
	Pattern     string         `json:"pattern,omitempty"`
	ServiceType string         `json:"service_type,omitempty"`
}

// LogsOptions defines options for viewing service logs
type LogsOptions struct {
	Follow     bool   `json:"follow"`
	Lines      int    `json:"lines"`
	Since      string `json:"since,omitempty"`
	Until      string `json:"until,omitempty"`
	Priority   string `json:"priority,omitempty"`
	Unit       string `json:"unit"`
	Grep       string `json:"grep,omitempty"`
	Reverse    bool   `json:"reverse"`
	NoHostname bool   `json:"no_hostname"`
}
