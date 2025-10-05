// pkg/debug/types.go
// Core types for the diagnostic framework

package debug

import (
	"context"
	"time"
)

// Status represents the health status of a diagnostic check
type Status string

const (
	StatusOK      Status = "OK"
	StatusWarning Status = "WARNING"
	StatusError   Status = "ERROR"
	StatusInfo    Status = "INFO"
	StatusSkipped Status = "SKIPPED"
)

// Result represents the outcome of a single diagnostic check
type Result struct {
	Name        string                 // Diagnostic name
	Category    string                 // Category (e.g., "Binary", "Configuration")
	Status      Status                 // Overall status
	Message     string                 // Human-readable summary
	Output      string                 // Detailed output (command output, file contents, etc.)
	Duration    time.Duration          // How long the check took
	Error       error                  // Error if check failed
	Metadata    map[string]interface{} // Additional structured data
	Remediation string                 // Suggested fix if status is not OK
}

// Diagnostic represents a single diagnostic check that can be executed
type Diagnostic struct {
	Name        string                                     // Diagnostic name
	Category    string                                     // Category for grouping
	Description string                                     // What this diagnostic checks
	Collect     func(ctx context.Context) (*Result, error) // Function to run the diagnostic
	Condition   func(ctx context.Context) bool             // Optional: only run if condition is true
}

// Report represents a complete diagnostic report with all results
type Report struct {
	ServiceName string                 // Service being diagnosed (e.g., "vault", "consul")
	Timestamp   time.Time              // When the report was generated
	Hostname    string                 // Host where diagnostics were run
	Results     []*Result              // All diagnostic results
	Summary     *Summary               // Summary statistics
	Metadata    map[string]interface{} // Additional report-level metadata
}

// Summary provides aggregate statistics about the diagnostic results
type Summary struct {
	Total    int
	OK       int
	Warnings int
	Errors   int
	Skipped  int
	Duration time.Duration
}

// Formatter defines the interface for formatting diagnostic reports
type Formatter interface {
	Format(*Report) string
}

// Collector runs a set of diagnostics and generates a report
type Collector struct {
	serviceName string
	diagnostics []*Diagnostic
	formatter   Formatter
}
