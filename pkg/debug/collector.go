// pkg/debug/collector.go
// Diagnostic collection and execution framework

package debug

import (
	"context"
	"os"
	"time"
)

// NewCollector creates a new diagnostic collector
func NewCollector(serviceName string, formatter Formatter) *Collector {
	return &Collector{
		serviceName: serviceName,
		diagnostics: make([]*Diagnostic, 0),
		formatter:   formatter,
	}
}

// Add adds diagnostics to the collector
func (c *Collector) Add(diagnostics ...*Diagnostic) {
	c.diagnostics = append(c.diagnostics, diagnostics...)
}

// Run executes all diagnostics and generates a report
func (c *Collector) Run(ctx context.Context) (*Report, error) {
	hostname, _ := os.Hostname()

	report := &Report{
		ServiceName: c.serviceName,
		Timestamp:   time.Now(),
		Hostname:    hostname,
		Results:     make([]*Result, 0),
		Summary: &Summary{
			Total: len(c.diagnostics),
		},
		Metadata: make(map[string]interface{}),
	}

	startTime := time.Now()

	for _, diag := range c.diagnostics {
		// Check if diagnostic should run
		if diag.Condition != nil && !diag.Condition(ctx) {
			result := &Result{
				Name:     diag.Name,
				Category: diag.Category,
				Status:   StatusSkipped,
				Message:  "Condition not met, skipping",
			}
			report.Results = append(report.Results, result)
			report.Summary.Skipped++
			continue
		}

		// Run the diagnostic
		diagStart := time.Now()
		result, err := diag.Collect(ctx)
		diagDuration := time.Since(diagStart)

		if result == nil {
			result = &Result{
				Name:     diag.Name,
				Category: diag.Category,
			}
		}

		result.Duration = diagDuration

		if err != nil {
			result.Status = StatusError
			result.Error = err
			if result.Message == "" {
				result.Message = err.Error()
			}
		}

		// Ensure required fields are set
		if result.Name == "" {
			result.Name = diag.Name
		}
		if result.Category == "" {
			result.Category = diag.Category
		}

		report.Results = append(report.Results, result)

		// Update summary
		switch result.Status {
		case StatusOK:
			report.Summary.OK++
		case StatusWarning:
			report.Summary.Warnings++
		case StatusError:
			report.Summary.Errors++
		case StatusSkipped:
			report.Summary.Skipped++
		}
	}

	report.Summary.Duration = time.Since(startTime)

	return report, nil
}

// Format formats the report using the configured formatter
func (c *Collector) Format(report *Report) string {
	if c.formatter == nil {
		c.formatter = NewTextFormatter()
	}
	return c.formatter.Format(report)
}

// RunAndFormat is a convenience method that runs diagnostics and returns formatted output
func (c *Collector) RunAndFormat(ctx context.Context) (string, error) {
	report, err := c.Run(ctx)
	if err != nil {
		return "", err
	}
	return c.Format(report), nil
}
