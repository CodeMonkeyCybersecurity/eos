// pkg/debug/formatters.go
// Output formatters for diagnostic reports

package debug

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// TextFormatter formats reports as human-readable text
type TextFormatter struct {
	ShowMetadata bool
	ShowSkipped  bool
}

// NewTextFormatter creates a new text formatter with default settings
func NewTextFormatter() *TextFormatter {
	return &TextFormatter{
		ShowMetadata: false,
		ShowSkipped:  false,
	}
}

// Format formats a report as text
func (f *TextFormatter) Format(report *Report) string {
	var b strings.Builder

	// Header
	b.WriteString(strings.Repeat("=", 80))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("%s DIAGNOSTIC REPORT\n", strings.ToUpper(report.ServiceName)))
	b.WriteString(fmt.Sprintf("Generated: %s\n", report.Timestamp.Format("2006-01-02 15:04:05 MST")))
	b.WriteString(fmt.Sprintf("Hostname: %s\n", report.Hostname))
	b.WriteString(strings.Repeat("=", 80))
	b.WriteString("\n\n")

	// Group results by category
	categories := make(map[string][]*Result)
	for _, result := range report.Results {
		if !f.ShowSkipped && result.Status == StatusSkipped {
			continue
		}
		category := result.Category
		if category == "" {
			category = "General"
		}
		categories[category] = append(categories[category], result)
	}

	// Print each category
	for category, results := range categories {
		b.WriteString(fmt.Sprintf("\n%s\n", strings.Repeat("=", 80)))
		b.WriteString(fmt.Sprintf("%s\n", category))
		b.WriteString(fmt.Sprintf("%s\n\n", strings.Repeat("=", 80)))

		for _, result := range results {
			b.WriteString(f.formatResult(result))
			b.WriteString("\n")
		}
	}

	// Summary
	b.WriteString(fmt.Sprintf("\n%s\n", strings.Repeat("=", 80)))
	b.WriteString("SUMMARY\n")
	b.WriteString(fmt.Sprintf("%s\n\n", strings.Repeat("=", 80)))
	b.WriteString(fmt.Sprintf("Total Checks:  %d\n", report.Summary.Total))
	b.WriteString(fmt.Sprintf("✓ Passed:      %d\n", report.Summary.OK))
	b.WriteString(fmt.Sprintf("⚠ Warnings:    %d\n", report.Summary.Warnings))
	b.WriteString(fmt.Sprintf("✗ Errors:      %d\n", report.Summary.Errors))
	if f.ShowSkipped {
		b.WriteString(fmt.Sprintf("- Skipped:     %d\n", report.Summary.Skipped))
	}
	b.WriteString(fmt.Sprintf("Duration:      %s\n", report.Summary.Duration.Round(time.Millisecond)))

	b.WriteString(fmt.Sprintf("\n%s\n", strings.Repeat("=", 80)))
	b.WriteString("END OF DIAGNOSTIC REPORT\n")
	b.WriteString(strings.Repeat("=", 80))
	b.WriteString("\n")

	return b.String()
}

func (f *TextFormatter) formatResult(result *Result) string {
	var b strings.Builder

	// Status indicator
	statusSymbol := ""
	switch result.Status {
	case StatusOK:
		statusSymbol = "✓"
	case StatusWarning:
		statusSymbol = "⚠"
	case StatusError:
		statusSymbol = "✗"
	case StatusInfo:
		statusSymbol = "ℹ"
	case StatusSkipped:
		statusSymbol = "-"
	}

	b.WriteString(fmt.Sprintf("--- %s %s ---\n", statusSymbol, result.Name))

	if result.Message != "" {
		b.WriteString(fmt.Sprintf("Status: %s\n", result.Message))
	}

	if result.Output != "" {
		b.WriteString("\nOutput:\n")
		// Indent output
		lines := strings.Split(result.Output, "\n")
		for _, line := range lines {
			if line != "" {
				b.WriteString(fmt.Sprintf("  %s\n", line))
			}
		}
	}

	if result.Error != nil {
		b.WriteString(fmt.Sprintf("\nError: %v\n", result.Error))
	}

	if result.Remediation != "" {
		b.WriteString(fmt.Sprintf("\nRemediation:\n  %s\n", result.Remediation))
	}

	if f.ShowMetadata && len(result.Metadata) > 0 {
		b.WriteString("\nMetadata:\n")
		for k, v := range result.Metadata {
			b.WriteString(fmt.Sprintf("  %s: %v\n", k, v))
		}
	}

	if result.Duration > 0 {
		b.WriteString(fmt.Sprintf("Duration: %s\n", result.Duration.Round(time.Millisecond)))
	}

	return b.String()
}

// JSONFormatter formats reports as JSON
type JSONFormatter struct {
	Pretty bool
}

// NewJSONFormatter creates a new JSON formatter
func NewJSONFormatter(pretty bool) *JSONFormatter {
	return &JSONFormatter{Pretty: pretty}
}

// Format formats a report as JSON
func (f *JSONFormatter) Format(report *Report) string {
	var data []byte
	var err error

	if f.Pretty {
		data, err = json.MarshalIndent(report, "", "  ")
	} else {
		data, err = json.Marshal(report)
	}

	if err != nil {
		return fmt.Sprintf(`{"error": "failed to marshal report: %s"}`, err.Error())
	}

	return string(data)
}

// MarkdownFormatter formats reports as GitHub-flavored Markdown
type MarkdownFormatter struct{}

// NewMarkdownFormatter creates a new Markdown formatter
func NewMarkdownFormatter() *MarkdownFormatter {
	return &MarkdownFormatter{}
}

// Format formats a report as Markdown
func (f *MarkdownFormatter) Format(report *Report) string {
	var b strings.Builder

	// Header
	b.WriteString(fmt.Sprintf("# %s Diagnostic Report\n\n", strings.Title(report.ServiceName)))
	b.WriteString(fmt.Sprintf("**Generated:** %s  \n", report.Timestamp.Format("2006-01-02 15:04:05 MST")))
	b.WriteString(fmt.Sprintf("**Hostname:** %s  \n\n", report.Hostname))

	// Summary table
	b.WriteString("## Summary\n\n")
	b.WriteString("| Metric | Count |\n")
	b.WriteString("|--------|-------|\n")
	b.WriteString(fmt.Sprintf("| Total Checks | %d |\n", report.Summary.Total))
	b.WriteString(fmt.Sprintf("| ✓ Passed | %d |\n", report.Summary.OK))
	b.WriteString(fmt.Sprintf("| ⚠ Warnings | %d |\n", report.Summary.Warnings))
	b.WriteString(fmt.Sprintf("| ✗ Errors | %d |\n", report.Summary.Errors))
	b.WriteString(fmt.Sprintf("| Duration | %s |\n\n", report.Summary.Duration.Round(time.Millisecond)))

	// Group results by category
	categories := make(map[string][]*Result)
	for _, result := range report.Results {
		if result.Status == StatusSkipped {
			continue
		}
		category := result.Category
		if category == "" {
			category = "General"
		}
		categories[category] = append(categories[category], result)
	}

	// Print each category
	for category, results := range categories {
		b.WriteString(fmt.Sprintf("## %s\n\n", category))

		for _, result := range results {
			statusSymbol := ""
			switch result.Status {
			case StatusOK:
				statusSymbol = "✓"
			case StatusWarning:
				statusSymbol = "⚠"
			case StatusError:
				statusSymbol = "✗"
			case StatusInfo:
				statusSymbol = "ℹ"
			}

			b.WriteString(fmt.Sprintf("### %s %s\n\n", statusSymbol, result.Name))

			if result.Message != "" {
				b.WriteString(fmt.Sprintf("**Status:** %s\n\n", result.Message))
			}

			if result.Output != "" {
				b.WriteString("```\n")
				b.WriteString(result.Output)
				b.WriteString("\n```\n\n")
			}

			if result.Error != nil {
				b.WriteString(fmt.Sprintf("**Error:** `%s`\n\n", result.Error.Error()))
			}

			if result.Remediation != "" {
				b.WriteString(fmt.Sprintf("**Remediation:**\n```bash\n%s\n```\n\n", result.Remediation))
			}
		}
	}

	return b.String()
}
