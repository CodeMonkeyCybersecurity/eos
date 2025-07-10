// Package output provides utilities for formatting and displaying output
package output

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/security_permissions"
)

// TextWriter provides utilities for formatted text output
type TextWriter struct {
	writer io.Writer
}

// NewTextWriter creates a new TextWriter that writes to stdout
func NewTextWriter() *TextWriter {
	return &TextWriter{writer: os.Stdout}
}

// NewTextWriterTo creates a new TextWriter that writes to the specified writer
func NewTextWriterTo(w io.Writer) *TextWriter {
	return &TextWriter{writer: w}
}

// WritePermissionResult writes a permission fix result in text format
func (tw *TextWriter) WritePermissionResult(result *security_permissions.PermissionFixResult, dryRun bool) error {
	if dryRun {
		fmt.Fprintln(tw.writer, "🔒 Security Permissions Check (DRY RUN)")
	} else {
		fmt.Fprintln(tw.writer, "🔒 Security Permissions Fix")
	}
	fmt.Fprintln(tw.writer, strings.Repeat("=", 50))

	for category, scanResult := range result.Results {
		fmt.Fprintf(tw.writer, "\n %s (%d files checked)\n", strings.ToUpper(category), scanResult.TotalChecks)

		for _, check := range scanResult.Checks {
			if check.Error != "" {
				fmt.Fprintf(tw.writer, "   ❌ %s: %s\n", check.Rule.Description, check.Error)
			} else if check.NeedsChange {
				if dryRun {
					fmt.Fprintf(tw.writer, "    %s: %o → %o (would fix)\n",
						check.Rule.Description, check.CurrentMode, check.ExpectedMode)
				} else {
					fmt.Fprintf(tw.writer, "    %s: %o → %o (fixed)\n",
						check.Rule.Description, check.CurrentMode, check.ExpectedMode)
				}
			} else {
				fmt.Fprintf(tw.writer, "    %s: %o (correct)\n",
					check.Rule.Description, check.CurrentMode)
			}
		}
	}

	// Summary
	fmt.Fprintln(tw.writer, "\n" + strings.Repeat("=", 50))
	fmt.Fprintf(tw.writer, " Summary: %d files processed, %d fixed, %d skipped\n",
		result.Summary.TotalFiles, result.Summary.FilesFixed, result.Summary.FilesSkipped)

	if len(result.Summary.Errors) > 0 {
		fmt.Fprintf(tw.writer, "❌ Errors: %d\n", len(result.Summary.Errors))
		for _, err := range result.Summary.Errors {
			fmt.Fprintf(tw.writer, "   • %s\n", err)
		}
	}

	if result.Summary.Success {
		if dryRun && result.Summary.FilesFixed > 0 {
			fmt.Fprintln(tw.writer, " Run without --dry-run to apply changes")
		} else if !dryRun {
			fmt.Fprintln(tw.writer, " Permission fixes completed successfully")
		} else {
			fmt.Fprintln(tw.writer, " All permissions are correctly configured")
		}
		fmt.Fprintln(tw.writer, strings.Repeat("=", 50))
		return nil
	} else {
		fmt.Fprintln(tw.writer, "❌ Permission operation completed with errors")
		fmt.Fprintln(tw.writer, strings.Repeat("=", 50))
		return fmt.Errorf("permission operation failed")
	}
}

// WriteLines writes multiple lines of text
func (tw *TextWriter) WriteLines(lines ...string) error {
	for _, line := range lines {
		if _, err := fmt.Fprintln(tw.writer, line); err != nil {
			return err
		}
	}
	return nil
}

// WriteSection writes a section header with content
func (tw *TextWriter) WriteSection(header string, content string) error {
	if _, err := fmt.Fprintf(tw.writer, "%s\n%s\n%s\n", header, strings.Repeat("=", len(header)), content); err != nil {
		return err
	}
	return nil
}

// TextToStdout writes a permission result as formatted text to stdout
func TextToStdout(result *security_permissions.PermissionFixResult, dryRun bool) error {
	tw := NewTextWriter()
	return tw.WritePermissionResult(result, dryRun)
}

// FormatPermissionResult formats a permission result as text and returns it as a string
func FormatPermissionResult(result *security_permissions.PermissionFixResult, dryRun bool) (string, error) {
	var buf strings.Builder
	tw := NewTextWriterTo(&buf)
	if err := tw.WritePermissionResult(result, dryRun); err != nil {
		return "", err
	}
	return buf.String(), nil
}
