package vault

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PrintStorageSummary displays a summary of storage test results
func PrintStorageSummary(rc *eos_io.RuntimeContext, primary string, primaryPath string, primaryResult string, fallback string, fallbackResult string) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Displaying storage test summary",
		zap.String("primary", primary),
		zap.String("primary_result", primaryResult),
		zap.String("fallback", fallback),
		zap.String("fallback_result", fallbackResult))

	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, " Test Data Storage Summary")
	_, _ = fmt.Fprintf(os.Stderr, "  %s: %s\n", primary, primaryResult)
	if primaryResult == "SUCCESS" {
		_, _ = fmt.Fprintf(os.Stderr, "     Path: %s\n", primaryPath)
	}
	if fallback != "N/A" {
		_, _ = fmt.Fprintf(os.Stderr, "  %s: %s\n", fallback, fallbackResult)
		if fallbackResult == "SUCCESS" {
			_, _ = fmt.Fprintf(os.Stderr, "     Path: %s\n", diskFallbackPath())
		}
	}
	_, _ = fmt.Fprintln(os.Stderr, "")
}

// PrintData displays test data contents with source and path information
func PrintData(rc *eos_io.RuntimeContext, data map[string]any, source, path string) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Displaying test data contents",
		zap.String("source", source),
		zap.String("path", path),
		zap.Any("data", data))

	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, " Test Data Contents:")
	raw, _ := json.MarshalIndent(data, "", "  ")
	_, _ = fmt.Fprintln(os.Stderr, string(raw))
	_, _ = fmt.Fprintln(os.Stderr, "")

	PrintInspectSummary(rc, source, path)
}

// PrintInspectSummary displays a summary of test data inspection results
func PrintInspectSummary(rc *eos_io.RuntimeContext, source, path string) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Displaying test data inspection summary",
		zap.String("source", source),
		zap.String("path", path))

	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, " Test Data Inspection Summary")
	switch source {
	case "Vault":
		_, _ = fmt.Fprintf(os.Stderr, "   Source: %s\n", source)
	case "Disk":
		_, _ = fmt.Fprintf(os.Stderr, "   Source: %s\n", source)
	default:
		_, _ = fmt.Fprintf(os.Stderr, "  ❓ Source: %s\n", source)
	}
	_, _ = fmt.Fprintf(os.Stderr, "   Path: %s\n", path)
	_, _ = fmt.Fprintln(os.Stderr, "")
}