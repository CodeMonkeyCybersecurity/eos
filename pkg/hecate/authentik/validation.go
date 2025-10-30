// pkg/hecate/authentik/validation.go
// Export validation and completeness checking

package authentik

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ExportValidationReport represents completeness of export
type ExportValidationReport struct {
	TotalFiles         int
	SuccessfulFiles    int
	FailedFiles        []string
	MissingFiles       []string
	EmptyFiles         []string
	CompletenessScore  float64 // 0-100
	CriticalMissing    []string
	NonCriticalMissing []string
}

// ExpectedExportFile defines metadata for an expected export file
type ExpectedExportFile struct {
	Filename    string
	Description string
	Critical    bool // If true, export is incomplete without this
	MinSize     int64 // Minimum expected file size in bytes
}

// GetExpectedExportFiles returns list of files that should be in a complete export
func GetExpectedExportFiles() []ExpectedExportFile {
	return []ExpectedExportFile{
		// Authentik API exports (critical)
		{Filename: "01_applications.json", Description: "Authentik applications", Critical: true, MinSize: 50},
		{Filename: "02_providers.json", Description: "OAuth2 providers", Critical: true, MinSize: 50},
		{Filename: "03_outposts.json", Description: "Authentik outposts", Critical: true, MinSize: 50},
		{Filename: "04_flows.json", Description: "Authentication flows", Critical: true, MinSize: 50},
		{Filename: "05_property_mappings.json", Description: "Property mappings (deprecated endpoint)", Critical: false, MinSize: 50},
		{Filename: "06_oauth_sources.json", Description: "OAuth sources", Critical: false, MinSize: 10},
		{Filename: "07_policies.json", Description: "Policies", Critical: false, MinSize: 10},
		{Filename: "08_stages.json", Description: "Authentication stages", Critical: true, MinSize: 50},
		{Filename: "09_property_mappings_scope.json", Description: "Scope property mappings", Critical: true, MinSize: 50},
		{Filename: "10_property_mappings_all.json", Description: "All property mappings", Critical: true, MinSize: 50},
		{Filename: "11_system_config.json", Description: "System configuration", Critical: false, MinSize: 10},
		{Filename: "12_tenants.json", Description: "Tenants", Critical: false, MinSize: 10},
		{Filename: "13_policy_bindings.json", Description: "Policy bindings", Critical: true, MinSize: 50},
		{Filename: "14_users.json", Description: "Users", Critical: false, MinSize: 50},
		{Filename: "15_groups.json", Description: "Groups", Critical: false, MinSize: 10},
		{Filename: "16_brands.json", Description: "Brands/themes", Critical: false, MinSize: 10},
		{Filename: "17_certificates.json", Description: "TLS certificates", Critical: false, MinSize: 10},
		{Filename: "18_events.json", Description: "Recent events/audit log", Critical: false, MinSize: 10},

		// Hecate configuration files (critical)
		{Filename: "19_Caddyfile.disk", Description: "Disk Caddyfile", Critical: true, MinSize: 100},
		{Filename: "19_Caddyfile.live.json", Description: "Live Caddy API config", Critical: true, MinSize: 500},
		{Filename: "20_docker-compose.disk.yml", Description: "Disk docker-compose.yml", Critical: true, MinSize: 500},
		{Filename: "20_docker-compose.runtime.json", Description: "Runtime container state", Critical: true, MinSize: 1000},

		// Reports and metadata
		{Filename: "21_DRIFT_REPORT.md", Description: "Configuration drift analysis", Critical: true, MinSize: 100},
		{Filename: "README.md", Description: "Export documentation", Critical: true, MinSize: 500},
	}
}

// ValidateExport checks completeness and quality of export
func ValidateExport(rc *eos_io.RuntimeContext, exportDir string) (*ExportValidationReport, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Validating export completeness",
		zap.String("export_dir", exportDir))

	report := &ExportValidationReport{
		FailedFiles:        []string{},
		MissingFiles:       []string{},
		EmptyFiles:         []string{},
		CriticalMissing:    []string{},
		NonCriticalMissing: []string{},
	}

	expectedFiles := GetExpectedExportFiles()
	report.TotalFiles = len(expectedFiles)

	// Check each expected file
	for _, expected := range expectedFiles {
		filePath := filepath.Join(exportDir, expected.Filename)

		// Check if file exists
		info, err := os.Stat(filePath)
		if os.IsNotExist(err) {
			report.MissingFiles = append(report.MissingFiles, expected.Filename)
			if expected.Critical {
				report.CriticalMissing = append(report.CriticalMissing, expected.Filename)
			} else {
				report.NonCriticalMissing = append(report.NonCriticalMissing, expected.Filename)
			}
			continue
		}

		if err != nil {
			report.FailedFiles = append(report.FailedFiles, expected.Filename)
			continue
		}

		// Check file size
		if info.Size() < expected.MinSize {
			report.EmptyFiles = append(report.EmptyFiles, expected.Filename)
			if expected.Critical {
				report.CriticalMissing = append(report.CriticalMissing, expected.Filename)
			}
			continue
		}

		// Additional validation for JSON files
		if filepath.Ext(expected.Filename) == ".json" {
			if !isValidJSON(filePath) {
				report.FailedFiles = append(report.FailedFiles, expected.Filename)
				continue
			}
		}

		// File is valid
		report.SuccessfulFiles++
	}

	// Calculate completeness score
	// Critical files = 70% of score, non-critical = 30%
	criticalFiles := 0
	successfulCritical := 0
	nonCriticalFiles := 0
	successfulNonCritical := 0

	for _, expected := range expectedFiles {
		if expected.Critical {
			criticalFiles++
			if !containsString(report.CriticalMissing, expected.Filename) &&
				!containsString(report.FailedFiles, expected.Filename) &&
				!containsString(report.EmptyFiles, expected.Filename) {
				successfulCritical++
			}
		} else {
			nonCriticalFiles++
			if !containsString(report.NonCriticalMissing, expected.Filename) &&
				!containsString(report.FailedFiles, expected.Filename) &&
				!containsString(report.EmptyFiles, expected.Filename) {
				successfulNonCritical++
			}
		}
	}

	criticalScore := 0.0
	if criticalFiles > 0 {
		criticalScore = (float64(successfulCritical) / float64(criticalFiles)) * 70.0
	}

	nonCriticalScore := 0.0
	if nonCriticalFiles > 0 {
		nonCriticalScore = (float64(successfulNonCritical) / float64(nonCriticalFiles)) * 30.0
	}

	report.CompletenessScore = criticalScore + nonCriticalScore

	logger.Info("Export validation complete",
		zap.Int("total_files", report.TotalFiles),
		zap.Int("successful", report.SuccessfulFiles),
		zap.Int("missing", len(report.MissingFiles)),
		zap.Int("failed", len(report.FailedFiles)),
		zap.Float64("completeness", report.CompletenessScore))

	return report, nil
}

// isValidJSON checks if file contains valid JSON
func isValidJSON(filePath string) bool {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}

	var js interface{}
	return json.Unmarshal(data, &js) == nil
}

// containsString checks if string slice contains value
func containsString(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}

// RenderValidationReport generates human-readable validation report
func RenderValidationReport(report *ExportValidationReport) string {
	var result string

	result += "# Export Validation Report\n\n"

	// Overall status
	if report.CompletenessScore >= 90.0 {
		result += "## Status: ✅ COMPLETE\n\n"
	} else if report.CompletenessScore >= 70.0 {
		result += "## Status: ⚠️ MOSTLY COMPLETE\n\n"
	} else if report.CompletenessScore >= 50.0 {
		result += "## Status: ⚠️ INCOMPLETE\n\n"
	} else {
		result += "## Status: ❌ CRITICALLY INCOMPLETE\n\n"
	}

	result += fmt.Sprintf("**Completeness Score**: %.1f%%\n\n", report.CompletenessScore)
	result += fmt.Sprintf("- **Total Expected Files**: %d\n", report.TotalFiles)
	result += fmt.Sprintf("- **Successful**: %d\n", report.SuccessfulFiles)
	result += fmt.Sprintf("- **Missing**: %d\n", len(report.MissingFiles))
	result += fmt.Sprintf("- **Failed**: %d\n", len(report.FailedFiles))
	result += fmt.Sprintf("- **Empty/Too Small**: %d\n\n", len(report.EmptyFiles))

	// Critical issues
	if len(report.CriticalMissing) > 0 {
		result += "## ❌ Critical Files Missing\n\n"
		result += "These files are REQUIRED for complete migration:\n\n"
		for _, file := range report.CriticalMissing {
			result += fmt.Sprintf("- `%s`\n", file)
		}
		result += "\n"
	}

	// Non-critical issues
	if len(report.NonCriticalMissing) > 0 {
		result += "## ⚠️ Non-Critical Files Missing\n\n"
		result += "These files are optional but recommended:\n\n"
		for _, file := range report.NonCriticalMissing {
			result += fmt.Sprintf("- `%s`\n", file)
		}
		result += "\n"
	}

	// Failed files
	if len(report.FailedFiles) > 0 {
		result += "## ❌ Files Failed Validation\n\n"
		result += "These files exist but failed validation (invalid JSON, corrupt, etc.):\n\n"
		for _, file := range report.FailedFiles {
			result += fmt.Sprintf("- `%s`\n", file)
		}
		result += "\n"
	}

	// Empty files
	if len(report.EmptyFiles) > 0 {
		result += "## ⚠️ Files Too Small/Empty\n\n"
		result += "These files are suspiciously small and may be incomplete:\n\n"
		for _, file := range report.EmptyFiles {
			result += fmt.Sprintf("- `%s`\n", file)
		}
		result += "\n"
	}

	// Recommendations
	result += "## Recommendations\n\n"
	if report.CompletenessScore < 70.0 {
		result += "1. **Re-run export**: `eos update hecate --export`\n"
		result += "2. **Check Authentik API token**: Ensure AUTHENTIK_BOOTSTRAP_TOKEN is valid\n"
		result += "3. **Verify Caddy is running**: `docker ps | grep caddy`\n"
		result += "4. **Check file permissions**: Ensure eos can write to export directory\n\n"
	} else if report.CompletenessScore < 90.0 {
		result += "1. **Export is mostly complete** - missing files are likely optional\n"
		result += "2. **Review non-critical missing files** to determine if needed\n\n"
	} else {
		result += "✅ **Export is complete** - all critical files present and valid\n\n"
	}

	return result
}
