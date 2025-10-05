// pkg/debug/vault/analyzer.go
// Vault-specific analysis rules and insights

package vault

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/debug"
)

// VaultAnalysisRules returns vault-specific analysis rules
func VaultAnalysisRules() []debug.AnalysisRule {
	return []debug.AnalysisRule{
		DetectSealedVault,
		DetectTLSIssues,
		DetectValidationCommand,
		DetectDuplicateBinaries,
		DetectDeprecatedSystemd,
		DetectInitialization,
	}
}

// DetectSealedVault checks if vault is sealed and provides guidance
func DetectSealedVault(report *debug.Report, analysis *debug.Analysis) {
	for _, result := range report.Results {
		if result.Name == "HTTP Health Check" && result.Output != "" {
			if strings.Contains(result.Output, `"sealed":true`) {
				analysis.Warnings = append(analysis.Warnings, debug.Warning{
					Message:        "Vault is sealed (this is normal after restart)",
					Recommendation: "Unseal Vault: export VAULT_ADDR=http://127.0.0.1:8200 && vault operator unseal",
				})

				if !strings.Contains(result.Output, `"initialized":true`) {
					analysis.Recommendations = append(analysis.Recommendations,
						"Initialize Vault: vault operator init (save the keys!)")
				} else {
					analysis.Recommendations = append(analysis.Recommendations,
						"Unseal Vault with your unseal keys: vault operator unseal")
				}
			}
		}
	}
}

// DetectTLSIssues checks for TLS configuration problems
func DetectTLSIssues(report *debug.Report, analysis *debug.Analysis) {
	for _, result := range report.Results {
		if result.Category == "Security" && strings.Contains(result.Name, "TLS") {
			if tls_enabled, ok := result.Metadata["tls_enabled"].(bool); ok {
				if !tls_enabled {
					// TLS is disabled
					analysis.Warnings = append(analysis.Warnings, debug.Warning{
						Message:        "TLS is disabled - all Vault traffic is unencrypted",
						Recommendation: "Enable TLS for production: eos repair vault --fix-tls",
					})
					analysis.Recommendations = append(analysis.Recommendations,
						"For production use, enable TLS to encrypt all Vault communication")
				} else if result.Status == debug.StatusError {
					// TLS enabled but has issues
					analysis.MajorIssues = append(analysis.MajorIssues, debug.Issue{
						Severity:    "major",
						Component:   "TLS Configuration",
						Description: result.Message,
						Impact:      "Vault cannot start or connections will fail",
						Remediation: result.Remediation,
					})
				}
			}
		}
	}
}

// DetectValidationCommand checks if vault validate works
func DetectValidationCommand(report *debug.Report, analysis *debug.Analysis) {
	for _, result := range report.Results {
		if result.Name == "Configuration Validation" {
			if result.Output != "" && (strings.Contains(result.Output, "exit status 127") ||
				strings.Contains(result.Output, "command not found")) {
				analysis.MajorIssues = append(analysis.MajorIssues, debug.Issue{
					Severity:    "major",
					Component:   "Vault CLI",
					Description: "Vault 'validate' subcommand not found or not working",
					Impact:      "Cannot validate configurations before applying changes",
					Remediation: "Check Vault version and installation: vault version",
				})

				analysis.Recommendations = append(analysis.Recommendations,
					"Verify Vault installation: which vault && vault version")
			}
		}
	}
}

// DetectDuplicateBinaries checks for multiple vault binaries
func DetectDuplicateBinaries(report *debug.Report, analysis *debug.Analysis) {
	binaryPaths := []string{}

	for _, result := range report.Results {
		if result.Category == "Installation" && strings.Contains(result.Name, "Binary") {
			if exists, ok := result.Metadata["exists"].(bool); ok && exists {
				if path, ok := result.Metadata["path"].(string); ok {
					binaryPaths = append(binaryPaths, path)
				}
			}
		}
	}

	if len(binaryPaths) > 1 {
		analysis.Warnings = append(analysis.Warnings, debug.Warning{
			Message: fmt.Sprintf("Multiple Vault binaries found at: %s",
				strings.Join(binaryPaths, ", ")),
			Recommendation: "Remove old binaries to avoid confusion. Keep only /usr/local/bin/vault",
		})

		analysis.Recommendations = append(analysis.Recommendations,
			"Remove duplicate binaries to prevent PATH conflicts")
	}
}

// DetectDeprecatedSystemd checks for deprecated systemd directives
func DetectDeprecatedSystemd(report *debug.Report, analysis *debug.Analysis) {
	for _, result := range report.Results {
		if result.Category == "Systemd" && strings.Contains(result.Output, "Capabilities=") {
			if strings.Contains(result.Output, "has been removed") ||
				strings.Contains(result.Output, "deprecated") {
				analysis.MinorIssues = append(analysis.MinorIssues, debug.Issue{
					Severity:    "minor",
					Component:   "Systemd Service",
					Description: "Service file uses deprecated 'Capabilities=' directive",
					Impact:      "Systemd warnings in logs, may break in future systemd versions",
					Remediation: "Update /etc/systemd/system/vault.service to use 'AmbientCapabilities=' instead",
				})

				analysis.Recommendations = append(analysis.Recommendations,
					"Update systemd service file: sed -i 's/Capabilities=/AmbientCapabilities=/' /etc/systemd/system/vault.service && systemctl daemon-reload")
			}
		}
	}
}

// DetectInitialization checks vault initialization status
func DetectInitialization(report *debug.Report, analysis *debug.Analysis) {
	for _, result := range report.Results {
		if result.Name == "HTTP Health Check" && result.Output != "" {
			if strings.Contains(result.Output, `"initialized":false`) {
				analysis.CriticalIssues = append(analysis.CriticalIssues, debug.Issue{
					Severity:    "critical",
					Component:   "Vault Initialization",
					Description: "Vault is NOT initialized",
					Impact:      "Vault cannot be used until initialized",
					Remediation: "Initialize Vault: vault operator init (SAVE THE KEYS SECURELY!)",
				})

				analysis.Recommendations = append(analysis.Recommendations,
					"IMPORTANT: Initialize Vault and securely store the unseal keys and root token")
			}
		}
	}
}

// GenerateNextSteps creates actionable next steps based on vault state
func GenerateNextSteps(report *debug.Report, analysis *debug.Analysis) []string {
	steps := []string{}

	// Priority 1: Critical issues
	if len(analysis.CriticalIssues) > 0 {
		for _, issue := range analysis.CriticalIssues {
			if issue.Remediation != "" {
				steps = append(steps, issue.Remediation)
			}
		}
	}

	// Priority 2: Service not running
	serviceRunning := false
	for _, result := range report.Results {
		if result.Category == "Systemd" && result.Status == debug.StatusOK {
			serviceRunning = true
			break
		}
	}

	if !serviceRunning {
		steps = append(steps, "Start Vault service: systemctl start vault")
	}

	// Priority 3: Vault sealed
	if containsRecommendation(analysis.Recommendations, "unseal") {
		steps = append(steps, "Unseal Vault with unseal keys")
	}

	// Priority 4: TLS issues
	if containsRecommendation(analysis.Recommendations, "TLS") {
		steps = append(steps, "(Optional) Enable TLS: eos repair vault --fix-tls")
	}

	// If no issues, suggest verification
	if len(steps) == 0 {
		steps = append(steps, "Vault is healthy - verify with: vault status")
	}

	return steps
}

// Helper function
func containsRecommendation(recommendations []string, keyword string) bool {
	for _, rec := range recommendations {
		if strings.Contains(strings.ToLower(rec), strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}
