// pkg/debug/vault/tls.go
// TLS-specific diagnostics for Vault

package vault

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/debug"
)

// TLSStatus holds TLS configuration status
type TLSStatus struct {
	Enabled       bool
	CertPath      string
	KeyPath       string
	CertExists    bool
	KeyExists     bool
	Issue         string
	Reason        string
	CertLocations []CertLocation
}

// CertLocation represents a potential certificate location
type CertLocation struct {
	Path   string
	Exists bool
	Files  []string
}

// TLSDiagnostic checks complete TLS configuration
func TLSDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "TLS Configuration",
		Category:    "Security",
		Description: "Complete TLS setup analysis",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			// Read config file
			configData, err := os.ReadFile(DefaultConfigPath)
			if err != nil {
				result.Status = debug.StatusWarning
				result.Message = "Cannot read config file"
				return result, nil
			}

			config := string(configData)
			status := analyzeTLSConfig(config)

			// Build output
			var output strings.Builder
			output.WriteString(fmt.Sprintf("TLS Status: %s\n", tlsStatusString(status.Enabled)))

			if status.Enabled {
				output.WriteString(fmt.Sprintf("  Certificate: %s\n", certStatus(status.CertPath, status.CertExists)))
				output.WriteString(fmt.Sprintf("  Private Key: %s\n", certStatus(status.KeyPath, status.KeyExists)))

				// Add certificate details if cert exists
				if status.CertExists && status.CertPath != "" {
					output.WriteString("\nCertificate Details:\n")
					certDetails := getCertificateDetails(ctx, status.CertPath)
					if certDetails != "" {
						output.WriteString(certDetails)
					} else {
						output.WriteString("  (Unable to parse certificate details)\n")
					}
				}

				result.Metadata["tls_enabled"] = true
				result.Metadata["cert_path"] = status.CertPath
				result.Metadata["key_path"] = status.KeyPath
				result.Metadata["cert_exists"] = status.CertExists
				result.Metadata["key_exists"] = status.KeyExists

				if status.Issue != "" {
					output.WriteString(fmt.Sprintf("\n⚠ ISSUE: %s\n", status.Issue))
					result.Status = debug.StatusError
					result.Message = status.Issue
					result.Remediation = "Generate certificates: eos repair vault --fix-tls"
				} else {
					result.Status = debug.StatusOK
					result.Message = "TLS properly configured"
				}
			} else {
				result.Metadata["tls_enabled"] = false
				if status.Reason != "" {
					output.WriteString(fmt.Sprintf("  Reason: %s\n", status.Reason))
					result.Metadata["reason"] = status.Reason
				}

				output.WriteString("\n⚠ WARNING: Vault traffic is UNENCRYPTED\n")
				output.WriteString("  All communication with Vault is in plaintext\n")
				output.WriteString("  This is a SECURITY RISK for production environments\n")

				result.Status = debug.StatusWarning
				result.Message = "TLS disabled - traffic is unencrypted"
				result.Remediation = "Enable TLS for production: eos repair vault --fix-tls"
			}

			// Check potential certificate locations
			output.WriteString("\nPotential Certificate Locations:\n")
			for _, loc := range status.CertLocations {
				icon := "✗"
				detail := "not found"
				if loc.Exists {
					if len(loc.Files) > 0 {
						icon = "✓"
						detail = fmt.Sprintf("%d files", len(loc.Files))
					} else {
						icon = "⚠"
						detail = "exists but empty"
					}
				}
				output.WriteString(fmt.Sprintf("  %s %s (%s)\n", icon, loc.Path, detail))

				if loc.Exists && len(loc.Files) > 0 {
					for _, file := range loc.Files {
						output.WriteString(fmt.Sprintf("      - %s\n", file))
					}
				}
			}

			result.Output = output.String()
			return result, nil
		},
	}
}

// analyzeTLSConfig analyzes TLS configuration from config content
func analyzeTLSConfig(config string) TLSStatus {
	status := TLSStatus{}

	// Check if TLS is disabled
	if strings.Contains(config, "tls_disable = true") || strings.Contains(config, "tls_disable=true") {
		status.Enabled = false
		status.Reason = "Explicitly disabled in configuration (tls_disable = true)"
	} else if strings.Contains(config, "tls_disable = false") || strings.Contains(config, "tls_disable=false") {
		status.Enabled = true

		// Extract cert paths
		status.CertPath = extractConfigValue(config, "tls_cert_file")
		status.KeyPath = extractConfigValue(config, "tls_key_file")

		// Check if certs exist
		if status.CertPath != "" {
			status.CertExists = fileExists(status.CertPath)
		}
		if status.KeyPath != "" {
			status.KeyExists = fileExists(status.KeyPath)
		}

		// Determine issues
		if status.CertPath == "" && status.KeyPath == "" {
			status.Issue = "TLS enabled but no certificate paths configured"
		} else if status.CertPath == "" {
			status.Issue = "TLS certificate path not configured"
		} else if status.KeyPath == "" {
			status.Issue = "TLS private key path not configured"
		} else if !status.CertExists {
			status.Issue = fmt.Sprintf("TLS certificate file not found: %s", status.CertPath)
		} else if !status.KeyExists {
			status.Issue = fmt.Sprintf("TLS private key file not found: %s", status.KeyPath)
		}
	} else {
		// TLS setting not found - default behavior
		status.Enabled = true
		status.Issue = "TLS configuration not specified (using Vault defaults)"
	}

	// Check common certificate locations
	potentialPaths := []string{
		"/etc/vault.d/tls",
		"/opt/vault/tls",
		"/etc/pki/vault",
		"/etc/ssl/vault",
	}

	for _, path := range potentialPaths {
		loc := CertLocation{Path: path}
		info, err := os.Stat(path)
		if err == nil && info.IsDir() {
			loc.Exists = true
			entries, _ := os.ReadDir(path)
			for _, entry := range entries {
				if !entry.IsDir() {
					loc.Files = append(loc.Files, entry.Name())
				}
			}
		}
		status.CertLocations = append(status.CertLocations, loc)
	}

	return status
}

// extractConfigValue extracts a value from vault config
func extractConfigValue(config, key string) string {
	// Look for key = "value" or key = value
	patterns := []string{
		key + ` = "`,
		key + `="`,
		key + ` = `,
		key + `=`,
	}

	for _, pattern := range patterns {
		idx := strings.Index(config, pattern)
		if idx == -1 {
			continue
		}

		// Move past the pattern
		start := idx + len(pattern)
		if start >= len(config) {
			continue
		}

		// Find the end (quote or newline)
		hasQuote := config[start-1] == '"'

		if hasQuote {
			// Look for closing quote
			end := strings.Index(config[start:], `"`)
			if end != -1 {
				return config[start : start+end]
			}
		} else {
			// Look for newline or space
			end := strings.IndexAny(config[start:], "\n ")
			if end != -1 {
				return strings.TrimSpace(config[start : start+end])
			}
		}
	}

	return ""
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// getCertificateDetails uses openssl to extract certificate information
func getCertificateDetails(ctx context.Context, certPath string) string {
	// Use openssl x509 to parse certificate details
	cmd := exec.CommandContext(ctx, "openssl", "x509", "-in", certPath, "-noout", "-text")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}

	// Parse and format the most relevant fields
	lines := strings.Split(string(output), "\n")
	var result strings.Builder
	lineCount := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Limit output to first 20 lines of relevant info
		if lineCount >= 20 {
			break
		}

		// Capture key sections
		if strings.HasPrefix(trimmed, "Issuer:") {
			result.WriteString("  " + trimmed + "\n")
			lineCount++
			continue
		}
		if strings.HasPrefix(trimmed, "Subject:") {
			result.WriteString("  " + trimmed + "\n")
			lineCount++
			continue
		}
		if strings.HasPrefix(trimmed, "Validity") {
			result.WriteString("  " + trimmed + "\n")
			lineCount++
			continue
		}
		if strings.HasPrefix(trimmed, "Not Before:") || strings.HasPrefix(trimmed, "Not After:") {
			result.WriteString("    " + trimmed + "\n")
			lineCount++
			continue
		}
		if strings.HasPrefix(trimmed, "Subject Alternative Name:") {
			result.WriteString("  " + trimmed + "\n")
			lineCount++
			continue
		}
	}

	return result.String()
}

// Helper formatters
func tlsStatusString(enabled bool) string {
	if enabled {
		return "ENABLED"
	}
	return "DISABLED"
}

func certStatus(path string, exists bool) string {
	if path == "" {
		return "(not configured)"
	}
	if exists {
		return fmt.Sprintf("%s ✓", path)
	}
	return fmt.Sprintf("%s ✗ (not found)", path)
}
