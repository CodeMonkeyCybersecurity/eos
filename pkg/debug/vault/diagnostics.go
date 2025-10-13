// pkg/debug/vault/diagnostics.go
// Vault-specific diagnostic checks

package vault

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/debug"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

const (
	DefaultBinaryPath = "/usr/local/bin/vault"
	DefaultConfigPath = "/etc/vault.d/vault.hcl"
	DefaultDataPath   = "/opt/vault/data"
	DefaultLogPath    = "/var/log/vault"
)

// AllDiagnostics returns all vault diagnostic checks
func AllDiagnostics() []*debug.Diagnostic {
	return []*debug.Diagnostic{
		BinaryDiagnostic(),
		ConfigFileDiagnostic(),
		ConfigValidationDiagnostic(),
		DataDirectoryDiagnostic(),
		LogDirectoryDiagnostic(),
		UserDiagnostic(),
		ServiceDiagnostic(),
		ServiceLogsDiagnostic(),
		ProcessDiagnostic(),
		PortDiagnostic(),
		HealthCheckDiagnostic(),
		EnvironmentDiagnostic(),
		CapabilitiesDiagnostic(),
	}
}

// BinaryDiagnostic checks the vault binary
func BinaryDiagnostic() *debug.Diagnostic {
	return debug.BinaryCheck("Vault", DefaultBinaryPath)
}

// ConfigFileDiagnostic checks the vault configuration file
func ConfigFileDiagnostic() *debug.Diagnostic {
	return debug.FileCheck("Configuration File", DefaultConfigPath, true)
}

// ConfigValidationDiagnostic validates the configuration file
func ConfigValidationDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Configuration Validation",
		Category:    "Configuration",
		Description: "Validate vault.hcl configuration",
		Condition: func(ctx context.Context) bool {
			// Only run if binary and config exist
			_, binErr := os.Stat(DefaultBinaryPath)
			_, cfgErr := os.Stat(DefaultConfigPath)
			return binErr == nil && cfgErr == nil
		},
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			cmd := exec.CommandContext(ctx, DefaultBinaryPath, "validate", DefaultConfigPath)
			output, err := cmd.CombinedOutput()

			result.Output = string(output)
			result.Metadata["config_path"] = DefaultConfigPath

			if err != nil {
				result.Status = debug.StatusError
				result.Message = "Configuration validation failed"
				result.Remediation = fmt.Sprintf("Fix configuration errors in %s", DefaultConfigPath)
			} else {
				result.Status = debug.StatusOK
				result.Message = "Configuration is valid"
			}

			return result, nil
		},
	}
}

// DataDirectoryDiagnostic checks the vault data directory
func DataDirectoryDiagnostic() *debug.Diagnostic {
	return debug.DirectoryCheck("Data Directory", DefaultDataPath, "vault")
}

// LogDirectoryDiagnostic checks the vault log directory
func LogDirectoryDiagnostic() *debug.Diagnostic {
	return debug.DirectoryCheck("Log Directory", DefaultLogPath, "vault")
}

// UserDiagnostic checks the vault user exists
func UserDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Vault User",
		Category:    "System",
		Description: "Check vault user and group exist",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			// Check user exists
			cmd := exec.CommandContext(ctx, "id", "vault")
			output, err := cmd.CombinedOutput()
			result.Output = string(output)

			if err != nil {
				result.Status = debug.StatusError
				result.Message = "Vault user does not exist"
				result.Remediation = "Create vault user: useradd -r -s /bin/false vault"
			} else {
				result.Status = debug.StatusOK
				result.Message = "Vault user exists"

				// Extract uid/gid
				outputStr := string(output)
				result.Metadata["id_output"] = outputStr
			}

			return result, nil
		},
	}
}

// ServiceDiagnostic checks the systemd service status
func ServiceDiagnostic() *debug.Diagnostic {
	return debug.SystemdServiceCheck("vault")
}

// ServiceLogsDiagnostic retrieves recent service logs
func ServiceLogsDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Service Logs",
		Category:    "Systemd",
		Description: "Recent vault service logs",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			cmd := exec.CommandContext(ctx, "journalctl", "-u", "vault.service", "-n", "100", "--no-pager")
			output, err := cmd.CombinedOutput()

			result.Output = string(output)

			if err != nil {
				result.Status = debug.StatusWarning
				result.Message = "Could not retrieve logs"
			} else {
				// Check for errors in logs
				if strings.Contains(string(output), "error") || strings.Contains(string(output), "Error") {
					result.Status = debug.StatusWarning
					result.Message = "Logs contain errors (see output)"
				} else {
					result.Status = debug.StatusInfo
					result.Message = "Logs retrieved successfully"
				}
			}

			return result, nil
		},
	}
}

// ProcessDiagnostic checks for running vault processes
func ProcessDiagnostic() *debug.Diagnostic {
	return debug.CommandCheck("Running Processes", "System", "pgrep", "-a", "vault")
}

// PortDiagnostic checks if vault is listening on configured ports
func PortDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        fmt.Sprintf("Vault Ports (%d API, %d Cluster)", shared.PortVault, shared.PortVault+1),
		Category:    "Network",
		Description: fmt.Sprintf("Check if Vault is listening on ports %d (API) and %d (Cluster)", shared.PortVault, shared.PortVault+1),
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			// Check main API port (8179)
			apiCmd := exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("ss -tlnp | grep ':%d' || netstat -tlnp 2>/dev/null | grep ':%d'", shared.PortVault, shared.PortVault))
			apiOutput, apiErr := apiCmd.CombinedOutput()

			// Check cluster port (8180)
			clusterCmd := exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("ss -tlnp | grep ':%d' || netstat -tlnp 2>/dev/null | grep ':%d'", shared.PortVault+1, shared.PortVault+1))
			clusterOutput, _ := clusterCmd.CombinedOutput()

			var outputBuilder strings.Builder
			apiListening := len(apiOutput) > 0
			clusterListening := len(clusterOutput) > 0

			result.Metadata["api_port"] = shared.PortVault
			result.Metadata["cluster_port"] = shared.PortVault + 1
			result.Metadata["api_listening"] = apiListening
			result.Metadata["cluster_listening"] = clusterListening

			if apiListening {
				outputBuilder.WriteString(fmt.Sprintf("API Port %d: LISTENING\n", shared.PortVault))
				outputBuilder.WriteString(string(apiOutput))
				outputBuilder.WriteString("\n")
			} else {
				outputBuilder.WriteString(fmt.Sprintf("API Port %d: NOT IN USE\n", shared.PortVault))
			}

			if clusterListening {
				outputBuilder.WriteString(fmt.Sprintf("Cluster Port %d: LISTENING\n", shared.PortVault+1))
				outputBuilder.WriteString(string(clusterOutput))
			} else {
				outputBuilder.WriteString(fmt.Sprintf("Cluster Port %d: NOT IN USE\n", shared.PortVault+1))
			}

			result.Output = outputBuilder.String()

			if apiListening && clusterListening {
				result.Status = debug.StatusOK
				result.Message = "Both API and cluster ports are listening"
			} else if apiListening {
				result.Status = debug.StatusWarning
				result.Message = "API port listening but cluster port not available (single-node mode)"
			} else {
				result.Status = debug.StatusWarning
				result.Message = fmt.Sprintf("Port %d not in use", shared.PortVault)
				if apiErr != nil {
					result.Remediation = "Ensure vault service is running and configured correctly"
				}
			}

			return result, nil
		},
	}
}

// HealthCheckDiagnostic performs HTTP health check
func HealthCheckDiagnostic() *debug.Diagnostic {
	return debug.NetworkCheck("HTTP Health Check", "http://127.0.0.1:8200/v1/sys/health", 5*time.Second)
}

// EnvironmentDiagnostic checks vault environment variables
func EnvironmentDiagnostic() *debug.Diagnostic {
	return &debug.Diagnostic{
		Name:        "Environment Variables",
		Category:    "Configuration",
		Description: "Check Vault environment variables",
		Collect: func(ctx context.Context) (*debug.Result, error) {
			result := &debug.Result{
				Metadata: make(map[string]interface{}),
			}

			envVars := map[string]string{
				"VAULT_ADDR":        os.Getenv("VAULT_ADDR"),
				"VAULT_TOKEN":       maskToken(os.Getenv("VAULT_TOKEN")),
				"VAULT_CACERT":      os.Getenv("VAULT_CACERT"),
				"VAULT_SKIP_VERIFY": os.Getenv("VAULT_SKIP_VERIFY"),
				"VAULT_NAMESPACE":   os.Getenv("VAULT_NAMESPACE"),
			}

			var output strings.Builder
			hasVars := false
			for k, v := range envVars {
				if v != "" {
					output.WriteString(fmt.Sprintf("%s=%s\n", k, v))
					result.Metadata[k] = v
					hasVars = true
				}
			}

			result.Output = output.String()

			if hasVars {
				result.Status = debug.StatusInfo
				result.Message = "Environment variables configured"
			} else {
				result.Status = debug.StatusInfo
				result.Message = "No Vault environment variables set"
			}

			return result, nil
		},
	}
}

// CapabilitiesDiagnostic checks binary capabilities
func CapabilitiesDiagnostic() *debug.Diagnostic {
	return debug.CommandCheck("Binary Capabilities", "System", "getcap", DefaultBinaryPath)
}

// Helper function to mask tokens
func maskToken(token string) string {
	if token == "" {
		return ""
	}
	if len(token) <= 8 {
		return "***"
	}
	return token[:4] + "..." + token[len(token)-4:]
}
