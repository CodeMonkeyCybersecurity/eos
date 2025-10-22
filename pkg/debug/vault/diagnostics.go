// pkg/debug/vault/diagnostics.go
// Vault-specific diagnostic checks

package vault

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/debug"
)

// NOTE: These constants duplicate values from pkg/vault/constants.go
// This is intentional to avoid circular import (pkg/debug/vault cannot import pkg/vault)
// If you change these values, also update pkg/vault/constants.go
//
// For runtime paths that don't cause circular imports, use pkg/shared constants:
// - shared.AgentToken (vault.VaultAgentTokenPath)
// - shared.AppRolePaths.RoleID (vault.VaultRoleIDFilePath)
// - shared.AppRolePaths.SecretID (vault.VaultSecretIDFilePath)
// - shared.EosRunDir (vault.EosRunDir)
// - shared.VaultAgentConfigPath (vault.VaultAgentConfigPath)
const (
	DefaultBinaryPath      = "/usr/local/bin/vault"          // Matches vault.VaultBinaryPath
	DefaultConfigPath      = "/etc/vault.d/vault.hcl"        // Matches vault.VaultConfigPath
	DefaultAgentConfigPath = "/etc/vault.d/agent-config.hcl" // Matches vault.VaultAgentConfigPath & shared.VaultAgentConfigPath
	DefaultDataPath        = "/opt/vault/data"               // Matches vault.VaultDataDir
	DefaultLogPath         = "/var/log/vault"                // Matches vault.VaultLogsDir
	DeletionTransactionDir = "/var/log/eos"
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
		PermissionsDiagnostic(), // NEW: Comprehensive permissions check
		// Vault service diagnostics (systemd)
		SystemdServiceDiagnostic(), // Extracted to diag_service.go
		ServiceConfigDiagnostic(),  // Extracted to diag_service.go
		ServiceLogsDiagnostic(),    // Extracted to diag_service.go
		ProcessDiagnostic(),
		PortDiagnostic(),
		HealthCheckDiagnostic(),
		EnvironmentDiagnostic(),
		CapabilitiesDiagnostic(),
		DeletionTransactionLogsDiagnostic(),
		IdempotencyStatusDiagnostic(), // NEW: Shows current installation state for idempotent operations
		OrphanedStateDiagnostic(),     // NEW: Detects orphaned Vault state (initialized but credentials lost)
		// Vault Agent diagnostics
		VaultAgentServiceDiagnostic(),
		VaultAgentConfigDiagnostic(),
		VaultAgentCredentialsDiagnostic(),
		VaultAgentTokenDiagnostic(),
		VaultAgentTokenPermissionsDiagnostic(), // Comprehensive token permissions analysis
		VaultAgentLogsDiagnostic(),
	}
}

// AgentDiagnostics returns only Vault Agent-related diagnostic checks
// Use this for focused troubleshooting of Vault Agent authentication and service issues
func AgentDiagnostics() []*debug.Diagnostic {
	return []*debug.Diagnostic{
		VaultAgentServiceDiagnostic(),
		VaultAgentConfigDiagnostic(),
		VaultAgentCredentialsDiagnostic(),
		VaultAgentTokenDiagnostic(),
		VaultAgentTokenPermissionsDiagnostic(),
		VaultAgentLogsDiagnostic(),
	}
}

// AuthDiagnostics returns authentication and authorization focused diagnostic checks
// This mode provides deep analysis of:
// - Vault server connectivity and health
// - AppRole authentication method configuration
// - Agent credentials (role_id, secret_id)
// - Token acquisition and validity
// - Token permissions and policies
// - Policy content and configuration
// - Authentication flow end-to-end
//
// Use this for troubleshooting:
// - "permission denied" errors
// - Token authentication failures
// - Policy misconfigurations
// - AppRole setup issues
// - Services unable to read/write secrets
func AuthDiagnostics() []*debug.Diagnostic {
	return []*debug.Diagnostic{
		// 1. Verify Vault is healthy and accessible (prerequisite for auth)
		HealthCheckDiagnostic(),

		// 2. Check AppRole credentials exist and are valid
		VaultAgentCredentialsDiagnostic(),

		// 3. Check if Agent has successfully authenticated (token file)
		VaultAgentTokenDiagnostic(),

		// 4. Deep dive into token permissions, policies, and capabilities
		VaultAgentTokenPermissionsDiagnostic(),

		// 5. Check Agent service is running (auth flow depends on it)
		VaultAgentServiceDiagnostic(),

		// 6. Review logs for authentication errors
		VaultAgentLogsDiagnostic(),
	}
}

// NOTE: Installation diagnostics (Binary, Config, Data/Log Directories, User)
// are now in diag_installation.go

// NOTE: Permissions diagnostic (comprehensive ownership & access tests)
// is now in diag_permissions.go

// Network diagnostics moved to diag_network.go:
// - ProcessDiagnostic() - Vault process detection via pgrep
// - PortDiagnostic() - Port binding checks (API 8179, Cluster 8180)
// - HealthCheckDiagnostic() - HTTP health endpoint check

// Environment diagnostics moved to diag_environment.go:
// - EnvironmentDiagnostic() - Environment variables check (VAULT_ADDR, VAULT_TOKEN, etc.)
// - CapabilitiesDiagnostic() - Linux capabilities check (mlock, ipc_lock)
// - maskToken() - Helper function to mask sensitive tokens

// State diagnostics moved to diag_state.go:
// - DeletionTransactionLogsDiagnostic() - Vault deletion transaction logs
// - IdempotencyStatusDiagnostic() - Installation state for idempotent operations
// - OrphanedStateDiagnostic() - Detect orphaned Vault state (initialized but credentials lost)

//--------------------------------------------------------------------
// Vault Agent Diagnostics - moved to diag_agent.go
//--------------------------------------------------------------------
// - VaultAgentServiceDiagnostic() - Service status check
// - VaultAgentConfigDiagnostic() - Configuration file validation
// - VaultAgentCredentialsDiagnostic() - AppRole credentials check
// - VaultAgentTokenDiagnostic() - Token file validation
// - VaultAgentLogsDiagnostic() - Recent service logs
// - VaultAgentTokenPermissionsDiagnostic() - Comprehensive token permissions analysis
// - min() - Helper function for minimum of two integers
