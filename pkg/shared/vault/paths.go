// Package vault provides centralized Vault secret path management for EOS.
//
// This package implements the standardized secret path structure:
//   services/{environment}/{service}
//
// Example paths:
//   services/production/consul
//   services/staging/authentik
//   services/development/bionicgpt
//
// All Vault secret path construction MUST use the helpers in this package.
// Direct path string construction is forbidden (see CLAUDE.md P0 rule #13).
package vault

import (
	"fmt"
	"path"
	"strings"
)

// Constants for path construction
const (
	// DefaultMount is the standard KV v2 mount point for application secrets
	DefaultMount = "secret"

	// ServicesPrefix is the namespace for all service secrets
	// All service secrets are stored under: {mount}/services/{environment}/{service}
	ServicesPrefix = "services"
)

// Environment represents a deployment environment.
// Use these constants rather than string literals for type safety and validation.
type Environment string

const (
	EnvironmentProduction  Environment = "production"
	EnvironmentStaging     Environment = "staging"
	EnvironmentDevelopment Environment = "development"
	EnvironmentAdmin       Environment = "admin"
)

// String returns the string representation of the environment
func (e Environment) String() string {
	return string(e)
}

// Service represents a service name.
// Use these constants rather than string literals for type safety and validation.
type Service string

const (
	ServiceConsul    Service = "consul"
	ServiceAuthentik Service = "authentik"
	ServiceBionicGPT Service = "bionicgpt"
	ServiceWazuh     Service = "wazuh"
	ServiceHecate    Service = "hecate"
	ServiceHelen     Service = "helen"
)

// String returns the string representation of the service
func (s Service) String() string {
	return string(s)
}

// AllServices returns all known services.
// This list should be updated as new services are added to EOS.
func AllServices() []Service {
	return []Service{
		ServiceConsul,
		ServiceAuthentik,
		ServiceBionicGPT,
		ServiceWazuh,
		ServiceHecate,
		ServiceHelen,
	}
}

// AllEnvironments returns all known environments.
func AllEnvironments() []Environment {
	return []Environment{
		EnvironmentProduction,
		EnvironmentStaging,
		EnvironmentDevelopment,
		EnvironmentAdmin,
	}
}

// SecretPath constructs the base secret path for a service in an environment.
//
// Format: services/{environment}/{service}
//
// Example:
//   SecretPath(EnvironmentProduction, ServiceConsul)
//   → "services/production/consul"
//
// This is the canonical path format used throughout EOS.
// All service secrets are stored at this path as a single KV v2 entry
// containing multiple key-value pairs.
func SecretPath(env Environment, svc Service) string {
	return path.Join(ServicesPrefix, string(env), string(svc))
}

// SecretDataPath constructs the full Vault API data path for reading/writing secrets.
//
// Format: {mount}/data/services/{environment}/{service}
//
// Example:
//   SecretDataPath("", EnvironmentProduction, ServiceConsul)
//   → "secret/data/services/production/consul"
//
// This path is used with the Vault Logical API client.Logical().Read()
// for direct KV v2 data access.
//
// The KV v2 SDK client.KVv2(mount).Get() automatically adds the /data/ prefix,
// so use SecretPath() for SDK methods.
//
// Parameters:
//   mount - KV v2 mount point (use "" for default "secret")
//   env   - Target environment
//   svc   - Target service
func SecretDataPath(mount string, env Environment, svc Service) string {
	if mount == "" {
		mount = DefaultMount
	}
	return path.Join(mount, "data", SecretPath(env, svc))
}

// SecretMetadataPath constructs the full Vault API metadata path.
//
// Format: {mount}/metadata/services/{environment}/{service}
//
// Example:
//   SecretMetadataPath("", EnvironmentProduction, ServiceConsul)
//   → "secret/metadata/services/production/consul"
//
// This path is used to access KV v2 metadata (version history, timestamps, etc.)
// via client.Logical().Read() or LIST operations.
//
// Parameters:
//   mount - KV v2 mount point (use "" for default "secret")
//   env   - Target environment
//   svc   - Target service
func SecretMetadataPath(mount string, env Environment, svc Service) string {
	if mount == "" {
		mount = DefaultMount
	}
	return path.Join(mount, "metadata", SecretPath(env, svc))
}

// SecretListPath constructs the path for listing all services in an environment.
//
// Format: {mount}/metadata/services/{environment}
//
// Example:
//   SecretListPath("", EnvironmentProduction)
//   → "secret/metadata/services/production"
//
// Use this with Vault LIST operation to discover all services with secrets
// in a given environment.
//
// Parameters:
//   mount - KV v2 mount point (use "" for default "secret")
//   env   - Target environment
func SecretListPath(mount string, env Environment) string {
	if mount == "" {
		mount = DefaultMount
	}
	return path.Join(mount, "metadata", ServicesPrefix, string(env))
}

// CLIPath constructs the CLI-style path (without mount/data/metadata prefixes).
//
// Format: services/{environment}/{service}
//
// Example:
//   CLIPath(EnvironmentProduction, ServiceConsul)
//   → "services/production/consul"
//
// This is identical to SecretPath() and provided for clarity in CLI contexts.
func CLIPath(env Environment, svc Service) string {
	return SecretPath(env, svc)
}

// ParseSecretPath parses a secret path and extracts environment and service.
//
// Expected format: services/{environment}/{service}
//
// Example:
//   ParseSecretPath("services/production/consul")
//   → (EnvironmentProduction, ServiceConsul, nil)
//
// Returns error if:
//   - Path doesn't have exactly 3 components
//   - First component is not "services"
//   - Environment or service is invalid
//
// Use this to reverse-engineer paths received from Vault LIST operations
// or validate user-provided paths.
func ParseSecretPath(secretPath string) (Environment, Service, error) {
	// Expected: services/{environment}/{service}
	parts := strings.Split(strings.TrimPrefix(secretPath, "/"), "/")

	if len(parts) != 3 {
		return "", "", fmt.Errorf("invalid secret path format: expected 3 parts (services/env/service), got %d parts in '%s'",
			len(parts), secretPath)
	}

	if parts[0] != ServicesPrefix {
		return "", "", fmt.Errorf("invalid secret path: must start with '%s', got '%s' in path '%s'",
			ServicesPrefix, parts[0], secretPath)
	}

	env := Environment(parts[1])
	svc := Service(parts[2])

	// Validate environment and service
	if err := ValidateEnvironment(string(env)); err != nil {
		return "", "", fmt.Errorf("invalid environment in path '%s': %w", secretPath, err)
	}

	if err := ValidateService(string(svc)); err != nil {
		return "", "", fmt.Errorf("invalid service in path '%s': %w", secretPath, err)
	}

	return env, svc, nil
}

// ValidateEnvironment checks if an environment string is valid.
//
// Valid environments: production, staging, development, admin
//
// Returns error if environment is not recognized.
//
// Example:
//   ValidateEnvironment("production")  → nil
//   ValidateEnvironment("invalid")     → error
func ValidateEnvironment(env string) error {
	validEnvs := map[string]bool{
		string(EnvironmentProduction):  true,
		string(EnvironmentStaging):     true,
		string(EnvironmentDevelopment): true,
		string(EnvironmentAdmin):       true,
	}

	if !validEnvs[env] {
		return fmt.Errorf("invalid environment: '%s' (valid: production, staging, development, admin)", env)
	}

	return nil
}

// ValidateService checks if a service string is valid.
//
// Valid services: consul, authentik, bionicgpt, wazuh, hecate, helen
//
// Returns error if service is not recognized.
//
// Example:
//   ValidateService("consul")  → nil
//   ValidateService("invalid") → error
func ValidateService(svc string) error {
	validSvcs := map[string]bool{
		string(ServiceConsul):    true,
		string(ServiceAuthentik): true,
		string(ServiceBionicGPT): true,
		string(ServiceWazuh):     true,
		string(ServiceHecate):    true,
		string(ServiceHelen):     true,
	}

	if !validSvcs[svc] {
		return fmt.Errorf("invalid service: '%s' (valid: consul, authentik, bionicgpt, wazuh, hecate, helen)", svc)
	}

	return nil
}

// LegacyConsulPath returns the legacy Consul secret path for backward compatibility.
//
// DEPRECATED: This is only for migration support. New code should use SecretPath().
//
// Legacy path: consul/bootstrap-token
// New path:    services/{env}/consul (with key: bootstrap-token)
//
// This will be removed after migration is complete (approximately 6 months).
func LegacyConsulPath(secretKey string) string {
	return path.Join("consul", secretKey)
}

// LegacyBionicGPTPath returns the legacy BionicGPT secret path for backward compatibility.
//
// DEPRECATED: This is only for migration support. New code should use SecretPath().
//
// Legacy path: secret/bionicgpt/{key}
// New path:    services/{env}/bionicgpt (with multiple keys)
//
// This will be removed after migration is complete (approximately 6 months).
func LegacyBionicGPTPath(secretKey string) string {
	return path.Join("secret", "bionicgpt", secretKey)
}

// LegacyHecatePath returns the legacy Hecate secret path for backward compatibility.
//
// DEPRECATED: This is only for migration support. New code should use SecretPath().
//
// Legacy path: secret/hecate/{subsystem}/{key}
// New path:    services/{env}/hecate (with multiple keys)
//
// This will be removed after migration is complete (approximately 6 months).
func LegacyHecatePath(subsystem, secretKey string) string {
	return path.Join("secret", "hecate", subsystem, secretKey)
}

// ============================================================================
// Vault Bootstrap and Internal Paths (SINGLE SOURCE OF TRUTH)
// ============================================================================
// These paths are used internally by Eos during Vault setup and operation.
// DO NOT use these for application secrets - use SecretPath() instead.

const (
	// === Bootstrap Secrets (Ephemeral - Deleted After Use) ===
	// These secrets are only used during initial Vault setup and are deleted
	// after successful initialization to minimize the window of exposure.

	// UserpassBootstrapPasswordKVPath is the temporary storage location for the
	// userpass admin password during Vault initialization.
	//
	// Purpose:     Temporary storage for userpass password during Vault initialization
	// Lifecycle:   Created in Phase 10a, read in Phase 13 (MFA setup), deleted after successful TOTP verification
	// Security:    Contains plaintext password, MUST be deleted ASAP after use
	// Access:      Only root token and vault admin policy can read
	// Path format: secret/data/eos/bootstrap (KV v2 data path)
	// CLI path:    secret/eos/bootstrap (vault CLI path without /data/ prefix)
	//
	// Example usage:
	//   Write: client.Logical().Write("secret/data/eos/bootstrap", data)
	//   Read:  client.Logical().Read("secret/data/eos/bootstrap")
	//   Delete: client.Logical().Delete("secret/data/eos/bootstrap")
	UserpassBootstrapPasswordKVPath = "secret/data/eos/bootstrap"

	// UserpassBootstrapPasswordKVField is the field name within the bootstrap secret
	// that contains the actual password value.
	UserpassBootstrapPasswordKVField = "password"

	// UserpassBootstrapPasswordCLIPath is the CLI-friendly path (without /data/ prefix)
	// for use with vault kv commands.
	UserpassBootstrapPasswordCLIPath = "secret/eos/bootstrap"

	// === MFA Method Storage ===
	// Storage location for MFA method metadata (method IDs, configuration, etc.)

	// MFAMethodStoragePrefix is the base path for storing MFA method metadata.
	// Individual methods are stored at: secret/data/eos/mfa-methods/{method-type}
	MFAMethodStoragePrefix = "secret/data/eos/mfa-methods/"

	// TOTPMethodStorageKVPath is the storage location for TOTP MFA method metadata.
	// Contains: method_id, method_type, created_at, created_by
	TOTPMethodStorageKVPath = "secret/data/eos/mfa-methods/totp"

	// TOTPMethodStorageCLIPath is the CLI-friendly path for TOTP method metadata.
	TOTPMethodStorageCLIPath = "secret/eos/mfa-methods/totp"

	// === Legacy Bootstrap Paths (DEPRECATED) ===
	// Old path used before standardization. Kept for migration support only.

	// UserpassPasswordKVPathLegacy is the old bootstrap password path.
	// DEPRECATED: Use UserpassBootstrapPasswordKVPath instead.
	// This will be removed after migration is complete (approximately 6 months).
	UserpassPasswordKVPathLegacy = "secret/data/eos/userpass-password"
)
