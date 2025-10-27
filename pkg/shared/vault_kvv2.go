// pkg/shared/vault_kvv2.go
package shared

import "path"

// ----------------------
// Test data constants
// ----------------------

const (
	TestDataVaultPath = "eos/test-data"
	TestDataFilename  = "test-data.json"
	TestKVPath        = "hello"
	TestKVKey         = "value"
	TestKVValue       = "world"

	// ----------------------
	// Vault KV namespaces
	// ----------------------

	VaultMountKV         = "secret"
	VaultSecretMountPath = VaultMountKV + "/metadata/"
	VaultTestPath        = "bootstrap/test" // Used to verify KV functionality

	// ----------------------
	// Eos-specific Vault paths
	// ----------------------

	KVNamespaceUsers = "users/"
	EosVaultUserPath = VaultMountKV + "/" + KVNamespaceUsers + EosID

	// ----------------------
	// Entity specific Vault paths
	// ----------------------

	EosEntityLookupPath = "identity/entity/name/%s"
	EosEntityPath       = "identity/entity"
	EosEntityAliasPath  = "identity/entity-alias"

	// ----------------------
	// Auth specific Vault paths
	// ----------------------

	// #nosec G101 - This is a Vault path prefix, not a hardcoded credential
	UserpassPathPrefix = "auth/userpass/users/"
	EosUserpassPath    = UserpassPathPrefix + EosID
	VaultSecretMount   = "secret"
	UserpassKVPath     = VaultSecretMount + "/eos/userpass-password"
	// #nosec G101 - This is a configuration key name, not a hardcoded credential
	FallbackPasswordKey = "eos-userpass-password"

	AuditID   = "file/"
	MountPath = "sys/audit/" + AuditID

	VaultHealthPath = "/v1/sys/health"

	// AppRole constants and paths

	AppRoleName      = "eos-approle"
	AppRolePath      = "auth/approle/role/" + AppRoleName
	AppRoleLoginPath = "auth/approle/login"

	// Admin AppRole constants and paths
	// Admin AppRole has elevated privileges (eos-admin-policy) for operational commands.
	// This follows HashiCorp best practice of using AppRole instead of root token.
	AdminAppRoleName      = "eos-admin-approle"
	AdminAppRolePath      = "auth/approle/role/" + AdminAppRoleName
	AdminAppRoleRoleIDPath   = AdminAppRolePath + "/role-id"
	AdminAppRoleSecretIDPath = AdminAppRolePath + "/secret-id"

	// Auth backends
	AuthBackendUserpass = "userpass/"
	AuthBackendApprole  = "approle/"

	AppRoleRoleIDPath   = AppRolePath + "/role-id"
	AppRoleSecretIDPath = AppRolePath + "/secret-id"
)

var AuthBackendLabels = map[string]string{
	AuthBackendUserpass: "userpass",
	AuthBackendApprole:  "approle",
}

// ----------------------
// Helper to build Vault paths
// ----------------------

// BuildVaultPath safely joins Vault paths.
func BuildVaultPath(parts ...string) string {
	return path.Join(parts...)
}
