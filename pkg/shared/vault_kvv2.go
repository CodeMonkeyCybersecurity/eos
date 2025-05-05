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
	// EOS-specific Vault paths
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

	UserpassPathPrefix  = "auth/userpass/users/"
	EosUserpassPath     = UserpassPathPrefix + EosID
	VaultSecretMount    = "secret"
	UserpassKVPath      = VaultSecretMount + "/eos/userpass-password"
	FallbackPasswordKey = "eos-userpass-password"

	AuditID   = "file/"
	MountPath = "sys/audit/" + AuditID

	VaultHealthPath = "/v1/sys/health"

	// AppRole constants and paths

	AppRoleName      = "eos-approle"
	AppRolePath      = "auth/approle/role/" + AppRoleName
	AppRoleLoginPath = "auth/approle/login"

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
