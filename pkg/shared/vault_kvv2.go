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
)

// ----------------------
// Vault KV namespaces
// ----------------------

const (
	VaultMountKV         = "secret"
	VaultSecretMountPath = VaultMountKV + "/metadata/"
	VaultTestPath        = "bootstrap/test" // Used to verify KV functionality
)

// ----------------------
// EOS-specific Vault paths
// ----------------------

const (
	KVNamespaceUsers = "users/"
	EosVaultUserPath = VaultMountKV + "/" + KVNamespaceUsers + "eos"
)

// ----------------------
// Helper to build Vault paths
// ----------------------

// BuildVaultPath safely joins Vault paths.
func BuildVaultPath(parts ...string) string {
	return path.Join(parts...)
}
