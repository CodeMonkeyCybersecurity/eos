/* pkg/vault/config.go */

package vault

var Policies = map[string]string{
	EosVaultPolicy: `
# Read and write actual data (KV v2)
path "secret/data/*" {
	capabilities = ["create", "read", "update", "delete", "list"]
}

# Access metadata (KV v2)
path "secret/metadata/*" {
	capabilities = ["read", "list"]
}

# Optional: Allow checking mounts
path "sys/mounts" {
	capabilities = ["read", "list"]
}
`,
}
