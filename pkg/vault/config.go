/* pkg/vault/config.go */

package vault

var Policies = map[string]string{
	EosVaultPolicy: `
# Read and write actual data (KV v2)
path "secret/*" {
	capabilities = ["create", "read", "update", "delete", "list"]
}


# Optional: Allow checking mounts
path "sys/*" {
	capabilities = ["create", "read", "update", "delete", "list"]
}

# 🔐 Allow eos user to manage userpass accounts
path "auth/*" {
	capabilities = ["create", "read", "update", "delete", "list"]
}
`,
}
