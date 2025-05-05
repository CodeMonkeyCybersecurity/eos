// pkg/shared/vault_policies.go
package shared

const (
	// Policy name
	EosVaultPolicy = "eos-policy"
)

var Policies = map[string]string{
	EosVaultPolicy: `
  # EOS full root access
  path "**" {
    capabilities = ["create", "read", "update", "delete", "list", "sudo"]
  }

  # Explicit audit backend control (redundant but kept for clarity)
  path "sys/audit/*" {
    capabilities = ["create", "read", "update", "delete", "list", "sudo"]
  }
  `,
}
