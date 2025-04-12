/* pkg/vault/config.go */

package vault

var Policies = map[string]string{
	EosVaultPolicy: `
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
`,
}
