/* pkg/vault/config.go */

package vault

var Policies = map[string]string{
	"eos-policy": `
path "*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}`,
}
