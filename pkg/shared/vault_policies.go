// pkg/shared/vault_policies

package shared

import (
	"bytes"
	"fmt"
	"text/template"
)

const EosDefaultPolicyName = "eos-default-policy"

const EosDefaultPolicyTemplate = `
# Vault token and identity permissions
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self" { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
path "sys/capabilities-self" { capabilities = ["update"] }
path "identity/entity/id/{{"{{"}}identity.entity.id{{"}}"}}" { capabilities = ["read"] }
path "identity/entity/name/{{"{{"}}identity.entity.name{{"}}"}}" { capabilities = ["read"] }
path "sys/internal/ui/resultant-acl" { capabilities = ["read"] }
path "sys/renew" { capabilities = ["update"] }
path "sys/leases/renew" { capabilities = ["update"] }
path "sys/leases/lookup" { capabilities = ["update"] }

# Cubbyhole and tools
path "cubbyhole/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "sys/wrapping/wrap" { capabilities = ["update"] }
path "sys/wrapping/lookup" { capabilities = ["update"] }
path "sys/wrapping/unwrap" { capabilities = ["update"] }
path "sys/tools/hash" { capabilities = ["update"] }
path "sys/tools/hash/*" { capabilities = ["update"] }
path "sys/control-group/request" { capabilities = ["update"] }

# OIDC authorize
path "identity/oidc/provider/+/authorize" { capabilities = ["read", "update"] }

# Secrets – dynamic KV mount path
path "{{ .KVPath }}/users/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "{{ .KVPath }}/data/*" { capabilities = ["create", "update", "read", "delete", "list"] }
path "{{ .KVPath }}/metadata/*" { capabilities = ["read", "list"] }

# Auth methods
path "auth/userpass/users/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "auth/approle/role/*" { capabilities = ["create", "read", "update", "delete", "list"] }
`

func RenderEosPolicy(kvPath string) (string, error) {
	tmpl, err := template.New(EosDefaultPolicyName).
		Option("missingkey=error").
		Parse(EosDefaultPolicyTemplate)
	if err != nil {
		return "", fmt.Errorf("parse policy template: %w", err)
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, map[string]string{
		"KVPath": kvPath,
	})
	if err != nil {
		return "", fmt.Errorf("execute policy template: %w", err)
	}

	return buf.String(), nil
}
