// pkg/shared/vault_policies

package shared

import (
	"bytes"
	"fmt"
	"text/template"
)

const (
	EosDefaultPolicyName   = "eos-default-policy"
	EosAdminPolicyName     = "eos-admin-policy"
	EosEmergencyPolicyName = "eos-emergency-policy"
	EosReadOnlyPolicyName  = "eos-readonly-policy"
)

const EosDefaultPolicyTemplate = `
# Vault token and identity permissions (read-only where possible)
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

# Personal cubbyhole only
path "cubbyhole/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "sys/wrapping/wrap" { capabilities = ["update"] }
path "sys/wrapping/lookup" { capabilities = ["update"] }
path "sys/wrapping/unwrap" { capabilities = ["update"] }

# Essential tools only
path "sys/tools/hash" { capabilities = ["update"] }
path "sys/tools/random" { capabilities = ["update"] }
path "sys/control-group/request" { capabilities = ["update"] }

# OIDC authorize (restricted)
path "identity/oidc/provider/+/authorize" { capabilities = ["read"] }

# Secrets – user-specific access
path "secret/data/eos/{{"{{"}}identity.entity.name{{"}}"}}/*" { 
  capabilities = ["create", "read", "update", "delete", "list"]
  required_parameters = ["version"]
}
path "secret/metadata/eos/{{"{{"}}identity.entity.name{{"}}"}}/*" { 
  capabilities = ["read", "list", "delete"] 
}

# Shared secrets (read-only)
path "secret/data/shared/*" { 
  capabilities = ["read", "list"]
}

# Emergency access (highly restricted)
path "secret/data/emergency/*" { 
  capabilities = ["read"]
}

# Self-service user management (limited)
path "auth/userpass/users/{{"{{"}}identity.entity.name{{"}}"}}" {
  capabilities = ["read", "update"]
  denied_parameters = {
    "policies" = []
    "token_policies" = []
    "token_ttl" = []
    "token_max_ttl" = []
  }
}

# MFA management
path "auth/totp/keys/{{"{{"}}identity.entity.name{{"}}"}}" { capabilities = ["create", "read", "update", "delete"] }
path "auth/totp/code/{{"{{"}}identity.entity.name{{"}}"}}" { capabilities = ["update"] }

# Self-inspection for diagnostics (read-only)
# Allows tokens to verify their own policy and AppRole configuration
# Required for: sudo eos debug vault
path "sys/policies/acl/eos-default-policy" { capabilities = ["read"] }
path "sys/policies/acl/eos-admin-policy" { capabilities = ["read"] }
path "sys/policies/acl/eos-emergency-policy" { capabilities = ["read"] }
path "sys/policies/acl/eos-readonly-policy" { capabilities = ["read"] }
path "auth/approle/role/eos-approle" { capabilities = ["read"] }

# Deny dangerous operations
path "sys/raw/*" { capabilities = ["deny"] }
path "sys/unseal" { capabilities = ["deny"] }
path "sys/seal" { capabilities = ["deny"] }
path "sys/step-down" { capabilities = ["deny"] }
path "sys/rekey/*" { capabilities = ["deny"] }
path "auth/token/create-orphan" { capabilities = ["deny"] }
path "auth/token/create/*" { capabilities = ["deny"] }
path "sys/auth/*" { capabilities = ["deny"] }
path "sys/mounts/*" { capabilities = ["deny"] }
path "sys/policy/*" { capabilities = ["deny"] }
`

const EosAdminPolicyTemplate = `
# Administrative policy for Eos infrastructure management
# This policy provides elevated privileges for infrastructure administration

# Full token management
path "auth/token/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "sys/capabilities" { capabilities = ["update"] }
path "sys/capabilities-self" { capabilities = ["update"] }

# Identity management
path "identity/*" { capabilities = ["create", "read", "update", "delete", "list"] }

# System administration (restricted)
path "sys/auth/*" { 
  capabilities = ["create", "read", "update", "delete", "list"]
  denied_parameters = {
    "root" = []
  }
}
path "sys/mounts/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "sys/policy/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "sys/policies/*" { capabilities = ["create", "read", "update", "delete", "list"] }

# Audit and monitoring
path "sys/audit" { capabilities = ["read", "list"] }
path "sys/audit/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "sys/health" { capabilities = ["read"] }
path "sys/host-info" { capabilities = ["read"] }
path "sys/key-status" { capabilities = ["read"] }
path "sys/leader" { capabilities = ["read"] }
path "sys/seal-status" { capabilities = ["read"] }

# Secrets engines management
path "secret/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "sys/mounts" { capabilities = ["read", "list"] }

# Lease management
path "sys/leases/*" { capabilities = ["create", "read", "update", "delete", "list"] }

# Cubbyhole access
path "cubbyhole/*" { capabilities = ["create", "read", "update", "delete", "list"] }

# MFA administration
path "auth/totp/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "auth/mfa/*" { capabilities = ["create", "read", "update", "delete", "list"] }

# Deny dangerous root operations
path "sys/raw/*" { capabilities = ["deny"] }
path "sys/rekey/*" { capabilities = ["deny"] }
path "sys/rotate" { capabilities = ["deny"] }
path "sys/seal" { capabilities = ["deny"] }
path "sys/step-down" { capabilities = ["deny"] }
`

const EosEmergencyPolicyTemplate = `
# Emergency access policy for critical situations
# This policy provides broad access for emergency response

# Full read access to troubleshoot issues
path "*" { 
  capabilities = ["read", "list"]
}

# Limited write access for emergency fixes
path "secret/data/emergency/*" { 
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Essential system operations
path "sys/health" { capabilities = ["read"] }
path "sys/seal-status" { capabilities = ["read"] }
path "sys/leader" { capabilities = ["read"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self" { capabilities = ["update"] }

# Cubbyhole for temporary storage
path "cubbyhole/*" { capabilities = ["create", "read", "update", "delete", "list"] }

# Deny destructive operations
path "sys/raw/*" { capabilities = ["deny"] }
path "sys/rekey/*" { capabilities = ["deny"] }
path "sys/rotate" { capabilities = ["deny"] }
path "sys/seal" { capabilities = ["deny"] }
path "sys/step-down" { capabilities = ["deny"] }
path "auth/token/create-orphan" { capabilities = ["deny"] }
`

const EosReadOnlyPolicyTemplate = `
# Read-only policy for monitoring and auditing
# This policy provides read-only access for monitoring systems

# Read-only access to secrets (with audit trail)
path "secret/data/*" { 
  capabilities = ["read", "list"]
}
path "secret/metadata/*" { capabilities = ["read", "list"] }

# System status monitoring
path "sys/health" { capabilities = ["read"] }
path "sys/seal-status" { capabilities = ["read"] }
path "sys/leader" { capabilities = ["read"] }
path "sys/key-status" { capabilities = ["read"] }
path "sys/host-info" { capabilities = ["read"] }

# Auth methods (read-only)
path "sys/auth" { capabilities = ["read", "list"] }
path "sys/mounts" { capabilities = ["read", "list"] }
path "sys/policies" { capabilities = ["read", "list"] }

# Token management (self only)
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self" { capabilities = ["update"] }

# Personal cubbyhole only
path "cubbyhole/*" { capabilities = ["create", "read", "update", "delete", "list"] }

# Deny all write operations to critical paths
path "sys/auth/*" { capabilities = ["deny"] }
path "sys/mounts/*" { capabilities = ["deny"] }
path "sys/policy/*" { capabilities = ["deny"] }
`

func RenderEosPolicy(kvPath string) (string, error) {
	return renderPolicyTemplate(EosDefaultPolicyName, EosDefaultPolicyTemplate, kvPath)
}

func RenderEosAdminPolicy(kvPath string) (string, error) {
	return renderPolicyTemplate(EosAdminPolicyName, EosAdminPolicyTemplate, kvPath)
}

func RenderEosEmergencyPolicy(kvPath string) (string, error) {
	return renderPolicyTemplate(EosEmergencyPolicyName, EosEmergencyPolicyTemplate, kvPath)
}

func RenderEosReadOnlyPolicy(kvPath string) (string, error) {
	return renderPolicyTemplate(EosReadOnlyPolicyName, EosReadOnlyPolicyTemplate, kvPath)
}

func renderPolicyTemplate(name, templateStr, kvPath string) (string, error) {
	tmpl, err := template.New(name).
		Option("missingkey=error").
		Parse(templateStr)
	if err != nil {
		return "", fmt.Errorf("parse policy template %s: %w", name, err)
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, map[string]string{
		"KVPath": kvPath,
	})
	if err != nil {
		return "", fmt.Errorf("execute policy template %s: %w", name, err)
	}

	return buf.String(), nil
}
