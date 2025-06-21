// pkg/vault/policy_presets.go

package vault

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// BuildEosDefaultPolicy creates the default EOS user policy using the builder
func BuildEosDefaultPolicy(rc *eos_io.RuntimeContext) (string, error) {
	builder := NewPolicyBuilder()

	policy := builder.
		AddComment("EOS Default Policy - Standard user access with security restrictions").
		AddTokenCapabilities().
		AddIdentityCapabilities().
		AddCubbyholeAccess().
		AddUserSecrets().
		AddSharedSecretsReadOnly().
		AddSelfServiceUserpass().
		AddMFAManagement().
		AddSection("Essential Tools").
		AddPath("sys/tools/hash", "update").
		AddPath("sys/tools/random", "update").
		AddPath("sys/control-group/request", "update").
		AddSection("OIDC Authorization (Restricted)").
		AddPath("identity/oidc/provider/+/authorize", "read").
		AddSection("System Information (Read-Only)").
		AddPath("sys/internal/ui/resultant-acl", "read").
		AddPath("sys/renew", "update").
		AddPath("sys/leases/renew", "update").
		AddPath("sys/leases/lookup", "update").
		AddSecurityDenials()

	return policy.Build(rc)
}

// BuildEosAdminPolicy creates the admin policy for infrastructure management
func BuildEosAdminPolicy(rc *eos_io.RuntimeContext) (string, error) {
	builder := NewPolicyBuilder()

	policy := builder.
		AddComment("EOS Admin Policy - Infrastructure management with elevated privileges").
		AddSection("Full Token Management").
		AddPath("auth/token/*", "create", "read", "update", "delete", "list").
		AddPath("sys/capabilities", "update").
		AddPath("sys/capabilities-self", "update").
		AddSection("Identity Management").
		AddPath("identity/*", "create", "read", "update", "delete", "list").
		AddSection("System Administration (Restricted)").
		AddPathWithDeniedParams(
			"sys/auth/*",
			[]string{"create", "read", "update", "delete", "list"},
			map[string][]string{"root": {}},
		).
		AddPath("sys/mounts/*", "create", "read", "update", "delete", "list").
		AddPath("sys/policy/*", "create", "read", "update", "delete", "list").
		AddPath("sys/policies/*", "create", "read", "update", "delete", "list").
		AddSection("Audit and Monitoring").
		AddPath("sys/audit", "read", "list").
		AddPath("sys/audit/*", "create", "read", "update", "delete", "list").
		AddPath("sys/health", "read").
		AddPath("sys/host-info", "read").
		AddPath("sys/key-status", "read").
		AddPath("sys/leader", "read").
		AddPath("sys/seal-status", "read").
		AddSection("Secrets Engine Management").
		AddPath("secret/*", "create", "read", "update", "delete", "list").
		AddPath("sys/mounts", "read", "list").
		AddSection("Lease Management").
		AddPath("sys/leases/*", "create", "read", "update", "delete", "list").
		AddSection("Cubbyhole Access").
		AddPath("cubbyhole/*", "create", "read", "update", "delete", "list").
		AddSection("MFA Administration").
		AddPath("auth/totp/*", "create", "read", "update", "delete", "list").
		AddPath("auth/mfa/*", "create", "read", "update", "delete", "list").
		AddSection("Security Denials (Root Operations)").
		AddPath("sys/raw/*", "deny").
		AddPath("sys/rekey/*", "deny").
		AddPath("sys/rotate", "deny").
		AddPath("sys/seal", "deny").
		AddPath("sys/step-down", "deny")

	return policy.Build(rc)
}

// BuildEosEmergencyPolicy creates the emergency access policy
func BuildEosEmergencyPolicy(rc *eos_io.RuntimeContext) (string, error) {
	builder := NewPolicyBuilder()

	policy := builder.
		AddComment("EOS Emergency Policy - Broad access for emergency response").
		AddSection("Emergency Read Access").
		AddPath("*", "read", "list").
		AddSection("Emergency Write Access").
		AddPath("secret/data/emergency/*", "create", "read", "update", "delete", "list").
		AddSection("Essential System Operations").
		AddPath("sys/health", "read").
		AddPath("sys/seal-status", "read").
		AddPath("sys/leader", "read").
		AddPath("auth/token/lookup-self", "read").
		AddPath("auth/token/renew-self", "update").
		AddSection("Cubbyhole for Temporary Storage").
		AddPath("cubbyhole/*", "create", "read", "update", "delete", "list").
		AddSection("Security Denials (Destructive Operations)").
		AddPath("sys/raw/*", "deny").
		AddPath("sys/rekey/*", "deny").
		AddPath("sys/rotate", "deny").
		AddPath("sys/seal", "deny").
		AddPath("sys/step-down", "deny").
		AddPath("auth/token/create-orphan", "deny")

	return policy.Build(rc)
}

// BuildEosReadOnlyPolicy creates the read-only policy for monitoring
func BuildEosReadOnlyPolicy(rc *eos_io.RuntimeContext) (string, error) {
	builder := NewPolicyBuilder()

	policy := builder.
		AddComment("EOS Read-Only Policy - Monitoring and auditing access").
		AddSection("Read-Only Secrets Access").
		AddPath("secret/data/*", "read", "list").
		AddPath("secret/metadata/*", "read", "list").
		AddSection("System Status Monitoring").
		AddPath("sys/health", "read").
		AddPath("sys/seal-status", "read").
		AddPath("sys/leader", "read").
		AddPath("sys/key-status", "read").
		AddPath("sys/host-info", "read").
		AddSection("Auth Methods (Read-Only)").
		AddPath("sys/auth", "read", "list").
		AddPath("sys/mounts", "read", "list").
		AddPath("sys/policies", "read", "list").
		AddSection("Token Management (Self Only)").
		AddPath("auth/token/lookup-self", "read").
		AddPath("auth/token/renew-self", "update").
		AddSection("Personal Cubbyhole").
		AddPath("cubbyhole/*", "create", "read", "update", "delete", "list").
		AddSection("Security Denials").
		AddPath("sys/auth/*", "deny").
		AddPath("sys/mounts/*", "deny").
		AddPath("sys/policy/*", "deny")

	return policy.Build(rc)
}
