// pkg/shared/fields.go

// Package shared defines common field names used across identity systems
// such as Vault, LDAP, SCIM, and internal Eos protocols.
package shared

const (
	// Username is the field key for identifying a user.
	// Used consistently in Vault KV, userpass auth, LDAP, and SCIM payloads.
	Username = "username"

	// Password is the field key for secrets, credentials, or login passwords.
	// Used in Vault KV, userpass auth, and other identity providers.
	Password = "password"

	// SSHPrivateKey is the field key for a user's private SSH key.
	// Used in Vault and any agent provisioning context.
	SSHPrivateKey = "ssh_private_key"
)
