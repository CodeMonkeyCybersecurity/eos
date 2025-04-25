// pkg/shared/vault_types.go

package shared

//
// ------------------------- TYPES -------------------------
//

type FallbackMode int

type FallbackCode string

// CheckReport represents the current state of a Vault instance during a health check.
type CheckReport struct {
	Installed   bool     // Vault binary is installed
	Initialized bool     // Vault has been initialized
	Sealed      bool     // Vault is currently sealed
	TokenReady  bool     // A token is available and usable
	KVWorking   bool     // The KV engine is accessible
	Notes       []string // Additional context or warnings
}

type UserpassCreds struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// UserSecret holds login and SSH key material for a system user.
type UserSecret struct {
	Username string `json:"username"`
	Password string `json:"password"`
	SSHKey   string `json:"ssh_private_key,omitempty"`
}

// AppRoleOptions defines options for provisioning or refreshing a Vault AppRole.
type AppRoleOptions struct {
	RoleName      string   // Vault AppRole name
	Policies      []string // List of Vault policies to attach
	TokenTTL      string   // TTL for generated tokens
	TokenMaxTTL   string   // Maximum TTL allowed for tokens
	SecretIDTTL   string   // TTL for generated Secret IDs
	ForceRecreate bool     // Whether to forcibly recreate the AppRole
	RefreshCreds  bool     // Whether to refresh AppRole credentials if already on disk
}
