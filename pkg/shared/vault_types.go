// pkg/shared/vault_types.go

package shared

//
// ------------------------- TYPES -------------------------
//

type FallbackMode int

type FallbackCode string

// CheckReport represents the current state of a Vault instance during a health check.
type CheckReport struct {
	Installed       bool     // Vault binary is installed
	Initialized     bool     // Vault has been initialized
	Sealed          bool     // Vault is currently sealed
	TokenReady      bool     // A token is available and usable
	KVWorking       bool     // The KV engine is accessible
	Notes           []string // Additional context or warnings
	SecretsVerified bool     // Unseal keys + root token matched trusted reference
}

// AppRoleOptions defines how EOS provisions or refreshes a Vault AppRole.
type AppRoleOptions struct {
	RoleName      string   `json:"role_name,omitempty"`
	Policies      []string `json:"policies,omitempty"`
	TokenTTL      string   `json:"token_ttl,omitempty"`
	TokenMaxTTL   string   `json:"token_max_ttl,omitempty"`
	SecretIDTTL   string   `json:"secret_id_ttl,omitempty"`
	ForceRecreate bool     `json:"force_recreate,omitempty"`
	RefreshCreds  bool     `json:"refresh_creds,omitempty"`
}

// VaultInitResponse mirrors the vault_init.json structure.
type VaultInitResponse struct {
	KeysB64   []string `json:"unseal_keys_b64"`
	RootToken string   `json:"root_token"`
}
