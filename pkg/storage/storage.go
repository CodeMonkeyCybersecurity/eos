package storage

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault/api"
)

var vaultClient *api.Client

// SetVaultClient allows Vault to be injected for reuse.
func SetVaultClient(client *api.Client) {
	vaultClient = client
}

// SaveToVault stores any struct at the given Vault path
func SaveToVault(path string, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to marshal struct: %w", err)
	}

	m := map[string]interface{}{
		"data": string(data),
	}

	_, err = vaultClient.Logical().Write(path, m)
	if err != nil {
		return fmt.Errorf("failed to write to Vault: %w", err)
	}
	return nil
}

// LoadFromVault retrieves a struct from Vault into the given reference
func LoadFromVault(path string, v interface{}) error {
	secret, err := vaultClient.Logical().Read(path)
	if err != nil || secret == nil {
		return fmt.Errorf("no data found at path: %s", path)
	}

	raw, ok := secret.Data["data"].(string)
	if !ok {
		return fmt.Errorf("invalid Vault structure for %s", path)
	}

	if err := json.Unmarshal([]byte(raw), v); err != nil {
		return fmt.Errorf("failed to unmarshal Vault data: %w", err)
	}
	return nil
}
