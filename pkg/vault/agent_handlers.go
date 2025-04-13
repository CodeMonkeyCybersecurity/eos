/* pkg/vault/agent_handler.go */

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/hashicorp/vault/api"
)

// readTokenFromSink reads the Vault Agent token (run as 'eos' system user)
func readTokenFromSink(path string) (string, error) {
	out, err := exec.Command("sudo", "-u", "eos", "cat", path).Output()
	if err != nil {
		return "", fmt.Errorf("failed to read token from Vault Agent sink at %s: %w", path, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// GetPrivilegedVaultClient returns a Vault client authenticated as 'eos' system user
func GetPrivilegedVaultClient() (*api.Client, error) {
	token, err := readTokenFromSink("/etc/vault-agent-eos.token")
	if err != nil {
		return nil, err
	}
	client, err := NewClient()
	if err != nil {
		return nil, err
	}
	client.SetToken(token)
	return client, nil
}

// VaultCreate creates a secret only if it doesn't already exist
func VaultCreate(path string, value interface{}) error {
	client, err := GetPrivilegedVaultClient()
	if err != nil {
		return err
	}
	kv := client.KVv2("secret")

	_, err = kv.Get(context.Background(), path)
	if err == nil {
		return fmt.Errorf("data already exists at path: %s", path)
	}

	data, err := toMap(value)
	if err != nil {
		return err
	}
	_, err = kv.Put(context.Background(), path, data)
	return err
}

// VaultRead reads and decodes a secret struct from Vault
func VaultRead[T any](path string) (*T, error) {
	client, err := GetPrivilegedVaultClient()
	if err != nil {
		return nil, err
	}
	kv := client.KVv2("secret")

	secret, err := kv.Get(context.Background(), path)
	if err != nil {
		return nil, err
	}
	raw, ok := secret.Data["json"].(string)
	if !ok {
		return nil, errors.New("missing or invalid 'json' field in secret")
	}
	var result T
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret JSON: %w", err)
	}
	return &result, nil
}

// VaultUpdate reads existing secret and applies a patch map
func VaultUpdate(path string, update map[string]interface{}) error {
	client, err := GetPrivilegedVaultClient()
	if err != nil {
		return err
	}
	kv := client.KVv2("secret")

	secret, err := kv.Get(context.Background(), path)
	if err != nil {
		return err
	}

	existing := secret.Data
	for k, v := range update {
		existing[k] = v
	}
	_, err = kv.Put(context.Background(), path, existing)
	return err
}

// VaultDelete removes a secret at the given KV v2 path
func VaultDelete(path string) error {
	client, err := GetPrivilegedVaultClient()
	if err != nil {
		return err
	}
	kv := client.KVv2("secret")
	return kv.Delete(context.Background(), path)
}

// VaultDestroy permanently deletes a secret at the given KV v2 path
func VaultPurge(path string) error {
	client, err := GetPrivilegedVaultClient()
	if err != nil {
		return err
	}
	kv := client.KVv2("secret")
	return kv.Destroy(context.Background(), path, []int{1}) // TODO To truly destroy all versions, we can add a version-walk helper
}

// VaultList returns keys under a path
func VaultList(path string) ([]string, error) {
	client, err := GetPrivilegedVaultClient()
	if err != nil {
		return nil, err
	}
	list, err := client.Logical().List("secret/metadata/" + path)
	if err != nil || list == nil {
		return nil, err
	}
	raw := list.Data["keys"].([]interface{})
	keys := make([]string, len(raw))
	for i, k := range raw {
		keys[i] = fmt.Sprintf("%v", k)
	}
	return keys, nil
}

// Helper: Marshal to Vault KV payload format
func toMap(v interface{}) (map[string]interface{}, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"json": string(data)}, nil
}
