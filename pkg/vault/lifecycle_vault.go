// pkg/vault/vault_lifecycle.go

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//
// ========================== CREATE ==========================
//

// VaultCreate creates a secret only if it doesn't already exist
func EnsureVault(path string, value interface{}, log *zap.Logger) error {
	client, err := GetPrivilegedVaultClient(log)
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

/* Install Vault via dnf if not already installed */
func InstallVaultViaDnf(log *zap.Logger) error {
	fmt.Println("Checking if Vault is installed...")
	_, err := exec.LookPath("vault")
	if err != nil {
		fmt.Println("Vault binary not found. Installing via dnf...")

		dnfCmd := exec.Command("dnf", "install", "-y", "vault")
		dnfOut, err := dnfCmd.CombinedOutput()
		if err != nil {
			fmt.Println("❌ Failed to install Vault via dnf")
			fmt.Println("Output:", string(dnfOut))
			os.Exit(1)
		}
		fmt.Println("✅ Vault installed successfully via dnf.")
	} else {
		fmt.Println("Vault is already installed.")
	}
	return nil
}

//
// ========================== LIST ==========================
//

// VaultList returns keys under a path
func ListVault(path string, log *zap.Logger) ([]string, error) {
	client, err := GetPrivilegedVaultClient(log)
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

//
// ========================== READ ==========================
//

// VaultRead reads and decodes a secret struct from Vault
func ReadVault[T any](path string, log *zap.Logger) (*T, error) {
	client, err := GetPrivilegedVaultClient(log)
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

// readTokenFromSink reads the Vault Agent token (run as 'eos' system user)
func readTokenFromSink(path string) (string, error) {
	if path == "" {
		path = VaultAgentTokenPath
	}
	out, err := exec.Command("sudo", "-u", "eos", "cat", path).Output()
	if err != nil {
		return "", fmt.Errorf("failed to read token from Vault Agent sink at %s: %w", path, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// GetPrivilegedVaultClient returns a Vault client authenticated as 'eos' system user
func GetPrivilegedVaultClient(log *zap.Logger) (*api.Client, error) {
	token, err := readTokenFromSink(VaultAgentTokenPath)
	if err != nil {
		return nil, err
	}
	client, err := NewClient(log)
	if err != nil {
		return nil, err
	}
	client.SetToken(token)
	return client, nil
}

//
// ========================== UPDATE ==========================
//

// VaultUpdate reads existing secret and applies a patch map
func UpdateVault(path string, update map[string]interface{}, log *zap.Logger) error {
	client, err := GetPrivilegedVaultClient(log)
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

//
// ========================== DELETE ==========================
//

// Purge removes Vault repo artifacts based on the Linux distro.
// It returns a list of removed files and a map of errors keyed by path.
func Purge(distro string, log *zap.Logger) (removed []string, errs map[string]error) {
	errs = make(map[string]error)

	switch distro {
	case "debian":
		paths := []string{
			"/usr/share/keyrings/hashicorp-archive-keyring.gpg",
			"/etc/apt/sources.list.d/hashicorp.list",
		}
		for _, path := range paths {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				errs[path] = fmt.Errorf("failed to remove %s: %w", path, err)
			} else {
				removed = append(removed, path)
			}
		}
	case "rhel":
		repoFile := "/etc/yum.repos.d/hashicorp.repo"
		if err := os.Remove(repoFile); err != nil && !os.IsNotExist(err) {
			errs[repoFile] = fmt.Errorf("failed to remove %s: %w", repoFile, err)
		} else {
			removed = append(removed, repoFile)
		}
	}

	return removed, errs
}

// VaultDelete removes a secret at the given KV v2 path
func VaultDelete(path string, log *zap.Logger) error {
	client, err := GetPrivilegedVaultClient(log)
	if err != nil {
		return err
	}
	kv := client.KVv2("secret")
	return kv.Delete(context.Background(), path)
}

// VaultDestroy permanently deletes a secret at the given KV v2 path
func VaultPurge(path string, log *zap.Logger) error {
	client, err := GetPrivilegedVaultClient(log)
	if err != nil {
		return err
	}
	kv := client.KVv2("secret")
	return kv.Destroy(context.Background(), path, []int{1}) // TODO To truly destroy all versions, we can add a version-walk helper
}
