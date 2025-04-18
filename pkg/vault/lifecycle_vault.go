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
	log.Info("[1/9] Ensuring Vault is installed")
	if err := InstallVaultViaDnf(log); err != nil {
		return fmt.Errorf("vault install failed: %w", err)
	}

	log.Info("[2/9] Checking for port mismatch (8200 → 8179)")
	TryPatchVaultPortIfNeeded(log)

	log.Info("[3/9] Ensuring Vault runtime directory exists")
	if err := EnsureRuntimeDir(log); err != nil {
		log.Error("❌ Failed to create Vault runtime directory", zap.Error(err))
		return fmt.Errorf("runtime dir check failed: %w", err)
	}

	log.Info("[4/9] Ensuring Vault client is available and healthy")
	EnsureVaultClient(log)

	log.Info("[5/9] Getting Vault client for setup")
	client, err := GetVaultClient(log)
	if err != nil {
		log.Error("❌ Failed to get Vault client", zap.Error(err))
		return fmt.Errorf("could not get client: %w", err)
	}

	log.Info("[6/9] Initializing and unsealing Vault if necessary")
	_, _, err = SetupVault(client, log)
	if err != nil {
		log.Error("❌ Vault setup failed", zap.Error(err))
		return fmt.Errorf("vault setup failed: %w", err)
	}

	log.Info("[7/9] Getting privileged Vault client (via Vault Agent)")
	privClient, err := GetPrivilegedVaultClient(log)
	if err != nil {
		log.Error("❌ Failed to get privileged Vault client", zap.Error(err))
		return fmt.Errorf("privileged client failed: %w", err)
	}
	kv := privClient.KVv2("secret")

	log.Info("[8/9] Checking if secret already exists", zap.String("path", path))
	_, err = kv.Get(context.Background(), path)
	if err == nil {
		log.Warn("⚠️ Secret already exists", zap.String("path", path))
		return fmt.Errorf("data already exists at path: %s", path)
	}

	log.Info("[9/9] Writing secret to Vault", zap.String("path", path))
	data, err := toMap(value)
	if err != nil {
		log.Error("❌ Failed to marshal secret to Vault KV format", zap.Error(err))
		return err
	}

	if _, err := kv.Put(context.Background(), path, data); err != nil {
		log.Error("❌ Failed to write secret to Vault", zap.Error(err))
		return err
	}

	log.Info("✅ Secret written to Vault successfully", zap.String("path", path))
	return nil
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

/* Initialize Vault (if not already initialized) */
func SetupVault(client *api.Client, log *zap.Logger) (*api.Client, *api.InitResponse, error) {
	fmt.Println("\nInitializing Vault...")

	if err := EnsureRuntimeDir(log); err != nil {
		log.Error("Runtime dir missing or invalid", zap.Error(err))
		return nil, nil, err
	}

	initRes, err := client.Sys().Init(&api.InitRequest{
		SecretShares:    5,
		SecretThreshold: 3,
	})
	if err != nil {
		if IsAlreadyInitialized(err, log) {
			fmt.Println("✅ Vault already initialized.")

			// ✨ Reuse fallback or prompt logic
			initRes, err := LoadInitResultOrPrompt(client, log)
			if err != nil {
				return nil, nil, fmt.Errorf("vault already initialized and fallback failed: %w\n💡 Run `eos enable vault` on a fresh Vault to reinitialize and regenerate fallback data", err)
			}

			// 🔓 Unseal and auth
			if err := UnsealVault(client, initRes, log); err != nil {
				return nil, nil, fmt.Errorf("failed to unseal already-initialized Vault: %w", err)
			}
			client.SetToken(initRes.RootToken)

			// ✅ Re-store init result
			if err := Write(client, "vault_init", initRes, log); err != nil {
				log.Warn("Failed to persist Vault init result", zap.Error(err))
			} else {
				fmt.Println("✅ Vault init result persisted successfully")
			}
			return client, initRes, nil
		}
		return nil, nil, fmt.Errorf("init failed: %w", err)
	}

	// 🆕 Vault just initialized: unseal and persist
	DumpInitResult(initRes, log)
	if err := UnsealVault(client, initRes, log); err != nil {
		return nil, nil, err
	}
	client.SetToken(initRes.RootToken)

	if err := Write(client, "vault_init", initRes, log); err != nil {
		return nil, nil, fmt.Errorf("failed to persist Vault init result: %w", err)
	}
	fmt.Println("✅ Vault init result persisted successfully")

	return client, initRes, nil
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

func TryPatchVaultPortIfNeeded(log *zap.Logger) {
	b, err := os.ReadFile(VaultConfigPath)
	if err != nil {
		log.Warn("Could not read Vault config file", zap.String("path", VaultConfigPath), zap.Error(err))
		return
	}
	content := string(b)

	// Bail if already using 8179
	if strings.Contains(content, "8179") {
		log.Info("Vault config already uses port 8179 — no need to patch")
		return
	}

	// Check if 8200 is hardcoded and replace
	if strings.Contains(content, "8200") {
		newContent := strings.ReplaceAll(content, "8200", "8179")
		if err := os.WriteFile(VaultConfigPath, []byte(newContent), 0644); err != nil {
			log.Error("Failed to patch Vault config file", zap.Error(err))
			return
		}
		log.Info("✅ Vault port patched from 8200 → 8179 in config")

		// Restart Vault
		log.Info("🔁 Restarting Vault to apply new config...")
		cmd := exec.Command("systemctl", "restart", "vault")
		if err := cmd.Run(); err != nil {
			log.Error("❌ Failed to restart Vault after patching", zap.Error(err))
			return
		}
		log.Info("✅ Vault restarted successfully")
	} else {
		log.Info("No 8200 binding found in config — nothing to patch")
	}
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
