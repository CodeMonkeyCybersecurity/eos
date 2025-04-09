/* pkg/vault/lifecycle.go */
package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/hashicorp/vault/api"
)

// Purge removes Vault repo artifacts based on the Linux distro.
// It returns a list of removed files and a map of errors keyed by path.
func purge(distro string) (removed []string, errs map[string]error) {
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

// deployAndStoreSecrets automates Vault setup and stores secrets after confirmation.
func DeployAndStoreSecrets(client *api.Client, path string, secrets map[string]string) error {
	fmt.Println("🚀 Deploying Vault...")

	if err := execute.ExecuteAndLog("eos", "deploy", "vault"); err != nil && !strings.Contains(err.Error(), "already installed") {
		return fmt.Errorf("vault deploy failed: %w", err)
	}

	if err := execute.ExecuteAndLog("eos", "enable", "vault"); err != nil {
		fmt.Println("⚠️ Vault enable failed — manual unseal may be required.")
		return fmt.Errorf("vault enable failed: %w", err)
	}

	if err := execute.ExecuteAndLog("eos", "secure", "vault"); err != nil {
		return fmt.Errorf("vault secure failed: %w", err)
	}

	if !IsVaultAvailable(client) {
		return fmt.Errorf("vault does not appear to be running after setup. Try 'eos logs vault'")
	}

	fmt.Println("✅ Vault is running. Storing secrets...")

	// Convert string map to interface{}
	data := make(map[string]interface{}, len(secrets))
	for k, v := range secrets {
		data[k] = v
	}

	return SaveSecret(client, path, data)
}

func RevokeRootToken(client *api.Client, token string) error {
	client.SetToken(token)

	err := client.Auth().Token().RevokeSelf("")
	if err != nil {
		return fmt.Errorf("failed to revoke root token: %w", err)
	}

	fmt.Println("✅ Root token revoked.")
	return nil
}

// 0. Install Vault via dnf if not already installed
func InstallVaultViaDnf() error {
	fmt.Println("[0/10] Checking if Vault is installed...")
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

/* 2. Initialize Vault (if not already initialized) */
func SetupVault(client *api.Client) (*api.Client, *api.InitResponse, error) {
	fmt.Println("\n[1/10] Initializing Vault...")

	initRes, err := client.Sys().Init(&api.InitRequest{
		SecretShares:    5,
		SecretThreshold: 3,
	})
	if err != nil {
		if IsAlreadyInitialized(err) {
			fmt.Println("⚠️ Vault already initialized.")

			// 1. Try to load from fallback YAML first
			var initRes api.InitResponse
			if err := readFallbackYAML(diskPath("vault-init"), &initRes); err != nil {
				return nil, nil, fmt.Errorf("vault already initialized and fallback read failed: %w\n💡 Run `eos enable vault` on a fresh Vault to reinitialize and regenerate fallback data", err)
			}

			// 2. Use the token to authenticate the client
			client.SetToken(initRes.RootToken)

			// 3. Optionally try to re-load from Vault to verify
			var vaultRes api.InitResponse
			if err := loadFromVault(client, "vault-init", &vaultRes); err != nil {
				fmt.Println("⚠️ Could not verify Vault load: continuing with fallback initRes")
			} else {
				initRes = vaultRes
			}

			return client, &initRes, nil
		}
		return nil, nil, fmt.Errorf("init failed: %w", err)
	}

	// ✅ Save the init result to fallback and optionally Vault
	DumpInitResult(initRes)
	if err := Save(client, "vault-init", initRes); err != nil {
		fmt.Println("⚠️ Failed to persist Vault init result:", err)
	}

	// 🔓 Proceed to unseal
	if err := UnsealVault(client, initRes); err != nil {
		return nil, nil, err
	}

	client.SetToken(initRes.RootToken)
	return client, initRes, nil
}

func IsAlreadyInitialized(err error) bool {
	return strings.Contains(err.Error(), "Vault is already initialized")
}

func DumpInitResult(initRes *api.InitResponse) {
	b, _ := json.MarshalIndent(initRes, "", "  ")
	_ = os.WriteFile("/tmp/vault_init.json", b, 0600)
	_ = os.WriteFile("vault_init.json", b, 0600)
	fmt.Printf("✅ Vault initialized with %d unseal keys.\n", len(initRes.KeysB64))
}

func UnsealVault(client *api.Client, initRes *api.InitResponse) error {
	if len(initRes.KeysB64) < 3 {
		return fmt.Errorf("not enough unseal keys")
	}

	fmt.Println("\n[2/10] Unsealing Vault...")
	for i, key := range initRes.KeysB64[:3] {
		resp, err := client.Sys().Unseal(key)
		if err != nil {
			return fmt.Errorf("unseal failed: %w", err)
		}
		if !resp.Sealed {
			fmt.Printf("✅ Vault unsealed after key %d\n", i+1)
			break
		}
	}
	fmt.Println("🔓 Unseal completed.")
	return nil
}

/* Enable file audit at "/var/snap/vault/common/vault_audit.log" */
func EnableFileAudit(client *api.Client) error {
	return enableFeature(client, "sys/audit/file",
		map[string]interface{}{
			"type": "file",
			"options": map[string]string{
				"file_path": "/var/snap/vault/common/vault_audit.log",
			},
		},
		"✅ File audit enabled.",
	)
}

/* Enable KV v2 */
func EnableKV2(client *api.Client) error {
	return enableMount(client, "secret", "kv", map[string]string{"version": "2"}, "✅ KV v2 enabled at path=secret.")
}

/* Enable AppRole */
func EnableAppRole(client *api.Client) error {
	return enableAuth(client, "approle")
}

/* Enable UserPass */
func EnableUserPass(client *api.Client) error {
	return enableAuth(client, "userpass")
}

/* Generate a random password and create an eos user with it */
func CreateEosAndSecret(client *api.Client, initRes *api.InitResponse) error {
	fmt.Println("\n[10/10] Generating random password and creating eos user...")

	password, err := crypto.GeneratePassword(20)
	if err != nil {
		fmt.Println("❌ Failed to generate password:", err)
		os.Exit(1)
	}

	// Save to fallback file
	fallbackFile := "/var/lib/eos/secrets/vault-userpass.yaml"
	os.MkdirAll("/var/lib/eos/secrets", 0700)
	fallbackContent := fmt.Sprintf("username: eos\npassword: %s\n", password)
	if err := os.WriteFile(fallbackFile, []byte(fallbackContent), 0600); err != nil {
		fmt.Println("⚠️ Failed to write fallback password file:", err)
	} else {
		fmt.Printf("🔐 Stored eos Vault user password at %s\n", fallbackFile)
	}

	// Store in Vault
	SaveSecret(client, "secret/bootstrap/eos-user", map[string]interface{}{
		"username": "eos",
		"password": password,
	})

	// Setup Vault Agent
	if err := setupVaultAgent(password); err != nil {
		fmt.Println("⚠️ Failed to set up Vault Agent service:", err)
	}

	// Create eos user with userpass auth
	_, err = client.Logical().Write("auth/userpass/users/eos", map[string]interface{}{
		"password": password,
		"policies": "eos",
	})
	if err != nil {
		fmt.Println("❌ Failed to create eos user:", err)
		os.Exit(1)
	}

	// Save init result
	if err := Save(client, "vault-init", initRes); err != nil {
		fmt.Println("⚠️ Failed to store vault-init data in Vault:", err)
	}

	return nil
}
