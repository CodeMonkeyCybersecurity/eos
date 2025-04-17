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
	"go.uber.org/zap"
)

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

// DeployAndStoreSecrets automates Vault setup and stores secrets after confirmation.
func DeployAndStoreSecrets(client *api.Client, path string, secrets map[string]string, log *zap.Logger) error {
	log.Info("🚀 Starting Vault deployment")

	if err := execute.ExecuteAndLog("eos", "deploy", "vault"); err != nil && !strings.Contains(err.Error(), "already installed") {
		log.Error("Vault deploy failed", zap.Error(err))
		return fmt.Errorf("vault deploy failed: %w", err)
	}

	if err := execute.ExecuteAndLog("eos", "enable", "vault"); err != nil {
		log.Warn("Vault enable failed — manual unseal may be required", zap.Error(err))
		return fmt.Errorf("vault enable failed: %w", err)
	}

	if err := execute.ExecuteAndLog("eos", "secure", "vault"); err != nil {
		log.Error("Vault secure failed", zap.Error(err))
		return fmt.Errorf("vault secure failed: %w", err)
	}

	report, client := Check(client, log, nil, "")
	if !report.Initialized || report.Sealed || !report.KVWorking {
		log.Error("Vault is not fully operational after setup", zap.Any("report", report))
		return fmt.Errorf("vault does not appear to be running after setup. Try 'eos logs vault'")
	}

	log.Info("✅ Vault is ready. Proceeding to store secrets...", zap.String("path", path))

	// Convert string map to interface{}
	data := make(map[string]interface{}, len(secrets))
	for k, v := range secrets {
		data[k] = v
	}

	if err := WriteSecret(client, path, data); err != nil {
		log.Error("Failed to write secrets to Vault", zap.String("path", path), zap.Error(err))
		return err
	}

	log.Info("✅ Secrets written to Vault successfully", zap.String("path", path))
	return nil
}

func RevokeRootToken(client *api.Client, token string, log *zap.Logger) error {
	client.SetToken(token)

	err := client.Auth().Token().RevokeSelf("")
	if err != nil {
		return fmt.Errorf("failed to revoke root token: %w", err)
	}

	fmt.Println("✅ Root token revoked.")
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
		if IsAlreadyInitialized(err) {
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

func IsAlreadyInitialized(err error) bool {
	return strings.Contains(err.Error(), "Vault is already initialized")
}

func DumpInitResult(initRes *api.InitResponse, log *zap.Logger) {
	b, _ := json.MarshalIndent(initRes, "", "  ")
	_ = os.WriteFile("/tmp/vault_init.json", b, 0600)
	_ = os.WriteFile(DiskPath("vault_init", log), b, 0600)
	fmt.Printf("✅ Vault initialized with %d unseal keys.\n", len(initRes.KeysB64))
}

func UnsealVault(client *api.Client, initRes *api.InitResponse, log *zap.Logger) error {
	if len(initRes.KeysB64) < 3 {
		return fmt.Errorf("not enough unseal keys")
	}

	fmt.Println("\nUnsealing Vault...")
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
func EnableFileAudit(client *api.Client, log *zap.Logger) error {

	// Check if the audit device is already enabled
	audits, err := client.Sys().ListAudit()
	if err != nil {
		return fmt.Errorf("failed to list audit devices: %w", err)
	}

	if _, exists := audits[auditPath]; exists {
		log.Info("Audit device already enabled at sys/audit/file. Skipping.")
		return nil
	}

	// Enable the audit device
	return enableFeature(client, mountPath,
		map[string]interface{}{
			"type": "file",
			"options": map[string]string{
				"file_path": "/var/snap/vault/common/vault_audit.log",
			},
		},
		"✅ File audit enabled.",
	)
}

func IsMountEnabled(client *api.Client, mount string) (bool, error) {
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return false, err
	}
	_, exists := mounts[mount]
	return exists, nil
}

/* Enable KV v2 */
func EnableKV2(client *api.Client, log *zap.Logger) error {
	ok, err := IsMountEnabled(client, "secret/")
	if err != nil {
		return fmt.Errorf("failed to check if KV is mounted: %w", err)
	}
	if ok {
		log.Info("KV v2 already mounted at path=secret/. Skipping.")
		return nil
	}
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
func CreateEosAndSecret(client *api.Client, initRes *api.InitResponse, log *zap.Logger) error {
	fmt.Println("\nGenerating random password and creating eos user...")

	password, err := crypto.GeneratePassword(20)
	if err != nil {
		return fmt.Errorf("failed to generate password: %w", err)
	}

	if err := os.MkdirAll(SecretsDir, 0700); err != nil {
		return fmt.Errorf("failed to create secrets directory: %w", err)
	}

	creds := UserpassCreds{
		Username: "eos",
		Password: password,
	}

	if err := WriteFallbackJSON(EosUserFallbackFile, creds); err != nil {
		fmt.Println("⚠️ Failed to write eos Vault user fallback secret:", err)
	} else {
		fmt.Printf("🔐 Stored eos Vault user password at %s\n", EosUserFallbackFile)
	}

	// Store in Vault
	if err := WriteToVaultAt("secret", "bootstrap/eos-user", map[string]interface{}{
		"username": "eos",
		"password": password,
	}); err != nil {
		fmt.Println("❌ Failed to store eos-user secret in Vault:", err)
	} else {
		fmt.Println("✅ eos-user secret successfully written to Vault.")
	}

	// Setup Vault Agent
	if err := EnsureVaultAgent(password, log); err != nil {
		fmt.Println("⚠️ Failed to set up Vault Agent service:", err)
	}

	fmt.Println("📜 Re-applying eos policy:\n" + Policies[EosVaultPolicy])
	err = client.Sys().PutPolicy(EosVaultPolicy, Policies[EosVaultPolicy])
	if err != nil {
		fmt.Println("❌ Failed to create eos policy:", err)
		os.Exit(1)
	}

	// Create eos user with userpass auth
	_, err = client.Logical().Write(
		"auth/userpass/users/eos",
		map[string]interface{}{
			"password": password,
			"policies": "default," + EosVaultPolicy,
		},
	)
	if err != nil {
		fmt.Println("❌ Failed to create eos user:", err)
		os.Exit(1)
	}

	// Write init result
	if err := Write(client, "vault_init", initRes, log); err != nil {
		fmt.Println("⚠️ Failed to store vault_init data in Vault:", err)
	} else {
		fmt.Println("✅ vault_init successfully written to Vault.")
	}

	return nil
}

func EnableVaultAuthMethods(client *api.Client) error {
	if err := enableAuth(client, "userpass"); err != nil {
		return err
	}
	if err := enableAuth(client, "approle"); err != nil {
		return err
	}
	return nil
}

func CreateUserpassAccount(client *api.Client, username, password string) error {
	fmt.Printf("👤 Creating Vault userpass account for %q...\n", username)

	_, err := client.Logical().Write(
		"auth/userpass/users/"+username,
		map[string]interface{}{
			"password": password,
			"policies": EosVaultPolicy,
		},
	)
	return err
}

func SetupEosVaultUser(client *api.Client, password string, log *zap.Logger) error {
	if err := EnableVaultAuthMethods(client); err != nil {
		return err
	}
	if err := CreateUserpassAccount(client, "eos", password); err != nil {
		return err
	}
	if err := CreateAppRole(client, "eos", log); err != nil {
		return err
	}
	return nil
}
