package enable

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var EnableVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Enables Vault with sane and secure defaults",
	Long: `This command assumes "github.com/CodeMonkeyCybersecurity/eos install vault" has been run.
It initializes and unseals Vault, sets up auditing, KV v2, 
AppRole, userpass, and creates an eos user with a random password.`,
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		// 0. Ensure Vault is installed
		if err := installVaultViaDnf(); err != nil {
			return err
		}

		// 1. Set VAULT_ADDR env var
		vault.SetVaultEnv()

		// 2. Create Vault client
		client, err := vault.NewClient()
		if err != nil {
			log.Fatal("Failed to create Vault client", zap.Error(err))
		}

		// 3. Init & unseal Vault
		client, initRes, err := setupVault(client)
		if err != nil {
			return err
		}

		// 4. Enable audit
		enableFileAudit(client)

		// 5. Enable KV
		if err := enableKV2(client); err != nil {
			return err
		}

		// 6. Test KV
		if err := testKVSecret(client); err != nil {
			return err
		}

		// 7. Enable AppRole
		if err := enableAppRoleAuth(client); err != nil {
			return err
		}

		// 8. Enable userpass
		if err := enableUserPassAuth(client); err != nil {
			return err
		}

		// 9. Create eos user + store secrets
		if err := createEosAndSecret(client, initRes); err != nil {
			return err
		}

		fmt.Println("\n✅ Vault enable steps completed successfully!")
		fmt.Println("🔑 You can now log in with the eos user using the generated password.")
		fmt.Println("📦 Please run 'eos secure vault' to secure the Vault service.")
		return nil
	}),
}

func init() {
	EnableCmd.AddCommand(EnableVaultCmd)
}

// 0. Install Vault via dnf if not already installed
func installVaultViaDnf() error {
	fmt.Println("[0/10] Checking if Vault is installed...")
	_, err := exec.LookPath("vault")
	if err != nil {
		fmt.Println("Vault binary not found. Installing via dnf...")

		dnfCmd := exec.Command("dnf", "install", "-y", "vault")
		dnfOut, err := dnfCmd.CombinedOutput()
		if err != nil {
			log.Fatal("Failed to install Vault via dnf", zap.Error(err), zap.String("output", string(dnfOut)))
		}
		fmt.Println("Vault installed successfully via dnf.")
	} else {
		fmt.Println("Vault is already installed.")
	}
	return nil
}

/* 2. Initialize Vault (if not already initialized) */
func setupVault(client *api.Client) (*api.Client, *api.InitResponse, error) {
	fmt.Println("\n[1/10] Initializing Vault (operator init)...")

	initRes, err := client.Sys().Init(&api.InitRequest{
		SecretShares:    5,
		SecretThreshold: 3,
	})
	if err != nil {
		if strings.Contains(err.Error(), "Vault is already initialized") {
			fmt.Println("Vault is already initialized. Skipping init.")
			return client, nil, nil
		}
		return nil, nil, fmt.Errorf("failed to init Vault: %w", err)
	}

	// Save init result to file
	b, _ := json.MarshalIndent(initRes, "", "  ")
	_ = os.WriteFile("/tmp/vault_init.json", b, 0600)
	_ = os.WriteFile("vault_init.json", b, 0600)
	fmt.Printf("✅ Vault initialized with %d unseal keys.\n", len(initRes.KeysB64))

	// Unseal Vault
	if len(initRes.KeysB64) >= 3 {
		fmt.Println("\n[2/10] Unsealing Vault...")
		for i := 0; i < 3; i++ {
			resp, err := client.Sys().Unseal(initRes.KeysB64[i])
			if err != nil {
				return nil, nil, fmt.Errorf("failed to unseal Vault: %w", err)
			}
			if !resp.Sealed {
				fmt.Printf("Vault unsealed after key %d\n", i+1)
				break
			}
		}
		fmt.Println("🔓 Unseal completed.")
	}

	// Log in with root token
	if initRes.RootToken != "" {
		fmt.Println("\n[3/10] Logging in with root token...")
		client.SetToken(initRes.RootToken)
	}

	return client, initRes, nil
}

/* Enable file audit at "/var/snap/vault/common/vault_audit.log" */
func enableFileAudit(client *api.Client) {
	fmt.Println("\n[4/10] Enabling file audit device...")

	_, err := client.Logical().Write("sys/audit/file", map[string]interface{}{
		"type": "file",
		"options": map[string]string{
			"file_path": "/var/snap/vault/common/vault_audit.log",
		},
	})
	if err != nil {
		log.Fatal("Failed to enable file audit device", zap.Error(err))
	}

	fmt.Println("✅ File audit enabled.")
}

/* Enable KV v2 */
func enableKV2(client *api.Client) error {
	fmt.Println("\n[5/10] Enabling KV v2 at path=secret...")

	err := client.Sys().Mount("secret", &api.MountInput{
		Type:    "kv",
		Options: map[string]string{"version": "2"},
	})
	if err != nil {
		if strings.Contains(err.Error(), "existing mount at") {
			fmt.Println("KV v2 is already enabled at path=secret.")
			return nil
		}
		return fmt.Errorf("failed to mount KV v2: %w", err)
	}

	fmt.Println("✅ KV v2 enabled at path=secret.")
	return nil
}

/* testing secrets read/write */
func testKVSecret(client *api.Client) error {
	fmt.Println("\n[6/10] Putting and getting a test secret (secret/hello)...")
	_, err := client.KVv2("secret").Put(context.Background(), "hello", map[string]interface{}{
		"value": "world",
	})
	if err != nil {
		log.Fatal("Failed to write test secret", zap.Error(err))
	}

	secret, err := client.KVv2("secret").Get(context.Background(), "hello")
	if err != nil {
		log.Fatal("Failed to read test secret", zap.Error(err))
	}
	fmt.Println("value:", secret.Data["value"])
	return nil
}

/* Enable AppRole auth, create a role, read the role ID */
func enableAppRoleAuth(client *api.Client) error {
	fmt.Println("\n[7/10] Enabling AppRole auth method...")

	err := client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{
		Type: "approle",
	})
	if err != nil {
		if strings.Contains(err.Error(), "path is already in use") {
			fmt.Println("AppRole auth already enabled.")
		} else {
			return fmt.Errorf("failed to enable AppRole auth: %w", err)
		}
	} else {
		fmt.Println("✅ AppRole auth enabled.")
	}

	fmt.Println("Configuring role my-role...")
	_, err = client.Logical().Write("auth/approle/role/my-role", map[string]interface{}{
		"token_policies":     "default,my-policy",
		"token_ttl":          "1h",
		"token_max_ttl":      "4h",
		"secret_id_ttl":      "60m",
		"secret_id_num_uses": 0,
	})
	if err != nil {
		return fmt.Errorf("failed to create AppRole role: %w", err)
	}
	fmt.Println("✅ Role 'my-role' created.")

	role, err := client.Logical().Read("auth/approle/role/my-role/role-id")
	if err != nil {
		return fmt.Errorf("failed to read role ID: %w", err)
	}
	fmt.Println("🔐 Role ID:", role.Data["role_id"])

	return nil
}

/* Enable userpass auth */
func enableUserPassAuth(client *api.Client) error {
	fmt.Println("\n[8/10] Enabling userpass auth method...")

	err := client.Sys().EnableAuthWithOptions("userpass", &api.EnableAuthOptions{
		Type: "userpass",
	})
	if err != nil {
		if strings.Contains(err.Error(), "path is already in use") {
			fmt.Println("Userpass auth already enabled.")
			return nil
		}
		return fmt.Errorf("failed to enable userpass auth: %w", err)
	}

	fmt.Println("✅ Userpass auth enabled.")
	return nil
}

/* Generate a random password and create an eos user with it */
func createEosAndSecret(client *api.Client, initRes *api.InitResponse) error {
	fmt.Println("\n[10/10] Generating random password and creating eos user...")

	password, err := crypto.GeneratePassword(20)
	if err != nil {
		log.Fatal("Failed to generate password", zap.Error(err))
	}

	// Save to fallback file
	fallbackFile := "/var/lib/eos/secrets/vault-userpass.yaml"
	os.MkdirAll("/var/lib/eos/secrets", 0700)
	fallbackContent := fmt.Sprintf("username: eos\npassword: %s\n", password)
	if err := os.WriteFile(fallbackFile, []byte(fallbackContent), 0600); err != nil {
		log.Warn("Failed to write fallback password file", zap.Error(err))
	} else {
		fmt.Printf("🔐 Stored eos Vault user password at %s\n", fallbackFile)
	}

	/* Store in Vault */
	vault.SaveSecret(client, "secret/bootstrap/eos-user", map[string]interface{}{
		"username": "eos",
		"password": password,
	})

	// Setup Vault Agent
	if err := vault.SetupVaultAgent(password); err != nil {
		log.Fatal("Failed to set up Vault Agent service", zap.Error(err))
	}

	// Create eos user with userpass auth
	_, err = client.Logical().Write("auth/userpass/users/eos", map[string]interface{}{
		"password": password,
		"policies": "eos",
	})
	if err != nil {
		log.Fatal("Failed to create eos Administrative user", zap.Error(err))
	}

	// Save init result
	if err := vault.Save("vault-init", initRes); err != nil {
		log.Warn("Failed to store vault-init data in Vault", zap.Error(err))
	}

	return nil
}
