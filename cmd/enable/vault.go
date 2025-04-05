package enable

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// initResult is the JSON structure returned by "vault operator init -format=json".
type initResult struct {
	UnsealKeysB64 []string `json:"unseal_keys_b64"`
	RootToken     string   `json:"root_token"`
}

var EnableVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Enables Vault with sane and secure defaults",
	Long: `This command assumes "github.com/CodeMonkeyCybersecurity/eos install vault" has been run.
It initializes and unseals Vault, sets up auditing, KV v2, 
AppRole, userpass, and creates an admin user with a random password.`,
	Run: func(cmd *cobra.Command, args []string) {

		// 0. Install Vault via dnf if not already installed
		fmt.Println("[0/9] Checking if Vault is installed...")
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

		// 1. Dynamically set VAULT_ADDR based on hostname.
		vault.SetVaultEnv()

		// 2. Initialize Vault (if not already initialized).
		fmt.Println("\n[1/9] Initializing Vault (operator init)...")
		initCmd := exec.Command("vault", "operator", "init",
			"-key-shares=5", "-key-threshold=3", "-format=json")

		var initOut []byte
		err = execute.RetryCaptureOutput(3, 2*time.Second, initCmd, &initOut)

		var initRes initResult
		if err != nil {
			if strings.Contains(string(initOut), "Vault is already initialized") {
				fmt.Println("Vault is already initialized. Skipping init.")
			} else {
				log.Fatal("Failed to init Vault",
					zap.Error(err),
					zap.String("output", string(initOut)),
				)
			}
		} else {
			// Parse the JSON output.
			if err := json.Unmarshal(initOut, &initRes); err != nil {
				log.Fatal("Failed to parse init output", zap.Error(err))
			}

			// Print the unseal keys and root token.
			fmt.Println("Unseal keys:")
			fmt.Printf("Vault initialized! Received %d unseal keys.\n", len(initRes.UnsealKeysB64))
			fmt.Println("Storing these keys for demonstration. In production, store them securely!")
			// Write the JSON output to a secure file.
			if err := os.WriteFile("vault_init.json", initOut, 0600); err != nil {
				log.Fatal("Failed to write initialization output", zap.Error(err))
			}
			fmt.Println("Initialization data stored securely in vault_init.json")
		}

		// 3. Unseal Vault with the first three unseal keys.
		//    (If already initialized, we only do this if we actually got new keys.)
		if len(initRes.UnsealKeysB64) >= 3 {
			fmt.Println("\n[2/9] Unsealing Vault...")
			for i := 0; i < 3; i++ {
				fmt.Printf("Unsealing with key %d...\n", i+1)
				unsealCmd := exec.Command("vault", "operator", "unseal", initRes.UnsealKeysB64[i])
				unsealOut, err := unsealCmd.CombinedOutput()
				if err != nil {
					log.Fatal("Failed to put test secret", zap.Error(err), zap.String("output", string(unsealOut)))
				}
			}
			fmt.Println("Unseal completed.")
		} else {
			fmt.Println("Skipping unseal because we didn't parse new unseal keys (Vault likely already unsealed).")
		}

		// 4. Log in with the root token (if we got a token).
		//    (If Vault was already initialized, user must already have a token or be unsealed.)
		if initRes.RootToken != "" {
			fmt.Println("\n[3/9] Logging in with root token...")
			loginCmd := exec.Command("vault", "login", initRes.RootToken)
			loginOut, err := loginCmd.CombinedOutput()
			if err != nil {
				log.Fatal("Failed to log in with root token", zap.Error(err), zap.String("output", string(loginOut)))
			}
			fmt.Println("Logged in as root.")
		} else {
			fmt.Println("Skipping root login (Vault was already initialized and we didn't parse a new token).")
		}

		// 5. Enable file audit at "/var/snap/vault/common/vault_audit.log"
		fmt.Println("\n[4/9] Enabling file audit device...")
		auditCmd := exec.Command("vault", "audit", "enable", "file", "file_path=/var/snap/vault/common/vault_audit.log")
		auditOut, err := auditCmd.CombinedOutput()
		if err != nil && !strings.Contains(string(auditOut), "already enabled") {
			log.Fatal("Failed to enable file audit", zap.Error(err), zap.String("output", string(auditOut)))
		}
		fmt.Println("File audit enabled.")

		// 6. Enable KV v2 secrets engine at "secret"
		fmt.Println("\n[5/9] Enabling KV v2 at path=secret...")
		secretsCmd := exec.Command("vault", "secrets", "enable", "-version=2", "-path=secret", "kv")
		secretsOut, err := secretsCmd.CombinedOutput()
		if err != nil && !strings.Contains(string(secretsOut), "mounted successfully") && !strings.Contains(string(secretsOut), "already enabled") {
			log.Fatal("Failed to enable KV v2", zap.Error(err), zap.String("output", string(secretsOut)))
		}
		fmt.Println("KV v2 enabled at path=secret.")

		// 7. Put and get a test secret
		fmt.Println("\n[6/9] Putting and getting a test secret (secret/hello)...")
		putCmd := exec.Command("vault", "kv", "put", "secret/hello", "value=world")
		putOut, err := putCmd.CombinedOutput()
		if err != nil {
			log.Fatal("Failed to put test secret", zap.Error(err), zap.String("output", string(putOut)))
		}

		getCmd := exec.Command("vault", "kv", "get", "secret/hello")
		getOut, err := getCmd.CombinedOutput()
		if err != nil {
			log.Fatal("Failed to get test secret", zap.Error(err), zap.String("output", string(getOut)))
		}
		fmt.Println(string(getOut))

		// 8. Enable AppRole auth, create a role, read the role ID
		fmt.Println("\n[7/9] Enabling AppRole auth method...")
		approleCmd := exec.Command("vault", "auth", "enable", "approle")
		approleOut, err := approleCmd.CombinedOutput()
		if err != nil && !strings.Contains(string(approleOut), "already enabled") {
			log.Fatal("Failed to enable AppRole auth", zap.Error(err), zap.String("output", string(approleOut)))
		}

		fmt.Println("Configuring role my-role...")
		writeRoleCmd := exec.Command("vault", "write", "auth/approle/role/my-role",
			"token_policies=default,my-policy",
			"token_ttl=1h",
			"token_max_ttl=4h",
			"secret_id_ttl=60m",
			"secret_id_num_uses=0")
		writeRoleOut, err := writeRoleCmd.CombinedOutput()
		if err != nil {
			log.Fatal("Failed to write role my-role", zap.Error(err), zap.String("output", string(writeRoleOut)))
		}
		fmt.Println("Role my-role created successfully.")

		roleIDCmd := exec.Command("vault", "read", "auth/approle/role/my-role/role-id")
		roleIDOut, err := roleIDCmd.CombinedOutput()
		if err != nil {
			log.Fatal("Failed to read role ID", zap.Error(err), zap.String("output", string(roleIDOut)))
		}
		fmt.Println("Role ID for my-role:")
		fmt.Println(string(roleIDOut))

		// 9. Enable userpass auth
		fmt.Println("\n[8/9] Enabling userpass auth method...")
		userpassCmd := exec.Command("vault", "auth", "enable", "userpass")
		userpassOut, err := userpassCmd.CombinedOutput()
		if err != nil && !strings.Contains(string(userpassOut), "already enabled") {
			log.Fatal("Failed to enable userpass auth", zap.Error(err), zap.String("output", string(userpassOut)))
		}
		fmt.Println("Userpass auth enabled.")

		// 10. Generate a random password and create an admin user with it
		fmt.Println("\n[9/9] Generating random password and creating admin user...")

		// Generate 16 bytes of random data in Base64
		randomCmd := exec.Command("vault", "write", "sys/tools/random", "bytes=16", "-format=json")
		randomOut, err := randomCmd.Output()
		if err != nil {
			log.Fatal("Failed to generate random password", zap.Error(err), zap.String("output", string(randomOut)))
		}

		// Parse the JSON output to get the random bytes
		var randomData struct {
			Data struct {
				RandomBytes string `json:"random_bytes"`
			} `json:"data"`
		}
		if err := json.Unmarshal(randomOut, &randomData); err != nil {
			log.Fatal("Failed to parse random password output", zap.Error(err))
		}
		randomPassword := randomData.Data.RandomBytes
		fmt.Printf("Generated admin password: %s\n", randomPassword)

		// Create the admin user
		createUserCmd := exec.Command("vault", "write", "auth/userpass/users/admin",
			fmt.Sprintf("password=%s", randomPassword),
			"policies=admin")
		createUserOut, err := createUserCmd.CombinedOutput()
		if err != nil {
			log.Fatal("Failed to create admin user", zap.Error(err), zap.String("output", string(createUserOut)))
		}

		if err := vault.SaveToVault("vault-init", initRes); err != nil {
			log.Warn("Failed to store vault-init data in Vault", zap.Error(err))
		}

		fmt.Println("\nAdmin user created successfully with userpass auth.")
		fmt.Println("\nVault enable steps completed successfully!")
		fmt.Println("\nYou can now log in with the admin user using the generated password.")
		fmt.Println("\nRemember to store the unseal keys and root token securely!")
		fmt.Println("\nPlease now run 'eos secure vault' to secure the Vault service.")
		fmt.Println("\nYou can also run 'eos logs vault' to view the Vault logs.")
	},
}

func init() {
	EnableCmd.AddCommand(EnableVaultCmd)
}
