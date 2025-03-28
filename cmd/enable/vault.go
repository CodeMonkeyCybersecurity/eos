package enable

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
	"github.com/spf13/cobra"
)

// initResult is the JSON structure returned by "vault operator init -format=json".
type initResult struct {
	UnsealKeysB64 []string `json:"unseal_keys_b64"`
	RootToken     string   `json:"root_token"`
}

var vaultEnableCmd = &cobra.Command{
	Use:   "vault",
	Short: "Enables Vault with sane and secure defaults",
	Long: `This command assumes "github.com/CodeMonkeyCybersecurity/eos install vault" has been run.
It initializes and unseals Vault, sets up auditing, KV v2, 
AppRole, userpass, and creates an admin user with a random password.`,
	Run: func(cmd *cobra.Command, args []string) {

		// 1. Dynamically set VAULT_ADDR based on hostname.
		hostname := utils.GetInternalHostname()
		vaultAddr := fmt.Sprintf("http://%s:8179", hostname)
		os.Setenv("VAULT_ADDR", vaultAddr)
		fmt.Printf("VAULT_ADDR is set to %s\n", vaultAddr)

		// 2. Initialize Vault (if not already initialized).
		fmt.Println("\n[1/9] Initializing Vault (operator init)...")
		initCmd := exec.Command("vault", "operator", "init",
			"-key-shares=5", "-key-threshold=3", "-format=json")
		initOut, err := initCmd.CombinedOutput()
		var initRes initResult
		if err != nil {
			if strings.Contains(string(initOut), "Vault is already initialized") {
				fmt.Println("Vault is already initialized. Skipping init.")
			} else {
				log.Fatalf("Failed to init Vault: %v\nOutput: %s", err, string(initOut))
			}
		} else {
			// Parse the JSON output.
			if err := json.Unmarshal(initOut, &initRes); err != nil {
				log.Fatalf("Failed to parse initialization output: %v", err)
			}
			fmt.Printf("Vault initialized! Received %d unseal keys.\n", len(initRes.UnsealKeysB64))
			fmt.Println("Storing these keys for demonstration. In production, store them securely!")
			// Write the JSON output to a secure file.
			if err := os.WriteFile("vault_init.json", initOut, 0600); err != nil {
				log.Fatalf("Failed to write initialization output to file: %v", err)
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
					log.Fatalf("Failed to unseal Vault (key %d): %v\nOutput: %s", i+1, err, string(unsealOut))
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
				log.Fatalf("Failed to log in with root token: %v\nOutput: %s", err, string(loginOut))
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
			log.Fatalf("Failed to enable file audit: %v\nOutput: %s", err, string(auditOut))
		}
		fmt.Println("File audit enabled.")

		// 6. Enable KV v2 secrets engine at "secret"
		fmt.Println("\n[5/9] Enabling KV v2 at path=secret...")
		secretsCmd := exec.Command("vault", "secrets", "enable", "-version=2", "-path=secret", "kv")
		secretsOut, err := secretsCmd.CombinedOutput()
		if err != nil && !strings.Contains(string(secretsOut), "mounted successfully") && !strings.Contains(string(secretsOut), "already enabled") {
			log.Fatalf("Failed to enable KV v2: %v\nOutput: %s", err, string(secretsOut))
		}
		fmt.Println("KV v2 enabled at path=secret.")

		// 7. Put and get a test secret
		fmt.Println("\n[6/9] Putting and getting a test secret (secret/hello)...")
		putCmd := exec.Command("vault", "kv", "put", "secret/hello", "value=world")
		putOut, err := putCmd.CombinedOutput()
		if err != nil {
			log.Fatalf("Failed to put test secret: %v\nOutput: %s", err, string(putOut))
		}

		getCmd := exec.Command("vault", "kv", "get", "secret/hello")
		getOut, err := getCmd.CombinedOutput()
		if err != nil {
			log.Fatalf("Failed to get test secret: %v\nOutput: %s", err, string(getOut))
		}
		fmt.Println(string(getOut))

		// 8. Enable AppRole auth, create a role, read the role ID
		fmt.Println("\n[7/9] Enabling AppRole auth method...")
		approleCmd := exec.Command("vault", "auth", "enable", "approle")
		approleOut, err := approleCmd.CombinedOutput()
		if err != nil && !strings.Contains(string(approleOut), "already enabled") {
			log.Fatalf("Failed to enable AppRole auth: %v\nOutput: %s", err, string(approleOut))
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
			log.Fatalf("Failed to create my-role: %v\nOutput: %s", err, string(writeRoleOut))
		}

		roleIDCmd := exec.Command("vault", "read", "auth/approle/role/my-role/role-id")
		roleIDOut, err := roleIDCmd.CombinedOutput()
		if err != nil {
			log.Fatalf("Failed to read my-role's role-id: %v\nOutput: %s", err, string(roleIDOut))
		}
		fmt.Println(string(roleIDOut))

		// 9. Enable userpass auth
		fmt.Println("\n[8/9] Enabling userpass auth method...")
		userpassCmd := exec.Command("vault", "auth", "enable", "userpass")
		userpassOut, err := userpassCmd.CombinedOutput()
		if err != nil && !strings.Contains(string(userpassOut), "already enabled") {
			log.Fatalf("Failed to enable userpass auth: %v\nOutput: %s", err, string(userpassOut))
		}

		// 10. Generate a random password and create an admin user with it
		fmt.Println("\n[9/9] Generating random password and creating admin user...")

		// Generate 16 bytes of random data in Base64
		randomCmd := exec.Command("vault", "write", "sys/tools/random", "bytes=16", "-format=json")
		randomOut, err := randomCmd.Output()
		if err != nil {
			log.Fatalf("Failed to generate random password: %v", err)
		}
		var randomData struct {
			Data struct {
				RandomBytes string `json:"random_bytes"`
			} `json:"data"`
		}
		if err := json.Unmarshal(randomOut, &randomData); err != nil {
			log.Fatalf("Failed to parse random output: %v", err)
		}
		randomPassword := randomData.Data.RandomBytes
		fmt.Printf("Generated admin password: %s\n", randomPassword)

		// Create the admin user
		createUserCmd := exec.Command("vault", "write", "auth/userpass/users/admin",
			fmt.Sprintf("password=%s", randomPassword),
			"policies=admin")
		createUserOut, err := createUserCmd.CombinedOutput()
		if err != nil {
			log.Fatalf("Failed to create admin user: %v\nOutput: %s", err, string(createUserOut))
		}
		fmt.Println("Admin user created successfully with userpass auth.")

		fmt.Println("\nVault enable steps completed successfully!")
	},
}

func init() {
	EnableCmd.AddCommand(vaultEnableCmd)
}
