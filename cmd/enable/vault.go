package enable

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"eos/pkg/utils"
	"github.com/spf13/cobra"
)

// initResult represents the JSON structure returned by "vault operator init".
type initResult struct {
	UnsealKeysB64 []string `json:"unseal_keys_b64"`
	RootToken     string   `json:"root_token"`
}

var vaultEnableCmd = &cobra.Command{
	Use:   "vault",
	Short: "Enables Vault with secure defaults",
	Long: `This command assumes "eos install vault" has been run.
It sets VAULT_ADDR dynamically, checks Vault status, and if not initialized,
initializes Vault with 5 key shares and a threshold of 3, unseals it using the first three keys,
logs in with the root token, enables file audit and the KV v2 secrets engine,
writes a test secret, and sets up AppRole and userpass authentication.
For demonstration, unseal keys and the root token are printed to the console.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Set VAULT_ADDR dynamically.
		hostname := utils.GetInternalHostname()
		vaultAddr := fmt.Sprintf("http://%s:8179", hostname)
		os.Setenv("VAULT_ADDR", vaultAddr)
		fmt.Printf("VAULT_ADDR is set to %s\n", vaultAddr)

		// Poll for Vault status.
		var vaultStatus struct {
			Initialized bool `json:"initialized"`
			Sealed      bool `json:"sealed"`
		}
		maxAttempts := 60
		attempt := 0
		for {
			statusCmd := exec.Command("vault", "status", "-address="+vaultAddr, "-format=json")
			statusOut, err := statusCmd.Output()
			if err == nil {
				if err := json.Unmarshal(statusOut, &vaultStatus); err == nil {
					break
				}
			}
			attempt++
			if attempt >= maxAttempts {
				log.Fatalf("Failed to get valid Vault status after %d attempts.", attempt)
			}
			time.Sleep(1 * time.Second)
		}

		// If Vault is not initialized, initialize it.
		var initRes initResult
		if !vaultStatus.Initialized {
			fmt.Println("\nVault is not initialized. Initializing Vault...")
			initCmd := exec.Command("vault", "operator", "init",
				"-address="+vaultAddr,
				"-key-shares=5",
				"-key-threshold=3",
				"-format=json")
			initOut, err := initCmd.CombinedOutput()
			if err != nil {
				// If error indicates already initialized, then continue.
				if strings.Contains(string(initOut), "Vault is already initialized") {
					fmt.Println("Vault is already initialized. Skipping initialization.")
					vaultStatus.Initialized = true
				} else {
					log.Fatalf("Failed to initialize Vault: %v\nOutput: %s", err, string(initOut))
				}
			} else {
				if err := json.Unmarshal(initOut, &initRes); err != nil {
					log.Fatalf("Failed to parse initialization output: %v", err)
				}
				fmt.Println("\nVault initialized successfully!")
				// For demonstration: output the unseal keys and root token.
				fmt.Println("Unseal Keys:")
				for i, key := range initRes.UnsealKeysB64 {
					fmt.Printf("  Key %d: %s\n", i+1, key)
				}
				fmt.Printf("Root Token: %s\n", initRes.RootToken)
			}

			// Unseal Vault using the first three unseal keys.
			if len(initRes.UnsealKeysB64) >= 3 {
				fmt.Println("\nUnsealing Vault...")
				for i := 0; i < 3; i++ {
					fmt.Printf("Unsealing with key %d...\n", i+1)
					unsealCmd := exec.Command("vault", "operator", "unseal",
						"-address="+vaultAddr,
						initRes.UnsealKeysB64[i])
					unsealOut, err := unsealCmd.CombinedOutput()
					if err != nil {
						log.Fatalf("Failed to unseal Vault (key %d): %v\nOutput: %s", i+1, err, string(unsealOut))
					}
				}
				fmt.Println("Vault unsealed successfully!")
			} else {
				fmt.Println("Skipping unseal because unseal keys were not obtained (Vault may already be unsealed).")
			}
		} else if vaultStatus.Sealed {
			fmt.Println("Vault is initialized but sealed. Please unseal manually and then run this command again.")
			return
		} else {
			fmt.Println("Vault is already initialized and unsealed.")
		}

		// Log in with the root token if available from init output.
		if initRes.RootToken != "" {
			fmt.Println("\nLogging in with root token...")
			loginCmd := exec.Command("vault", "login", "-address="+vaultAddr, initRes.RootToken)
			loginOut, err := loginCmd.CombinedOutput()
			if err != nil {
				log.Fatalf("Failed to log in with root token: %v\nOutput: %s", err, string(loginOut))
			}
			fmt.Println("Logged in as root.")
		}

		// Enable file audit device.
		fmt.Println("\nEnabling file audit device...")
		auditCmd := exec.Command("vault", "audit", "enable", "file", "file_path=/var/snap/vault/common/vault_audit.log")
		auditOut, err := auditCmd.CombinedOutput()
		if err != nil && !strings.Contains(string(auditOut), "already enabled") {
			log.Fatalf("Failed to enable file audit: %v\nOutput: %s", err, string(auditOut))
		}
		fmt.Println("File audit enabled.")

		// Enable KV v2 secrets engine.
		fmt.Println("\nEnabling KV v2 secrets engine at path 'secret'...")
		// Disable existing mount (if any)
		disableCmd := exec.Command("vault", "secrets", "disable", "secret")
		disableCmd.Run() // Ignore errors.
		secretsCmd := exec.Command("vault", "secrets", "enable", "-version=2", "-path=secret", "kv")
		secretsOut, err := secretsCmd.CombinedOutput()
		if err != nil && !strings.Contains(string(secretsOut), "mounted successfully") && !strings.Contains(string(secretsOut), "already enabled") {
			log.Fatalf("Failed to enable KV v2: %v\nOutput: %s", err, string(secretsOut))
		}
		fmt.Println("KV v2 secrets engine enabled at path 'secret'.")

		// Put and get a test secret.
		fmt.Println("\nStoring a test secret at secret/hello...")
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
		fmt.Println("Test secret retrieved:")
		fmt.Println(string(getOut))

		// Enable AppRole auth method and configure a role.
		fmt.Println("\nEnabling AppRole auth method...")
		approleCmd := exec.Command("vault", "auth", "enable", "approle")
		approleOut, err := approleCmd.CombinedOutput()
		if err != nil && !strings.Contains(string(approleOut), "already enabled") {
			log.Fatalf("Failed to enable AppRole auth: %v\nOutput: %s", err, string(approleOut))
		}
		fmt.Println("AppRole auth enabled.")

		fmt.Println("Configuring AppRole role 'my-role'...")
		writeRoleCmd := exec.Command("vault", "write", "auth/approle/role/my-role",
			"token_policies=default,my-policy",
			"token_ttl=1h",
			"token_max_ttl=4h",
			"secret_id_ttl=60m",
			"secret_id_num_uses=0")
		writeRoleOut, err := writeRoleCmd.CombinedOutput()
		if err != nil {
			log.Fatalf("Failed to create AppRole role 'my-role': %v\nOutput: %s", err, string(writeRoleOut))
		}
		fmt.Println("AppRole role 'my-role' configured.")

		roleIDCmd := exec.Command("vault", "read", "auth/approle/role/my-role/role-id")
		roleIDOut, err := roleIDCmd.CombinedOutput()
		if err != nil {
			log.Fatalf("Failed to read role-id for 'my-role': %v\nOutput: %s", err, string(roleIDOut))
		}
		fmt.Println("AppRole role ID:")
		fmt.Println(string(roleIDOut))

		// Enable userpass auth and create an admin user with a random password.
		fmt.Println("\nEnabling userpass auth method...")
		userpassCmd := exec.Command("vault", "auth", "enable", "userpass")
		userpassOut, err := userpassCmd.CombinedOutput()
		if err != nil && !strings.Contains(string(userpassOut), "already enabled") {
			log.Fatalf("Failed to enable userpass auth: %v\nOutput: %s", err, string(userpassOut))
		}
		fmt.Println("Userpass auth enabled.")

		fmt.Println("Generating a random password for the admin user...")
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

		fmt.Println("Creating admin user with userpass auth...")
		createUserCmd := exec.Command("vault", "write", "auth/userpass/users/admin",
			fmt.Sprintf("password=%s", randomPassword),
			"policies=admin")
		createUserOut, err := createUserCmd.CombinedOutput()
		if err != nil {
			log.Fatalf("Failed to create admin user: %v\nOutput: %s", err, string(createUserOut))
		}
		fmt.Println("Admin user created successfully with userpass auth.")

		fmt.Println("\nVault enable steps completed successfully!")
		fmt.Printf("Access Vault at: %s\n", vaultAddr)
		fmt.Println("Review audit logs at: /var/snap/vault/common/vault_audit.log")
	},
}

func init() {
	EnableCmd.AddCommand(vaultEnableCmd)
}
