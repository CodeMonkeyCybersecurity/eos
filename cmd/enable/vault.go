package enable

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/spf13/cobra"
)

// vaultEnableCmd represents the "enable vault" command.
var vaultEnableCmd = &cobra.Command{
	Use:   "vault",
	Short: "Initializes and unseals Vault",
	Long: `This command assumes Vault is installed and configured.
It checks Vault's status and, if Vault is not initialized, initializes it with 5 key shares (threshold 3)
and unseals it using the first three keys.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Check if VAULT_ADDR is set; if not, set it.
		vaultAddr := os.Getenv("VAULT_ADDR")
		if vaultAddr == "" {
			// Fallback: use localhost on port 8179.
			vaultAddr = "http://127.0.0.1:8179"
			os.Setenv("VAULT_ADDR", vaultAddr)
		}
		fmt.Printf("Using VAULT_ADDR = %s\n", vaultAddr)

		// Poll for Vault status.
		var vaultStatus struct {
			Initialized bool `json:"initialized"`
			Sealed      bool `json:"sealed"`
		}
		maxAttempts := 60
		attempt := 0
		for {
			statusCmd := exec.Command("vault", "status", "-format=json")
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
		if !vaultStatus.Initialized {
			fmt.Println("Vault is not initialized. Initializing Vault...")
			initCmd := exec.Command("vault", "operator", "init", "-key-shares=5", "-key-threshold=3", "-format=json")
			initOut, err := initCmd.Output()
			if err != nil {
				log.Fatalf("Failed to initialize Vault: %v", err)
			}
			var initResult struct {
				UnsealKeysB64 []string `json:"unseal_keys_b64"`
				RootToken     string   `json:"root_token"`
			}
			if err := json.Unmarshal(initOut, &initResult); err != nil {
				log.Fatalf("Failed to parse initialization output: %v", err)
			}
			fmt.Println("Vault initialized successfully!")
			for i := 0; i < 3; i++ {
				fmt.Printf("Unsealing Vault with key %d...\n", i+1)
				unsealCmd := exec.Command("vault", "operator", "unseal", initResult.UnsealKeysB64[i])
				unsealCmd.Stdout = os.Stdout
				unsealCmd.Stderr = os.Stderr
				if err := unsealCmd.Run(); err != nil {
					log.Fatalf("Failed to unseal Vault: %v", err)
				}
			}
			fmt.Println("Vault unsealed successfully!")
			fmt.Printf("Root Token (save this securely): %s\n", initResult.RootToken)
		} else if vaultStatus.Sealed {
			// If already initialized but sealed, signal manual intervention.
			fmt.Println("Vault is initialized but sealed. Please unseal manually.")
			return
		} else {
			fmt.Println("Vault is already initialized and unsealed.")
		}

		fmt.Println("Vault is now enabled and running in production mode.")
	},
}

func init() {
	// Assuming you have a parent enable command (EnableCmd) defined in your enable package.
	EnableCmd.AddCommand(vaultEnableCmd)
}
