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

// vaultEnableCmd represents the "enable vault" command.
var vaultEnableCmd = &cobra.Command{
	Use:   "vault",
	Short: "Initializes and unseals Vault",
	Long: `This command assumes Vault is installed and configured.
It sets VAULT_ADDR dynamically based on the host's name, then checks Vault's status.
If Vault is not initialized, it initializes it (with 5 key shares and a threshold of 3)
and unseals Vault using the first three keys.
If Vault is already initialized, it skips initialization.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Dynamically set VAULT_ADDR.
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
		if !vaultStatus.Initialized {
			fmt.Println("Vault is not initialized. Initializing Vault...")
			initCmd := exec.Command("vault", "operator", "init",
				"-address="+vaultAddr,
				"-key-shares=5",
				"-key-threshold=3",
				"-format=json")
			// Use CombinedOutput to capture both stdout and stderr.
			initOut, err := initCmd.CombinedOutput()
			if err != nil {
				if strings.Contains(string(initOut), "Vault is already initialized") {
					fmt.Println("Vault is already initialized. Skipping initialization.")
					vaultStatus.Initialized = true
				} else {
					log.Fatalf("Failed to initialize Vault: %v\nOutput: %s", err, string(initOut))
				}
			} else {
				var initResult struct {
					UnsealKeysB64 []string `json:"unseal_keys_b64"`
					RootToken     string   `json:"root_token"`
				}
				if err := json.Unmarshal(initOut, &initResult); err != nil {
					log.Fatalf("Failed to parse initialization output: %v", err)
				}
				fmt.Println("Vault initialized successfully!")
				// Unseal Vault using the first 3 unseal keys.
				for i := 0; i < 3; i++ {
					fmt.Printf("Unsealing Vault with key %d...\n", i+1)
					unsealCmd := exec.Command("vault", "operator", "unseal",
						"-address="+vaultAddr,
						initResult.UnsealKeysB64[i])
					unsealCmd.Stdout = os.Stdout
					unsealCmd.Stderr = os.Stderr
					if err := unsealCmd.Run(); err != nil {
						log.Fatalf("Failed to unseal Vault: %v", err)
					}
				}
				fmt.Println("Vault unsealed successfully!")
				fmt.Printf("Root Token (save this securely!): %s\n", initResult.RootToken)
			}
		} else if vaultStatus.Sealed {
			fmt.Println("Vault is initialized but sealed. Manual intervention required to unseal.")
			return
		} else {
			fmt.Println("Vault is already initialized and unsealed.")
		}

		fmt.Println("Vault is now enabled and running in production mode.")
	},
}

func init() {
	EnableCmd.AddCommand(vaultEnableCmd)
}
