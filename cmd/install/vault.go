package install
 
 import (
 	"context"
 	"encoding/json"
 	"fmt"
 	"io/ioutil"
 	"log"
 	"os"
 	"os/exec"
 	"time"
 
 	"eos/pkg/utils"
 	"github.com/spf13/cobra"
 )
 
 // vaultCmd represents the vault command under the "install" group.
 var vaultCmd = &cobra.Command{
 	Use:   "vault",
 	Short: "Installs and initializes HashiCorp Vault in production mode via snap",
 	Long: `This command installs HashiCorp Vault using snap and starts Vault in production mode.
 A minimal configuration file is generated and used to run Vault with persistent file storage.
 After starting, Vault is automatically initialized and unsealed if not already done.
 This is a quick prod-mode setup, not intended for production use without further hardening.`,
 	Run: func(cmd *cobra.Command, args []string) {
 		// Check for root privileges.
 		if os.Geteuid() != 0 {
 			log.Fatal("This command must be run with sudo or as root.")
 		}
 
 		fmt.Println("Installing HashiCorp Vault via snap...")
 		installCmd := exec.Command("snap", "install", "vault", "--classic")
 		installCmd.Stdout = os.Stdout
 		installCmd.Stderr = os.Stderr
 		if err := installCmd.Run(); err != nil {
 			log.Fatalf("Failed to install Vault: %v", err)
 		}
 
 		// Verify installation by checking if vault is in PATH.
 		if _, err := exec.LookPath("vault"); err != nil {
 			log.Fatal("Vault command not found after installation.")
 		}
 
 		// Get the internal hostname.
 		hostname := utils.GetInternalHostname()
 		// Construct the VAULT_ADDR using the hostname.
 		vaultAddr := fmt.Sprintf("http://%s:8179", hostname)
 		os.Setenv("VAULT_ADDR", vaultAddr)
 		fmt.Printf("VAULT_ADDR is set to %s\n", vaultAddr)
 
 		// Create a minimal production config file for Vault.
 		// Use a directory allowed by the snap confinement.
 		configDir := "/var/snap/vault/common"
 		configFile := configDir + "/config.hcl"
 		if err := os.MkdirAll(configDir, 0755); err != nil {
 			log.Fatalf("Failed to create config directory %s: %v", configDir, err)
 		}
 
 		configContent := fmt.Sprintf(`
 listener "tcp" {
   address     = "0.0.0.0:8179"
   tls_disable = 1
 }
 
 storage "file" {
   path = "/var/snap/vault/common/data"
 }
 
 disable_mlock = true
 api_addr = "%s"
 ui = true
 `, vaultAddr)
 		if err := ioutil.WriteFile(configFile, []byte(configContent), 0644); err != nil {
 			log.Fatalf("Failed to write config file: %v", err)
 		}
 		fmt.Printf("Vault configuration written to %s\n", configFile)
 
 		fmt.Println("Starting Vault in production mode...")
 		// Open the log file for Vault output.
 		logFilePath := "/var/log/vault.log"
 		logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
 		if err != nil {
 			log.Fatalf("Failed to open log file: %v", err)
 		}
 
 		// Start Vault in production mode using the config file.
 		vaultServerCmd := exec.Command("vault", "server", "-config="+configFile)
 		vaultServerCmd.Stdout = logFile
 		vaultServerCmd.Stderr = logFile
 
 		if err := vaultServerCmd.Start(); err != nil {
 			log.Fatalf("Failed to start Vault server: %v", err)
 		}
 		fmt.Printf("Vault process started with PID %d\n", vaultServerCmd.Process.Pid)
 
 		// Monitor Vault logs until we detect that Vault is up.
 		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
 		defer cancel()
 		fmt.Println("Monitoring Vault logs for startup message...")
 		if err := utils.MonitorVaultLogs(ctx, logFilePath, "Vault server started!"); err != nil {
 			log.Fatalf("Vault did not start properly: %v", err)
 		}
 
 		// Check Vault status (using JSON output).
 		statusCmd := exec.Command("vault", "status", "-format=json")
 		statusOut, err := statusCmd.Output()
 		if err != nil {
 			log.Fatalf("Failed to get Vault status: %v", err)
 		}
 
 		// Define a struct to parse the status.
 		var vaultStatus struct {
 			Initialized bool `json:"initialized"`
 			Sealed      bool `json:"sealed"`
 		}
 		if err := json.Unmarshal(statusOut, &vaultStatus); err != nil {
 			log.Fatalf("Failed to parse Vault status: %v", err)
 		}
 
 		// If Vault is not initialized, initialize and unseal it.
 		if !vaultStatus.Initialized {
 			fmt.Println("Vault is not initialized. Initializing Vault...")
 			initCmd := exec.Command("vault", "operator", "init", "-key-shares=5", "-key-threshold=3", "-format=json")
 			initOut, err := initCmd.Output()
 			if err != nil {
 				log.Fatalf("Failed to initialize Vault: %v", err)
 			}
 
 			// Define a struct for the initialization output.
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
 				unsealCmd := exec.Command("vault", "operator", "unseal", initResult.UnsealKeysB64[i])
 				unsealCmd.Stdout = os.Stdout
 				unsealCmd.Stderr = os.Stderr
 				if err := unsealCmd.Run(); err != nil {
 					log.Fatalf("Failed to unseal Vault: %v", err)
 				}
 			}
 			fmt.Println("Vault unsealed successfully!")
 			fmt.Printf("Root Token (save this securely!): %s\n", initResult.RootToken)
 		} else if vaultStatus.Sealed {
 			// If already initialized but still sealed, unseal.
 			fmt.Println("Vault is initialized but sealed. Unsealing Vault...")
 			// For simplicity, assume the operator will supply keys manually or
 			// extend the script to unseal with known keys.
 			// Here, you could repeat similar unseal logic if you stored keys.
 			log.Fatal("Vault is sealed. Manual intervention required to unseal.")
 		} else {
 			fmt.Println("Vault is already initialized and unsealed.")
 		}
 
 		fmt.Println("Vault is now running in production mode...")
 		fmt.Printf("Access it at %s.\n", vaultAddr)
 		fmt.Println("To view Vault logs, check", logFilePath)
 	},
 }
 
 func init() {
 	InstallCmd.AddCommand(vaultCmd)
 }
