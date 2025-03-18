package install

import (
	"fmt"
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
After starting, Vault is given a fixed wait period (5 seconds) before checking its status.
If Vault is not initialized, it will be initialized (with 5 key shares and a threshold of 3)
and then unsealed using the first three keys.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Set VAULT_ADDR as early as possible.
		hostname := utils.GetInternalHostname()
		vaultAddr := fmt.Sprintf("http://%s:8179", hostname)
		os.Setenv("VAULT_ADDR", vaultAddr)
		fmt.Printf("VAULT_ADDR is set to %s\n", vaultAddr)

		// Kill any existing Vault process.
		fmt.Println("Killing any existing Vault server process...")
		killCmd := exec.Command("pkill", "-f", "vault server")
		killCmd.Run() // Ignore error if no process is found.
		time.Sleep(3 * time.Second) // Allow time for cleanup.

		// Install Vault via snap.
		fmt.Println("Installing HashiCorp Vault via snap...")
		installCmd := exec.Command("snap", "install", "vault", "--classic")
		installCmd.Stdout = os.Stdout
		installCmd.Stderr = os.Stderr
		if err := installCmd.Run(); err != nil {
			log.Fatalf("Failed to install Vault: %v", err)
		}

		// Verify Vault installation.
		if _, err := exec.LookPath("vault"); err != nil {
			log.Fatal("Vault command not found after installation.")
		}

		// Create Vault configuration file.
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
		if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
			log.Fatalf("Failed to write config file: %v", err)
		}
		fmt.Printf("Vault configuration written to %s\n", configFile)

		// Start Vault in production mode.
		fmt.Println("Starting Vault in production mode...")
		logFilePath := "/var/log/vault.log"
		logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}
		vaultServerCmd := exec.Command("vault", "server", "-config="+configFile)
		vaultServerCmd.Stdout = logFile
		vaultServerCmd.Stderr = logFile
		if err := vaultServerCmd.Start(); err != nil {
			log.Fatalf("Failed to start Vault server: %v", err)
		}
		fmt.Printf("Vault process started with PID %d\n", vaultServerCmd.Process.Pid)

		// Wait a fixed 5 seconds for Vault to stabilize.
		fmt.Println("Waiting 5 seconds for Vault to stabilize...")
		time.Sleep(5 * time.Second)
	},
}
