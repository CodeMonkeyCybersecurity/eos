package install

import (
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
		logFile, err := os.OpenFile("/var/log/vault.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
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

		// Allow some time for the Vault server to initialize.
		time.Sleep(5 * time.Second)

		// Verify that Vault is running.
		checkCmd := exec.Command("pgrep", "-f", "vault server")
		if err := checkCmd.Run(); err != nil {
			log.Fatal("Vault server does not appear to be running. Please check /var/log/vault.log for details.")
		}

		fmt.Println("Vault is now running in production mode...")
		fmt.Printf("Access it at %s.\n", vaultAddr)
		fmt.Println("To view Vault logs, check /var/log/vault.log.")
	},
}

func init() {
	InstallCmd.AddCommand(vaultCmd)
}
