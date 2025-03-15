package install

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/spf13/cobra"
)

// vaultCmd represents the vault command under the "install" group.
var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Installs and initializes HashiCorp Vault via snap",
	Long: `This command installs HashiCorp Vault using snap and starts Vault in development mode.
In dev mode Vault auto-initializes and auto-unseals. For production, follow Vault's guidelines
for secure initialization, unsealing, and configuration.`,
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

		// Set VAULT_ADDR environment variable.
		vaultAddr := "http://0.0.0.0:8179"
		os.Setenv("VAULT_ADDR", vaultAddr)
		fmt.Printf("VAULT_ADDR is set to %s\n", vaultAddr)

		fmt.Println("Starting Vault...")
		// Open the log file for Vault output.
		logFile, err := os.OpenFile("/var/log/vault.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}

		// Start Vault in dev mode in the background.
		vaultServerCmd := exec.Command("vault", "server", "listen-address=0.0.0.0:8179")
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
			log.Fatal("Vault server does not appear to be running. Please check /var/log/vault-dev.log for details.")
		}

		fmt.Println("Vault is now running...")
		fmt.Printf("Access it at %s.\n", vaultAddr)
		fmt.Println("To view Vault logs, check /var/log/vault.log.")
	},
}

func init() {
	// Assuming you have an "install" parent command in this package.
	InstallCmd.AddCommand(vaultCmd)
}
