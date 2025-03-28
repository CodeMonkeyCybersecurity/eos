package refresh

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/spf13/cobra"
)

// vaultRefreshCmd represents the "refresh vault" command.
var vaultRefreshCmd = &cobra.Command{
	Use:   "vault",
	Short: "Refreshes (restarts) the Vault service",
	Long:  `Stops the running Vault server and restarts it using the configured settings.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Check for root privileges.
		if os.Geteuid() != 0 {
			log.Fatal("This command must be run with sudo or as root.")
		}

		fmt.Println("Refreshing Vault...")

		// Kill any running Vault process.
		killCmd := exec.Command("pkill", "-f", "vault server")
		killCmd.Stdout = os.Stdout
		killCmd.Stderr = os.Stderr
		if err := killCmd.Run(); err != nil {
			log.Printf("Warning: unable to kill Vault process (it might not be running): %v", err)
		} else {
			fmt.Println("Stopped Vault process.")
		}

		// Wait a bit for processes to exit.
		time.Sleep(3 * time.Second)

		// Start Vault using the production config file.
		configFile := "/var/snap/vault/common/config.hcl"
		logFilePath := "/var/log/vault.log"

		// Open (or create) the log file.
		logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}
		defer logFile.Close()

		// Start Vault.
		vaultCmd := exec.Command("vault", "server", "-config="+configFile)
		vaultCmd.Stdout = logFile
		vaultCmd.Stderr = logFile

		if err := vaultCmd.Start(); err != nil {
			log.Fatalf("Failed to start Vault: %v", err)
		}

		fmt.Printf("Vault process restarted with PID %d\n", vaultCmd.Process.Pid)
		fmt.Println("Vault refresh complete. Check logs at", logFilePath)
	},
}

func init() {
	// Assuming you have a parent "refresh" command.
	RefreshCmd.AddCommand(vaultRefreshCmd)
}
