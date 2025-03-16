package logs

import (
	"log"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

// vaultLogsCmd represents the "logs vault" command.
var vaultLogsCmd = &cobra.Command{
	Use:   "vault",
	Short: "Shows the last 100 Vault log lines then tails the log",
	Long:  "This command displays the most recent 100 lines from /var/log/vault.log and then tails the log file in real time. This ensures that you see some log history even if Vault is quiet.",
	Run: func(cmd *cobra.Command, args []string) {
		// Use the tail command with -n 100 to show the last 100 lines and -f to follow the file.
		tailCmd := exec.Command("tail", "-n", "100", "-f", "/var/log/vault.log")
		tailCmd.Stdout = os.Stdout
		tailCmd.Stderr = os.Stderr

		log.Println("Tailing Vault logs. Press Ctrl+C to exit.")
		if err := tailCmd.Run(); err != nil {
			log.Fatalf("Error executing tail command: %v", err)
		}
	},
}

func init() {
	LogsCmd.AddCommand(vaultLogsCmd)
}
