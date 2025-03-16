package logs

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/spf13/cobra"
)

// vaultLogsCmd represents the "logs vault" command.
var vaultLogsCmd = &cobra.Command{
	Use:   "vault",
	Short: "Tails Vault logs in real time",
	Long:  "This command tails the Vault log file (/var/log/vault.log) and prints new log lines to the terminal in real time.",
	Run: func(cmd *cobra.Command, args []string) {
		logFilePath := "/var/log/vault.log"

		// Open the log file.
		file, err := os.Open(logFilePath)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}
		defer file.Close()

		// Seek to the end of the file so we only see new log lines.
		_, err = file.Seek(0, os.SEEK_END)
		if err != nil {
			log.Fatalf("Failed to seek to the end of log file: %v", err)
		}

		fmt.Println("Tailing Vault logs. Press Ctrl+C to exit.")
		scanner := bufio.NewScanner(file)
		for {
			if scanner.Scan() {
				line := scanner.Text()
				fmt.Println(line)
			} else {
				// No new line available; wait briefly and try again.
				time.Sleep(1 * time.Second)
			}
		}
	},
}

func init() {
	// Register the vaultLogsCmd with the parent LogsCmd.
	// Ensure that LogsCmd is defined in your logs package.
	LogsCmd.AddCommand(vaultLogsCmd)
}
