package logs

import (
	"bufio"
	"log"
	"os/exec"
	"strings"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
	"github.com/spf13/cobra"
)

// vaultLogsCmd represents the "logs vault" command.
var vaultLogsCmd = &cobra.Command{
	Use:   "vault",
	Short: "Shows the last 100 Vault log lines then tails the log",
	Long:  "This command displays the most recent 100 lines from /var/log/vault.log and then tails the log file in real time, with the footer message at the bottom.",
	Run: func(cmd *cobra.Command, args []string) {
		// Initialize termui.
		if err := ui.Init(); err != nil {
			log.Fatalf("failed to initialize termui: %v", err)
		}
		defer ui.Close()

		// Create a Paragraph widget for logs.
		logPar := widgets.NewParagraph()
		logPar.Title = "Vault Logs"
		logPar.Text = "Loading logs..."
		logPar.SetRect(0, 0, 100, 20)
		logPar.WrapText = false

		// Create a Paragraph widget for the footer.
		footer := widgets.NewParagraph()
		footer.Text = "Tailing Vault logs. Press Ctrl+C to exit."
		footer.SetRect(0, 20, 100, 23)
		footer.Border = false

		ui.Render(logPar, footer)

		// Use a single tail command to print the last 100 lines and then follow new lines.
		tailCmd := exec.Command("tail", "-n", "100", "-f", "/var/log/vault.log")
		stdout, err := tailCmd.StdoutPipe()
		if err != nil {
			log.Fatalf("failed to get stdout pipe: %v", err)
		}

		if err := tailCmd.Start(); err != nil {
			log.Fatalf("failed to start tail command: %v", err)
		}

		// Read the output continuously.
		scanner := bufio.NewScanner(stdout)
		var allLogs []string
		for scanner.Scan() {
			line := scanner.Text()
			allLogs = append(allLogs, line)
			// Limit to the last 100 lines.
			if len(allLogs) > 100 {
				allLogs = allLogs[len(allLogs)-100:]
			}
			logPar.Text = strings.Join(allLogs, "\n")
			ui.Render(logPar, footer)
		}
		if err := scanner.Err(); err != nil {
			log.Printf("scanner error: %v", err)
		}

		// Optionally wait for the tail command to exit.
		if err := tailCmd.Wait(); err != nil {
			log.Printf("tail command exited with error: %v", err)
		}

		// Poll for UI events so the UI doesn't immediately exit.
		uiEvents := ui.PollEvents()
		for {
			e := <-uiEvents
			switch e.ID {
			case "q", "<C-c>":
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	},
}

func init() {
	LogsCmd.AddCommand(vaultLogsCmd)
}
