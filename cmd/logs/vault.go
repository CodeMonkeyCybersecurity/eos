package logs

import (
	"bufio"
	"os/exec"
	"strings"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
	"github.com/spf13/cobra"

	"go.uber.org/zap"
)

// VaultLogsCmd represents the "logs vault" command.
var VaultLogsCmd = &cobra.Command{
	Use:   "vault",
	Short: "Shows the last 100 Vault log lines then tails the log",
	Long:  `This command displays the most recent 100 lines from /var/log/vault.log and then tails the log file in real time, with the footer message at the bottom.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Initialize termui.
		if err := ui.Init(); err != nil {
			log.Fatal("failed to initialize termui", zap.Error(err))
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
		footer.Text = "Tailing Vault logs. Press q or Ctrl+C to exit."
		footer.SetRect(0, 20, 100, 23)
		footer.Border = false

		ui.Render(logPar, footer)

		// Use a single tail command to print the last 100 lines and then follow new lines.
		tailCmd := exec.Command("tail", "-n", "100", "-f", "/var/log/vault.log")
		stdout, err := tailCmd.StdoutPipe()
		if err != nil {
			log.Fatal("failed to get stdout pipe", zap.Error(err))
		}

		if err := tailCmd.Start(); err != nil {
			log.Fatal("failed to start tail command", zap.Error(err))
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
			log.Info("tail command exited with error", zap.Error(err))
		}

		// Optionally wait for the tail command to exit.
		if err := tailCmd.Wait(); err != nil {
			log.Info("tail command exited with error", zap.Error(err))
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
	LogsCmd.AddCommand(VaultLogsCmd)
}
