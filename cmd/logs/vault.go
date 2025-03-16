package logs

import (
	"log"
	"os/exec"
	"strings"
	"time"

	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
)

func main() {
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

	// Start tailing logs using "tail -f".
	cmd := exec.Command("tail", "-f", "/var/log/vault.log")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatalf("failed to get stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		log.Fatalf("failed to start tail command: %v", err)
	}

	// Read the output and update the log widget.
	go func() {
		buf := make([]byte, 1024)
		var allLogs []string
		for {
			n, err := stdout.Read(buf)
			if err != nil {
				break
			}
			text := string(buf[:n])
			lines := strings.Split(text, "\n")
			allLogs = append(allLogs, lines...)
			// Limit to the last 100 lines.
			if len(allLogs) > 100 {
				allLogs = allLogs[len(allLogs)-100:]
			}
			logPar.Text = strings.Join(allLogs, "\n")
			ui.Render(logPar, footer)
		}
	}()

	uiEvents := ui.PollEvents()
	for {
		e := <-uiEvents
		switch e.ID {
		case "q", "<C-c>":
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}
