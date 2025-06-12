package read

import (
	"errors"
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var InspectLogsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Inspect Eos logs (requires root or eos privileges)",
	Long: `Displays the last 100 lines of recent Eos logs.
Tries known log file locations first. If none found, falls back to journalctl.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)

		if !eos_unix.IsPrivilegedUser(rc.Ctx) {
			return errors.New("you must be root or the 'eos' user to view logs")
		}

		log.Info("Searching for log files", zap.String("action", "inspect-logs"))

		found := false
		active := logger.ResolveLogPath(rc)

		for _, candidate := range logger.PlatformLogPaths() {
			path := os.ExpandEnv(candidate)
			if content, err := logger.TryReadLogFile(rc, path); err == nil {
				prefix := "📄"
				if path == active {
					prefix = "⭐"
				}
				fmt.Printf("\n%s %s\n", prefix, path)

				logger.PrintLastNLines(content, 100) // <--- Only last 100 lines printed
				found = true
			}
		}

		if !found {
			log.Warn("No log files found; attempting journalctl fallback")
			fmt.Println("\n⚠️")
			fmt.Println("No log files found. Trying journalctl fallback...")
			fmt.Println("\n⚠️")
			out, err := logger.TryJournalctl(rc)
			if err != nil {
				return fmt.Errorf("journalctl fallback failed: %w", err)
			}
			logger.PrintLastNLines(out, 100)
		}

		log.Info("Log search complete")
		return nil
	}),
}

func init() {
	ReadCmd.AddCommand(InspectLogsCmd)
}
