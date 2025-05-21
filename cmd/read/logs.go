package read

import (
	"errors"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/debian"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var InspectLogsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Inspect EOS logs (requires root or eos privileges)",
	Long: `Displays the last 100 lines of recent EOS logs.
Tries known log file locations first. If none found, falls back to journalctl.`,
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("inspect-logs")

		if !debian.IsPrivilegedUser() {
			return errors.New("you must be root or the 'eos' user to view logs")
		}

		log.Info("Searching for log files", zap.String("action", "inspect-logs"))

		found := false
		active := logger.ResolveLogPath()

		for _, candidate := range logger.PlatformLogPaths() {
			path := os.ExpandEnv(candidate)
			if content, err := logger.TryReadLogFile(path); err == nil {
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
			out, err := logger.TryJournalctl()
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
