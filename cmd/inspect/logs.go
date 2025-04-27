package inspect

import (
	"errors"
	"fmt"
	"os"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var InspectLogsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Inspect EOS logs (requires root or eos privileges)",
	Long: `Displays recent EOS logs.
Tries known log file locations first. If none found, falls back to journalctl.`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("inspect-logs")

		if !utils.IsPrivilegedUser() {
			return errors.New("you must be root or the 'eos' user to view logs")
		}

		log.Info("Searching for log files", zap.String("action", "inspect-logs"))

		found := false
		active := logger.ResolveLogPath()

		for _, candidate := range logger.PlatformLogPaths() {
			path := os.ExpandEnv(candidate)
			if content, err := logger.TryReadLogFile(path, log); err == nil {
				prefix := "📄"
				if path == active {
					prefix = "⭐"
				}
				fmt.Printf("\n%s %s\n", prefix, path)
				fmt.Println(strings.TrimSpace(content))
				found = true
			}
		}

		if !found {
			log.Warn("No log files found; attempting journalctl fallback")
			log.Warn("No log files found. Trying journalctl fallback...")
			out, err := logger.TryJournalctl(log)
			if err != nil {
				return fmt.Errorf("journalctl fallback failed: %w", err)
			}
			fmt.Println(out)
			return nil
		}

		log.Info("Log search complete")
		return nil
	}),
}

func init() {
	InspectCmd.AddCommand(InspectLogsCmd)
}
