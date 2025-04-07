/* cmd/inspect/log.go
 */
package inspect

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var logLevel string

var InspectLogsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Inspect EOS logs (requires root or eos privileges)",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log := logger.L().Named("inspect")
		component := "logs"
		action := "search"

		if !utils.IsPrivilegedUser() {
			log.Warn("Insufficient permissions",
				zap.String("component", component),
				zap.String("action", action),
				zap.String("status", "denied"))
			return errors.New("you must be root or the 'eos' user to view logs")
		}

		log.Info("Searching for log files",
			zap.String("component", component),
			zap.String("action", action),
			zap.String("status", "started"))

		activeLog := logger.ResolveLogPath()
		found := false
		fmt.Println("🔍 Searching for logs:")

		for _, path := range logger.PlatformLogPaths() {
			full := os.ExpandEnv(path)
			if _, err := os.Stat(full); err != nil {
				continue
			}

			found = true
			prefix := "📄"
			if full == activeLog {
				prefix = "⭐"
			}
			fmt.Printf("\n%s %s\n", prefix, full)
		}

		if !found {
			log.Warn("No local logs found; attempting journalctl fallback",
				zap.String("component", component),
				zap.String("action", action),
				zap.String("status", "fallback"))
			return tryJournalctl(log)
		}

		log.Info("Log search complete",
			zap.String("component", component),
			zap.String("action", action),
			zap.String("status", "complete"))
		return nil
	}),
}

func tryJournalctl(log *zap.Logger) error {
	cmd := exec.Command("journalctl", "-u", "eos", "--no-pager", "--since", "today")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Error("journalctl failed",
			zap.String("component", "logs"),
			zap.String("action", "journalctl"),
			zap.String("status", "error"),
			zap.Error(err))
		return fmt.Errorf("could not query logs via journalctl: %w", err)
	}
	fmt.Println(string(out))
	return nil
}

func init() {
	InspectCmd.AddCommand(InspectLogsCmd)
	InspectLogsCmd.Flags().StringVar(&logLevel, "level", "", "Filter logs by minimum level (debug, info, warn, error, fatal)")
}
