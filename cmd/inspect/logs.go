/* cmd/inspect/log.go
 */

package inspect

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var logLevel string

var InspectLogsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Inspect Eos logs (requires root or eos privileges)",
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := zap.L().Named("inspect")

		if !utils.IsPrivilegedUser() {
			return errors.New("you must be root or the 'eos' user to view logs")
		}

		log.Info("Searching for log files", zap.String("component", "logs"), zap.String("action", "search"), zap.String("status", "started"))
		found := false
		active := logger.ResolveLogPath()

		for _, candidate := range logger.PlatformLogPaths() {
			path := os.ExpandEnv(candidate)
			if _, err := os.Stat(path); err == nil {
				prefix := "📄"
				if path == active {
					prefix = "⭐"
				}
				fmt.Printf("\n%s %s\n", prefix, path)

				content, err := logger.ReadLogFile(path)
				if err != nil {
					fmt.Printf("❌ Failed to read %s: %v\n", path, err)
					continue
				}
				fmt.Println(strings.TrimSpace(content))
				found = true
			}
		}

		if !found {
			log.Warn("No log files found, falling back to journalctl")
			fmt.Println("⚠️ No Eos logs found in known locations. Trying journalctl...")
			return tryJournalctl()
		}

		log.Info("Log search complete", zap.String("component", "logs"), zap.String("action", "search"), zap.String("status", "complete"))
		return nil
	}),
}

func tryJournalctl() error {
	out, err := exec.Command("journalctl", "-u", shared.EosID, "--no-pager", "--since", "today").CombinedOutput()
	if err != nil {
		return fmt.Errorf("could not query logs via journalctl: %w", err)
	}
	fmt.Println(string(out))
	return nil
}

func init() {
	InspectCmd.AddCommand(InspectLogsCmd)
	InspectLogsCmd.Flags().StringVar(&logLevel, "level", "", "Filter logs by minimum level (debug, info, warn, error, fatal)")
}
