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
)

var logLevel string

var InspectLogsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Inspect EOS logs (requires root or eos privileges)",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		if !utils.IsPrivilegedUser() {
			return errors.New("you must be root or the 'eos' user to view logs")
		}

		activeLog := logger.ResolveLogPath()
		foundLogs := false

		fmt.Println("🔍 Searching for logs:")

		for _, path := range logger.PlatformLogPaths() {
			fullPath := os.ExpandEnv(path)
			if _, err := os.Stat(fullPath); err != nil {
				continue
			}

			foundLogs = true
			prefix := "📄"
			if fullPath == activeLog {
				prefix = "⭐"
			}
			fmt.Printf("\n%s %s\n", prefix, fullPath)
		}

		if !foundLogs {
			fmt.Println("⚠️ No Eos logs found in known locations. Trying journalctl...")
			return tryJournalctl()
		}

		return nil
	}),
}

func tryJournalctl() error {
	out, err := exec.Command("journalctl", "-u", "eos", "--no-pager", "--since", "today").CombinedOutput()
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
