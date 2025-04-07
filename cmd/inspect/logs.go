package inspect

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
	"github.com/spf13/cobra"
)

var InspectLogsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Inspect EOS logs (requires root or hera privileges)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if !utils.IsPrivilegedUser() {
			return errors.New("you must be root or the 'hera' user to view logs")
		}

		active := logger.ResolveLogPath()
		paths := logger.PlatformLogPaths()

		found := false
		for _, path := range paths {
			if _, err := os.Stat(path); err == nil {
				prefix := "📄"
				if path == active {
					prefix = "⭐"
				}
				fmt.Printf("\n%s %s\n", prefix, path)
				content, _ := os.ReadFile(path)
				fmt.Println(string(content))
				found = true
			}
		}

		if !found {
			fmt.Println("⚠️ No Eos logs found in common paths. Falling back to journalctl...")
			cmd := exec.Command("journalctl", "-u", "eos", "--no-pager", "--since", "today")
			out, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("could not query logs via journalctl: %w", err)
			}
			fmt.Println(string(out))
		}

		return nil
	},
}

func init() {
	InspectCmd.AddCommand(InspectLogsCmd)
}
