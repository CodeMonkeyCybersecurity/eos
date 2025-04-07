// cmd/inspect/logs.go

package inspect

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

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

		logPaths := []string{
			"/var/log/eos/eos.log",
			"/var/log/eos/k3s-deploy.log",
			"/var/log/eos/vault.log",
		}

		found := false
		for _, path := range logPaths {
			if _, err := os.Stat(path); err == nil {
				fmt.Printf("\n📄 %s\n", path)
				content, _ := os.ReadFile(path)
				fmt.Println(string(content))
				found = true
			}
		}

		if !found {
			fmt.Println("⚠️ No Eos logs found in /var/log/eos/. Falling back to journalctl...")
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
