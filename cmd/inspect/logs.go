// cmd/inspect/logs.go
package inspect

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"

	"github.com/spf13/cobra"
)

var logLevel string

var InspectLogsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Inspect EOS logs (requires root or hera privileges)",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		if !utils.IsPrivilegedUser() {
			return errors.New("you must be root or the 'hera' user to view logs")
		}

		active := logger.ResolveLogPath()
		paths := logger.PlatformLogPaths()

		fmt.Println("🔍 Searching for logs:")
		found := false

		for _, path := range paths {
			expanded := os.ExpandEnv(path)
			if _, err := os.Stat(expanded); err == nil {
				prefix := "📄"
				if expanded == active {
					prefix = "⭐"
				}
				fmt.Printf("\n%s %s\n", prefix, expanded)

				content, err := logger.ReadLogFile(expanded)
				if err != nil {
					fmt.Printf("❌ Failed to read %s: %v\n", expanded, err)
					continue
				}

				if logLevel != "" {
					filtered := filterLogsByLevel(content, logLevel)
					fmt.Println(filtered)
				} else {
					fmt.Println(content)
				}
				found = true
			}
		}

		if !found {
			fmt.Println("⚠️ No Eos logs found in known locations. Trying journalctl...")
			out, err := exec.Command("journalctl", "-u", "eos", "--no-pager", "--since", "today").CombinedOutput()
			if err != nil {
				return fmt.Errorf("could not query logs via journalctl: %w", err)
			}
			fmt.Println(string(out))
		}

		return nil
	}),
}

func filterLogsByLevel(content string, level string) string {
	lines := strings.Split(content, "\n")
	var result []string

	threshold := map[string]int{
		"debug": 0,
		"info":  1,
		"warn":  2,
		"error": 3,
		"fatal": 4,
	}

	currentThreshold := threshold[strings.ToLower(level)]

	for _, line := range lines {
		if line == "" {
			continue
		}
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		lvl, ok := entry["L"].(string)
		if !ok {
			continue
		}

		if threshold[strings.ToLower(lvl)] >= currentThreshold {
			result = append(result, line)
		}
	}

	return strings.Join(result, "\n")
}

func init() {
	InspectCmd.AddCommand(InspectLogsCmd)
	InspectLogsCmd.Flags().StringVar(&logLevel, "level", "", "Filter logs by minimum level (debug, info, warn, error, fatal)")
}
