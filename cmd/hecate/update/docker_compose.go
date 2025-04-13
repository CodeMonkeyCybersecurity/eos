// cmd/hecate/update/docker_compose.go

package update

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// dockerComposeCmd is the subcommand that updates the docker-compose file.
var dockerComposeCmd = &cobra.Command{
	Use:   "docker-compose",
	Short: "Update the docker-compose file based on selected Eos apps",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log := logger.GetLogger()
		lastValues := hecate.LoadLastValues()
		selectedApps := make(map[string]bool)

		// Command-line mode: if arguments are provided.
		if len(args) > 0 {
			// Command-line mode: if arguments are provided.
			for _, arg := range args {
				lower := strings.ToLower(arg)
				if _, ok := hecate.SupportedApps[lower]; ok {
					selectedApps[lower] = true
				}
			}
			if len(selectedApps) == 0 {
				log.Error("No supported apps found in the command-line arguments.")
				return fmt.Errorf("no supported apps found in the command-line arguments")
			}
			var keys []string
			for k := range selectedApps {
				keys = append(keys, k)
			}
			lastValues["APPS_SELECTION"] = strings.Join(keys, ", ")
		} else {
			// Interactive mode.
			hecate.DisplayOptions()
			defaultSelection := lastValues["APPS_SELECTION"]

			// Create a reader for input.
			reader := bufio.NewReader(os.Stdin)

			var sel string
			selectedApps, sel = hecate.GetUserSelection(defaultSelection, reader)
			lastValues["APPS_SELECTION"] = sel
			hecate.SaveLastValues(lastValues)
		}
		if err := hecate.UpdateComposeFile(selectedApps); err != nil {
			log.Error("Error updating docker-compose file.", zap.Error(err))
			return err
		}
		return nil
	}),
}
