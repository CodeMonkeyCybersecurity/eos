/* cmd/hecate/update/docker_compose.go */

package update

import (
	"fmt"
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
	Short: "Update the docker-compose file based on selected EOS apps",
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log := logger.GetLogger()
		lastValues := hecate.LoadLastValues()
		selectedApps := make(map[string]bool)
		var selectionStr string

		// Command-line mode: if arguments are provided.
		if len(args) > 0 {
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
			selectionStr = strings.Join(keys, ", ")
		} else {
			// Interactive mode.
			hecate.DisplayOptions()
			defaultSelection := lastValues["APPS_SELECTION"]
			var sel string
			selectedApps, sel = hecate.GetUserSelection(defaultSelection)
			selectionStr = sel
			lastValues["APPS_SELECTION"] = selectionStr
			if err := hecate.SaveLastValues(lastValues); err != nil {
				log.Error("Error saving last values.", zap.Error(err))
				return err
			}
		}
		if err := hecate.UpdateComposeFile(selectedApps); err != nil {
			log.Error("Error updating docker-compose file.", zap.Error(err))
			return err
		}
		return nil
	}),
}
