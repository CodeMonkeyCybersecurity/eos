/* cmd/hecate/update/apps.go */

package update

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// removeUnwantedConfFiles walks through the hecate.ConfDir and removes any .conf file
// whose base name is not in the allowedFiles set.
func removeUnwantedConfFiles(allowedFiles map[string]bool) {
	info, err := os.Stat(hecate.ConfDir)
	if err != nil || !info.IsDir() {
		fmt.Printf("Error: Directory '%s' not found.\n", hecate.ConfDir)
		return
	}

	var removedFiles []string
	// Recursively walk the configuration directory.
	err = filepath.Walk(hecate.ConfDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Skip files with errors.
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".conf") {
			if !allowedFiles[info.Name()] {
				// Try to remove the file.
				err := os.Remove(path)
				if err != nil {
					fmt.Printf("Error removing %s: %v\n", path, err)
				} else {
					removedFiles = append(removedFiles, path)
					fmt.Printf("Removed: %s\n", path)
				}
			}
		}
		return nil
	})
	if err != nil {
		zap.L().Fatal("Error walking the directory", zap.Error(err))
	}

	if len(removedFiles) == 0 {
		fmt.Println("No configuration files were removed.")
	} else {
		fmt.Println("\nCleanup complete. The following files were removed:")
		for _, f := range removedFiles {
			fmt.Printf(" - %s\n", f)
		}
	}
}

// appsCmd is the "apps" subcommand for updating enabled applications.
var appsCmd = &cobra.Command{
	Use:   "apps",
	Short: "Update enabled applications in the conf.d directory",
	Long:  `Select and keep configuration files for enabled Eos backend web apps while removing others.`,
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {

		zap.L().Info("Running update apps command")

		zap.L().Info("=== Eos Backend Web Apps Selector ===\n")
		reader := bufio.NewReader(os.Stdin)

		// Load previous values from the configuration file.
		lastValues := hecate.LoadLastValues()
		defaultApps := lastValues["APPS_SELECTION"]

		// Display available apps.
		hecate.DisplayOptions()

		// Prompt for a selection.
		allowedFiles, selectionStr := hecate.GetUserSelection(defaultApps, reader)

		// Always add essential configuration files.
		essentialFiles := []string{"http.conf", "stream.conf", "fallback.conf"}
		for _, file := range essentialFiles {
			allowedFiles[file] = true
		}

		fmt.Println("\nYou have selected the following configuration files to keep:")
		// Print the allowed files list.
		for file := range allowedFiles {
			// Check if the file is essential.
			if file == "http.conf" || file == "stream.conf" || file == "fallback.conf" {
				fmt.Printf(" - Essential file: %s\n", file)
			} else {
				// Try to find the corresponding app name.
				var appName string
				for _, app := range hecate.AppsSelection {
					if app.ConfFile == file {
						appName = app.AppName
						break
					}
				}
				fmt.Printf(" - %s (%s)\n", appName, file)
			}
		}

		fmt.Println("\nNow scanning the conf.d directory and removing files not in your selection...")
		removeUnwantedConfFiles(allowedFiles)

		// Save the selection back to the last values file.
		lastValues["APPS_SELECTION"] = selectionStr
		hecate.SaveLastValues(lastValues)

		fmt.Println("\nUpdate complete.")
		return nil
	}),
}

func init() {
	// Attach the apps subcommand to the parent update command.
	UpdateCmd.AddCommand(appsCmd)
}
