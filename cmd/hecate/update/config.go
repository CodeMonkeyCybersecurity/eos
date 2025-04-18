package update

import (
	"bufio"
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/spf13/cobra"
)

// configCmd is the "config" subcommand for updating conf.d configuration files.
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Update configuration files in conf.d",
	Long:  `Recursively update configuration files in the conf.d directory by replacing placeholder variables.`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log.Info("Running update config command")

		// Display a header for the interactive update.
		log.Info("=== Recursive conf.d Variable Updater ===\n")

		// Load previous values if available.
		// NOTE: LoadLastValues returns only a map, so we remove the error assignment.
		lastValues := hecate.LoadLastValues()

		// Create a reader for user input.
		reader := bufio.NewReader(os.Stdin)

		// Prompt user for values, using stored defaults if available.
		backendIP := hecate.PromptInput("BACKEND_IP", "Enter the backend IP address", lastValues["BACKEND_IP"], reader)
		persBackendIP := hecate.PromptInput("PERS_BACKEND_IP", "Enter the backend IP address for your Persephone backups", lastValues["PERS_BACKEND_IP"], reader)
		delphiBackendIP := hecate.PromptInput("DELPHI_BACKEND_IP", "Enter the backend IP address for your Delphi install", lastValues["DELPHI_BACKEND_IP"], reader)
		baseDomain := hecate.PromptInput("BASE_DOMAIN", "Enter the base domain for your services", lastValues["BASE_DOMAIN"], reader)

		// Save the new values for future runs.
		newValues := map[string]string{
			"BACKEND_IP":        backendIP,
			"PERS_BACKEND_IP":   persBackendIP,
			"DELPHI_BACKEND_IP": delphiBackendIP,
			"BASE_DOMAIN":       baseDomain,
		}
		// SaveLastValues does not return a value, so simply call it:
		hecate.SaveLastValues(newValues)

		// Ensure the conf.d directory exists.
		if info, err := os.Stat(hecate.ConfDir); err != nil || !info.IsDir() {
			errMsg := fmt.Sprintf("Error: Directory '%s' not found in the current directory.", hecate.ConfDir)
			log.Error(errMsg)
			fmt.Println(errMsg)
			return err
		}

		// Process all .conf files recursively in the conf.d directory.
		hecate.ProcessConfDirectory(hecate.ConfDir, backendIP, persBackendIP, delphiBackendIP, baseDomain)

		fmt.Println("\nDone updating configuration files in the conf.d directory.")
		return nil
	}),
}

func init() {
	// Attach the config subcommand to the parent update command.
	UpdateCmd.AddCommand(configCmd)
}
