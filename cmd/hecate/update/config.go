/* cmd/hecate/update/config.go */

package update

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// configCmd is the "config" subcommand for updating conf.d configuration files.
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Update configuration files in conf.d",
	Long:  `Recursively update configuration files in the conf.d directory by replacing placeholder variables.`,
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
		log := logger.GetLogger()
		log.Info("Running update config command")

		// Display a header for the interactive update.
		fmt.Println("=== Recursive conf.d Variable Updater ===\n")

		// Load previous values if available.
		lastValues, err := loadLastValues()
		if err != nil {
			log.Error("Error loading last values", zap.Error(err))
			fmt.Printf("Error loading last values: %v\n", err)
		}

		// Prompt user for values, using stored defaults if available.
		backendIP := hecate.PromptInput("BACKEND_IP", "Enter the backend IP address", lastValues["BACKEND_IP"])
		persBackendIP := hecate.PromptInput("PERS_BACKEND_IP", "Enter the backend IP address for your Persephone backups", lastValues["PERS_BACKEND_IP"])
		delphiBackendIP := hecate.PromptInput("DELPHI_BACKEND_IP", "Enter the backend IP address for your Delphi install", lastValues["DELPHI_BACKEND_IP"])
		baseDomain := hecate.PromptInput("BASE_DOMAIN", "Enter the base domain for your services", lastValues["BASE_DOMAIN"])

		// Save the new values for future runs.
		newValues := map[string]string{
			"BACKEND_IP":        backendIP,
			"PERS_BACKEND_IP":   persBackendIP,
			"DELPHI_BACKEND_IP": delphiBackendIP,
			"BASE_DOMAIN":       baseDomain,
		}
		if err := hecate.SaveLastValues(newValues); err != nil {
			log.Error("Error saving new values", zap.Error(err))
			fmt.Printf("Error saving new values: %v\n", err)
		}

		// Ensure the conf.d directory exists.
		if info, err := os.Stat(hecate.ConfDir); err != nil || !info.IsDir() {
			errMsg := fmt.Sprintf("Error: Directory '%s' not found in the current directory.", hecate.ConfDir)
			log.Error(errMsg)
			fmt.Println(errMsg)
			return fmt.Errorf(errMsg)
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
