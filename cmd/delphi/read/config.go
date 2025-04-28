// cmd/delphi/inspect/config.go

package read

import (
	"encoding/json"
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
)

var InspectConfigCmd = &cobra.Command{
	Use:     "config",
	Short:   "Inspect the currently loaded Delphi configuration",
	Long:    "Displays the contents of the delphi.json config file, with sensitive fields masked for safety.",
	Aliases: []string{"cfg", "settings"},
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := logger.GetLogger()

		cfg, err := delphi.ReadConfig(log)
		if err != nil {
			log.Error("Failed to load Delphi config", zap.Error(err))
			fmt.Println("❌ Error loading Delphi config:", err)
			return err
		}

		if !utils.EnforceSecretsAccess(log, showSecrets) {
			return nil
		}

		// Mask sensitive fields
		if !showSecrets {
			cfg.APIPassword = "********"
			cfg.Token = "********"
		}

		cfgJSON, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			log.Error("Failed to marshal Delphi config", zap.Error(err))
			fmt.Println("❌ Error printing config:", err)
			return err
		}

		fmt.Println("📄 Delphi Configuration:")
		fmt.Println(string(cfgJSON))
		return nil
	}),
}

func init() {
	ReadCmd.AddCommand(InspectConfigCmd)
	InspectConfigCmd.Flags().BoolVar(&showSecrets, "show-secrets", false, "Display sensitive fields like password and token")
}
