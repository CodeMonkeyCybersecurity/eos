// cmd/delphi/inspect/config.go

package inspect

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
)

var showSecrets bool

var InspectConfigCmd = &cobra.Command{
	Use:     "config",
	Short:   "Inspect the currently loaded Delphi configuration",
	Long:    "Displays the contents of the delphi.json config file, with sensitive fields masked for safety.",
	Aliases: []string{"cfg", "settings"},
	Run: func(cmd *cobra.Command, args []string) {
		log := logger.GetLogger()

		cfg, err := config.LoadDelphiConfig()
		if err != nil {
			log.Error("Failed to load Delphi config", zap.Error(err))
			fmt.Println("❌ Error loading Delphi config:", err)
			return
		}

		// Mask sensitive fields
		if !showSecrets {
			cfg.API_Password = "********"
			cfg.Token = "********"
		}

		cfgJSON, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			log.Error("Failed to marshal Delphi config", zap.Error(err))
			fmt.Println("❌ Error printing config:", err)
			return
		}

		fmt.Println("📄 Delphi Configuration:")
		fmt.Println(string(cfgJSON))
	},
}
