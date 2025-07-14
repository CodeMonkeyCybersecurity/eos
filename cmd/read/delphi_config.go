// cmd/delphi/read/config.go

package read

import (
	"encoding/json"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
)

var ReadConfigCmd = &cobra.Command{
	Use:     "config",
	Short:   "Read the currently loaded Delphi configuration",
	Long:    "Displays the contents of the delphi.json config file, with sensitive fields masked for safety.",
	Aliases: []string{"cfg", "settings"},
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		cfg, err := delphi.ReadConfig(rc)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to load Delphi config", zap.Error(err))
			otelzap.Ctx(rc.Ctx).Info("terminal prompt: Error loading Delphi config", zap.Error(err))
			return err
		}

		if !eos_unix.EnforceSecretsAccess(rc.Ctx, showSecrets) {
			return nil
		}

		// Mask sensitive fields
		if !showSecrets {
			cfg.APIPassword = "********"
			cfg.Token = "********"
		}

		cfgJSON, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to marshal Delphi config", zap.Error(err))
			otelzap.Ctx(rc.Ctx).Info("terminal prompt: Error printing config", zap.Error(err))
			return err
		}

		otelzap.Ctx(rc.Ctx).Info("terminal prompt: Delphi Configuration")
		otelzap.Ctx(rc.Ctx).Info("terminal prompt: JSON output", zap.String("data", string(cfgJSON)))
		return nil
	}),
}

func init() {
	readDelphiCmd.AddCommand(ReadConfigCmd)
	ReadConfigCmd.Flags().BoolVar(&showSecrets, "show-secrets", false, "Display sensitive fields like password and token")
}
