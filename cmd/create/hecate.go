package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func init() {
	CreateCmd.AddCommand(CreateHecateCmd)
}

// CreateHecateCmd creates the `create hecate` subcommand
var CreateHecateCmd = &cobra.Command{
	Use:   "hecate",
	Short: "Fetch and set up Hecate reverse proxy framework",
	Long: `This command downloads the Hecate reverse proxy framework from its repository,
places it in /opt/hecate, and prepares it for use with EOS.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)
		log.Info("🚀 Starting full Hecate setup wizard...")

		// ✅ Call the full prompt + orchestrator flow
		if err := hecate.OrchestrateHecateWizard(rc); err != nil {
			log.Error("❌ Hecate setup failed", zap.Error(err))
			return err
		}

		log.Info("✅ Hecate setup completed successfully!")
		return nil
	}),
}
