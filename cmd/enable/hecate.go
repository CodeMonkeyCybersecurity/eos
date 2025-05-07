package enable

import (
	"context"
	"fmt"
	"os/exec"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func init() {
	EnableCmd.AddCommand(EnableHecateCmd)
}

// EnableHecateCmd brings up Hecate using Docker Compose
var EnableHecateCmd = &cobra.Command{
	Use:   "hecate",
	Short: "Start Hecate services using Docker Compose",
	Long: `This command starts the full Hecate stack using Docker Compose,
by running 'docker compose up -d' inside /opt/hecate.`,
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := zap.L().Named("enable-hecate")
		log.Info("🚀 Starting Hecate stack (docker compose up -d)...")

		composePath := hecate.BaseDir

		execCmd := exec.CommandContext(context.Background(), "docker", "compose", "up", "-d")
		execCmd.Dir = composePath

		output, err := execCmd.CombinedOutput()
		if err != nil {
			log.Error("❌ Failed to start Hecate stack", zap.Error(err), zap.ByteString("output", output))
			return fmt.Errorf("failed to start Hecate stack: %w", err)
		}

		log.Info("✅ Hecate stack started successfully!", zap.ByteString("output", output))
		return nil
	}),
}
