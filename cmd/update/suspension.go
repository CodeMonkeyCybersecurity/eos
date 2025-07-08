// cmd/update/disable-suspension.go

package update

import (
	"fmt"
	"runtime"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var disableSuspensionCmd = &cobra.Command{
	Use:   "suspension",
	Short: "Disable OS-level suspension and hibernation",
	Long: `Disable OS-level suspension and hibernation using the Assessment-Intervention-Evaluation pattern.

This command securely disables system sleep functionality by:
1. Assessing current sleep configuration
2. Masking systemd sleep targets
3. Configuring logind to ignore sleep keys
4. Evaluating that sleep is properly disabled

The operation is performed via Salt Stack for secure, auditable configuration management.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Starting system suspension disable operation")

		if runtime.GOOS != "linux" {
			logger.Warn("System suspension disabling is only supported on Linux")
			return fmt.Errorf("this command is not supported on %s", runtime.GOOS)
		}

		// Create Salt client for secure operations
		saltClient := saltstack.NewClient(logger)
		target := "localhost" // Default to localhost, could be parameterized

		// Use the modular system service helper with AIE pattern
		if err := system.DisableSystemSleep(rc.Ctx, logger, saltClient, target); err != nil {
			logger.Error("Failed to disable system sleep", zap.Error(err))
			return fmt.Errorf("failed to disable system sleep: %w", err)
		}

		logger.Info("System suspension and hibernation disabled successfully")
		return nil
	}),
}

func init() {
	UpdateCmd.AddCommand(disableSuspensionCmd)
}
