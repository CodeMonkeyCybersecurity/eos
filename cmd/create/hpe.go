// cmd/create/hpe.go

package create

import (
	"fmt"
	"os"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hpe"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var createHPECmd = &cobra.Command{
	Use:   "hpe",
	Short: "Set up HPE Management Component Pack repository and install management tools",
	Long: `Set up the HPE Management Component Pack (MCP) repository and install HPE hardware management tools.

This command will:
- Download and enroll HPE GPG public keys
- Add the HPE MCP repository to APT sources
- Update package indexes
- Install HPE management tools including:
  * HP Health (Gen9 and earlier system health monitoring)
  * HPE iLO configuration utility (hponcfg)
  * Agentless Management Service (amsd for Gen10+, hp-ams for Gen9)
  * SNMP Agents (hp-snmp-agents)
  * System Management Homepage (hpsmh, hp-smh-templates)
  * Smart Storage Administration (ssacli, ssaducli, ssa)
  * MegaRAID CLI (storcli)

Requirements:
- Ubuntu/Debian Linux
- Root privileges (run with sudo)
- Network connectivity to downloads.linux.hpe.com

Note: Some packages may not install if they're not compatible with your hardware generation.
This is expected behavior and will not cause the command to fail.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		start := time.Now()

		// Log user context and command details
		pwd, _ := os.Getwd()
		logger.Info("Starting HPE MCP repository setup",
			zap.String("user", os.Getenv("USER")),
			zap.String("pwd", pwd),
			zap.String("command_line", strings.Join(os.Args, " ")),
			zap.String("function", "createHPECmd"))

		// Platform validation
		platformOS := platform.GetOSPlatform()
		logger.Info("Checking platform requirements",
			zap.String("os_platform", platformOS),
			zap.String("required", "linux"))

		if platformOS != "linux" {
			logger.Error("Platform requirement not met",
				zap.String("platform", platformOS),
				zap.String("required", "linux"),
				zap.String("remediation", "HPE MCP repository is only available for Linux"))
			return fmt.Errorf("unsupported platform: %s (HPE MCP requires Linux)", platformOS)
		}

		// Distribution detection
		distro := platform.DetectLinuxDistro(rc)
		logger.Info("Linux distribution detected",
			zap.String("distro", distro))

		// Root privileges check
		if os.Getuid() != 0 {
			logger.Error("Insufficient privileges",
				zap.String("current_user", os.Getenv("USER")),
				zap.String("remediation", "Run this command with sudo"))
			return fmt.Errorf("must run as root. Please use: sudo eos create hpe")
		}

		// Run HPE repository setup
		if err := hpe.SetupHPERepository(rc); err != nil {
			logger.Error("HPE repository setup failed",
				zap.Error(err),
				zap.Duration("duration", time.Since(start)))
			return err
		}

		// Log successful completion
		logger.Info("HPE repository setup completed successfully",
			zap.Duration("total_duration", time.Since(start)),
			zap.String("platform", platformOS),
			zap.String("distro", distro))

		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(createHPECmd)
}
