package secure

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ubuntu"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func init() {
	SecureCmd.AddCommand(ubuntuCmd)
}

var ubuntuCmd = &cobra.Command{
	Use:   "ubuntu",
	Short: "Harden Ubuntu system with security tools and configurations",
	Long: `Install and configure essential security tools for Ubuntu including:
- auditd for system auditing
- osquery for OS instrumentation  
- AIDE for file integrity monitoring
- Lynis for security auditing
- fail2ban for brute force protection
- Automatic security updates
- Kernel hardening and sysctl settings`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Starting Ubuntu security hardening")

		// Check if running as root
		if os.Geteuid() != 0 {
			return fmt.Errorf("this command must be run as root")
		}

		// Run the hardening process
		if err := ubuntu.SecureUbuntu(rc); err != nil {
			logger.Error("Failed to secure Ubuntu", zap.Error(err))
			return fmt.Errorf("secure ubuntu: %w", err)
		}

		logger.Info("Ubuntu security hardening completed successfully")
		return nil
	}),
}