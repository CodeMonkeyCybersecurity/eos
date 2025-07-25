// cmd/bootstrap/core.go
// Core bootstrap functionality with comprehensive system preparation

package bootstrap

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/bootstrap"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GetCoreCmd returns the core bootstrap command
func GetCoreCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "core",
		Short: "Bootstrap core Eos components (Salt + API)",
		Long: `Bootstrap the core components required for Eos operation.

This minimal bootstrap includes:
• SaltStack installation and configuration
• Salt REST API setup with secure credentials
• File roots configuration for Eos states
• Basic system verification

This is the minimum required for Eos to function properly.
Use 'eos bootstrap all' for a complete system setup.`,
		RunE: eos.Wrap(runBootstrapCore),
	}
}

func runBootstrapCore(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check root permissions
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("bootstrap requires root privileges")
	}

	logger.Info("Starting Eos core bootstrap")

	// Check current bootstrap status
	status, err := bootstrap.CheckBootstrap(rc)
	if err != nil {
		logger.Warn("Failed to check bootstrap status", zap.Error(err))
		status = &bootstrap.BootstrapStatus{} // Continue with empty status
	}

	// Display current status
	displayCoreStatus(rc, status)

	// If already bootstrapped, check if user wants to re-run
	if status.SaltInstalled && status.SaltAPIConfigured && status.FileRootsConfigured {
		if !cmd.Flag("force").Changed {
			logger.Info("terminal prompt: Core components are already bootstrapped.")
			logger.Info("terminal prompt: Use --force to re-run bootstrap.")
			return nil
		}
	}

	// Step 1: Install and configure SaltStack with API
	logger.Info("Step 1/3: Installing SaltStack with API configuration")
	if err := bootstrapSaltWithAPI(rc); err != nil {
		return fmt.Errorf("SaltStack bootstrap failed: %w", err)
	}

	// Step 2: Verify file roots are set up
	logger.Info("Step 2/3: Verifying file roots configuration")
	if err := saltstack.SetupFileRoots(rc); err != nil {
		return fmt.Errorf("file roots setup failed: %w", err)
	}

	// Step 3: Mark as bootstrapped
	logger.Info("Step 3/3: Marking system as bootstrapped")
	if err := bootstrap.MarkBootstrapped(rc); err != nil {
		return fmt.Errorf("failed to mark bootstrap: %w", err)
	}

	// Final verification
	finalStatus, _ := bootstrap.CheckBootstrap(rc)
	if !finalStatus.Bootstrapped {
		return fmt.Errorf("bootstrap verification failed - system may not be properly configured")
	}

	displayCoreSuccess(rc)
	return nil
}

func displayCoreStatus(rc *eos_io.RuntimeContext, status *bootstrap.BootstrapStatus) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("terminal prompt: Core Bootstrap Status:")
	logger.Info(fmt.Sprintf("terminal prompt:   SaltStack installed:    %s", formatStatus(status.SaltInstalled)))
	logger.Info(fmt.Sprintf("terminal prompt:   Salt API configured:    %s", formatStatus(status.SaltAPIConfigured)))
	logger.Info(fmt.Sprintf("terminal prompt:   File roots configured:  %s", formatStatus(status.FileRootsConfigured)))
	logger.Info("terminal prompt: ")
}

func formatStatus(ok bool) string {
	if ok {
		return "✓"
	}
	return "✗"
}

func bootstrapSaltWithAPI(rc *eos_io.RuntimeContext) error {
	// Use the standard Salt installation which now includes API setup
	config := &saltstack.Config{
		MasterMode: false,
		LogLevel:   "warning",
		SkipTest:   false,
	}

	return saltstack.Install(rc, config)
}

func displayCoreSuccess(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ✅ Core bootstrap completed successfully!")
	logger.Info("terminal prompt: ")
	
	// Load and display API credentials
	if creds, err := saltstack.LoadAPICredentials(); err == nil {
		logger.Info("terminal prompt: Salt API is configured:")
		logger.Info(fmt.Sprintf("terminal prompt:   URL: %s", creds.URL))
		logger.Info(fmt.Sprintf("terminal prompt:   User: %s", creds.Username))
		logger.Info("terminal prompt:   Credentials: /etc/eos/salt/api.env")
		logger.Info("terminal prompt: ")
	}
	
	logger.Info("terminal prompt: You can now deploy services:")
	logger.Info("terminal prompt:   eos create consul")
	logger.Info("terminal prompt:   eos create vault")
	logger.Info("terminal prompt:   eos create nomad")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: For a complete system setup, run:")
	logger.Info("terminal prompt:   eos bootstrap all")
}

func init() {
	coreCmd := GetCoreCmd()
	coreCmd.Flags().Bool("force", false, "Force re-run bootstrap even if already completed")
}