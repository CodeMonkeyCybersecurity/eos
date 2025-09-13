// DEPRECATED: This file is deprecated. Use 'eos bootstrap quickstart' instead of 'eos create quickstart'.
// All quickstart functionality has been migrated to cmd/bootstrap/ for better organization.
// This file is maintained only for backward compatibility.

package create

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	// TODO: Re-add when Nomad implementation is complete:
	// "github.com/CodeMonkeyCybersecurity/eos/pkg/osquery"
	// "github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/state"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var quickstartCmd = &cobra.Command{
	Use:   "quickstart",
	Short: "DEPRECATED: Use 'eos bootstrap quickstart' instead",
	Long: `DEPRECATED: This command is deprecated. Use 'eos bootstrap quickstart' instead.

The new quickstart command provides the same functionality:

  eos bootstrap quickstart           # Quick 5-minute setup
  eos bootstrap quickstart --with-nomad  # Include Nomad

This command will redirect to the new bootstrap quickstart for backward compatibility.`,
	RunE: eos_cli.Wrap(runQuickstart),
}

func init() {
	// DEPRECATED: This command is deprecated. Users should use 'eos bootstrap quickstart' instead.
	// Keeping for backward compatibility but showing deprecation warnings.
	CreateCmd.AddCommand(quickstartCmd)

	quickstartCmd.Flags().Bool("with-nomad", false, "Include Nomad for container orchestration")
	quickstartCmd.Flags().Bool("with-clusterfuzz", false, "Include ClusterFuzz setup")
	quickstartCmd.Flags().Bool("skip-verify", false, "Skip verification steps")
	quickstartCmd.Flags().Duration("timeout", 5*time.Minute, "Maximum time for quickstart")
}

func runQuickstart(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	logger.Warn("DEPRECATION WARNING: 'eos create quickstart' is deprecated. Use 'eos bootstrap quickstart' instead.")
	logger.Info("Starting eos quickstart",
		zap.Time("start_time", startTime))

	// Create state tracker
	tracker := state.New()

	// Parse flags
	withNomad := cmd.Flag("with-nomad").Value.String() == "true"
	withClusterFuzz := cmd.Flag("with-clusterfuzz").Value.String() == "true"
	skipVerify := cmd.Flag("skip-verify").Value.String() == "true"
	timeout, _ := cmd.Flags().GetDuration("timeout")

	// Create context with timeout
	ctx, cancel := context.WithTimeout(rc.Ctx, timeout)
	defer cancel()
	rc.Ctx = ctx

	logger.Info("Quickstart configuration",
		zap.Bool("with_nomad", withNomad),
		zap.Bool("with_clusterfuzz", withClusterFuzz),
		zap.Bool("skip_verify", skipVerify),
		zap.Duration("timeout", timeout))

	// Phase 1: Core Bootstrap
	logger.Info("PHASE 1: Core Bootstrap",
		zap.Int("phase", 1),
		zap.Int("total_phases", 4))

	// 1.1 Bootstrap Salt - TODO: Replace with Nomad orchestration
	logger.Info("Salt bootstrap placeholder - Nomad orchestration not implemented yet")
	// TODO: Replace with Nomad client initialization
	// TODO: When implemented, restore the following phases:
	// - Phase 1: Vault bootstrap, OSQuery installation
	// - Phase 2: Nomad installation, ClusterFuzz setup
	// - Phase 3: State management and tracking
	// - Phase 4: Verification and summary
	_ = tracker // Suppress unused parameter warning
	_ = withNomad // Suppress unused parameter warning
	_ = withClusterFuzz // Suppress unused parameter warning
	_ = skipVerify // Suppress unused parameter warning
	return fmt.Errorf("quickstart not implemented with Nomad yet")
}

// The following functions have been removed as they are unused in the current implementation:
// - installNomadViaSalt: TODO restore when Nomad orchestration is implemented
// - setupClusterFuzz: TODO restore when ClusterFuzz integration is implemented  
// - verifyQuickstart: TODO restore when verification is implemented
