package ragequit

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit/diagnostics"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit/emergency"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit/recovery"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit/system"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RagequitCmd represents the ragequit command
var RagequitCmd = &cobra.Command{
	Use:   "ragequit",
	Short: "Emergency system diagnostic and recovery tool",
	Long: `Emergency system diagnostic and recovery tool for when things go completely wrong.

Ragequit performs comprehensive system diagnostics, captures critical state information,
and can optionally reboot the system to recover from stuck processes or system loops.

Features:
- Environment detection (containers, cloud, bare metal)
- Universal resource exhaustion checks
- Database and queue system diagnostics
- Security incident response data collection
- Post-reboot recovery automation
- Configurable notification systems

Examples:
  # Emergency diagnostics with reboot
  eos ragequit --reason "systemd loop detected"
  
  # Diagnostics only (no reboot)
  eos ragequit --no-reboot --reason "investigating high CPU"
  
  # Force immediate action (skip confirmation)
  eos ragequit --force --reason "critical system failure"
  
  # Minimal diagnostics for quick recovery
  eos ragequit --actions minimal --reason "stuck processes"`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		logger.Warn(" EMERGENCY: Ragequit initiated",
			zap.String("user", os.Getenv("USER")),
			zap.String("hostname", system.GetHostname()),
			zap.String("reason", reason),
			zap.Bool("no_reboot", noReboot),
			zap.String("actions", actions))

		// Confirmation prompt unless forced
		config := &ragequit.Config{
			Reason:   reason,
			NoReboot: noReboot,
			Force:    force,
			Actions:  actions,
		}

		if !emergency.ConfirmRagequit(rc, config) {
			logger.Info("Ragequit cancelled by user")
			return nil
		}

		// Create timestamp file for tracking
		if err := emergency.CreateTimestampFile(rc, reason); err != nil {
			logger.Warn("Failed to create timestamp file", zap.Error(err))
		}

		// Start diagnostic collection
		logger.Info("Starting emergency diagnostic collection",
			zap.String("phase", "diagnostics"),
			zap.String("output_dir", system.GetHomeDir()))

		var wg sync.WaitGroup

		// Run all diagnostic functions in parallel for speed
		diagnosticFuncs := []func(*eos_io.RuntimeContext) error{
			func(rc *eos_io.RuntimeContext) error {
				_, err := diagnostics.DetectEnvironment(rc)
				return err
			},
			func(rc *eos_io.RuntimeContext) error {
				_, err := diagnostics.CheckResources(rc)
				return err
			},
			diagnostics.CheckQueues,
			diagnostics.CheckDatabases,
			diagnostics.SecuritySnapshot,
			diagnostics.ContainerDiagnostics,
			diagnostics.PerformanceSnapshot,
			diagnostics.SystemctlDiagnostics,
			diagnostics.NetworkDiagnostics,
			diagnostics.CustomHooks,
		}

		for _, fn := range diagnosticFuncs {
			wg.Add(1)
			go func(diagFunc func(*eos_io.RuntimeContext) error) {
				defer wg.Done()
				if err := diagFunc(rc); err != nil {
					logger.Warn("Diagnostic function failed", zap.Error(err))
				}
			}(fn)
		}

		// Wait for all diagnostics to complete (with timeout)
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			logger.Info("All diagnostics completed successfully")
		case <-time.After(30 * time.Second):
			logger.Warn("Diagnostic collection timeout, proceeding anyway",
				zap.Duration("timeout", 30*time.Second))
		}

		// Generate recovery plan
		if err := recovery.GenerateRecoveryPlan(rc); err != nil {
			logger.Warn("Failed to generate recovery plan", zap.Error(err))
		}

		// Setup post-reboot automation
		if err := recovery.CreatePostRebootRecovery(rc); err != nil {
			logger.Warn("Failed to create post-reboot recovery", zap.Error(err))
		}

		// Send notifications
		if err := emergency.NotifyRagequit(rc, reason); err != nil {
			logger.Warn("Failed to send notifications", zap.Error(err))
		}

		// Final preparations before reboot
		if err := emergency.FlushDataSafety(rc); err != nil {
			logger.Warn("Failed to flush data safety", zap.Error(err))
		}

		if !noReboot {
			logger.Error("🔥 INITIATING EMERGENCY REBOOT",
				zap.String("countdown", "5 seconds"),
				zap.String("reason", reason))

			// Final countdown
			for i := 5; i > 0; i-- {
				logger.Warn("Rebooting in", zap.Int("seconds", i))
				time.Sleep(1 * time.Second)
			}

			// Execute reboot
			return emergency.ExecuteReboot(rc)
		} else {
			logger.Info("Diagnostic collection complete - no reboot requested",
				zap.String("investigation_file", filepath.Join(system.GetHomeDir(), "RAGEQUIT-RECOVERY-PLAN.md")))
			return nil
		}
	}),
}

// Configuration variables
var (
	reason   string
	noReboot bool
	force    bool
	actions  string
)

func init() {
	RagequitCmd.Flags().StringVar(&reason, "reason", "", "Reason for ragequit (required)")
	if err := RagequitCmd.MarkFlagRequired("reason"); err != nil {
		// This is a programming error, not a runtime error
		panic(fmt.Sprintf("Failed to mark reason flag as required: %v", err))
	}

	RagequitCmd.Flags().BoolVar(&noReboot, "no-reboot", false, "Collect diagnostics without rebooting")
	RagequitCmd.Flags().BoolVar(&force, "force", false, "Skip confirmation prompt")
	RagequitCmd.Flags().StringVar(&actions, "actions", "full", "Diagnostic actions: minimal, standard, full")
}
