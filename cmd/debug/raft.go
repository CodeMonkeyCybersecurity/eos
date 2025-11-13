// cmd/debug/raft.go
//
// Comprehensive Raft state diagnostics for Consul cluster debugging.
// This command provides deep inspection of Raft consensus state, data directory
// configuration, and ACL bootstrap reset troubleshooting.
//
// Last Updated: 2025-01-25

package debug

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/debug"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	raftShowPeers      bool
	raftShowDataDir    bool
	raftShowReset      bool
	raftSimulateReset  bool
	raftWatchResetFile bool
	raftResetHistory   bool
)

var raftDebugCmd = &cobra.Command{
	Use:   "raft",
	Short: "Comprehensive Consul Raft state and ACL bootstrap diagnostics",
	Long: `Deep inspection of Consul's Raft consensus state, data directory configuration,
and ACL bootstrap reset troubleshooting.

This command is CRITICAL for debugging ACL bootstrap reset failures where:
  - Reset file is written but Consul doesn't consume it
  - Data directory configuration doesn't match actual Raft database location
  - Reset index keeps failing with same error despite retries

WHAT THIS COMMAND DOES:
  1. Finds ACTUAL raft.db location across the entire filesystem
  2. Compares configured data_dir vs actual Raft database location
  3. Inspects running Consul process to extract data_dir from command line
  4. Shows Raft cluster peers and leader status
  5. Extracts current ACL bootstrap reset index from Consul
  6. Shows history of reset attempts from logs
  7. Simulates reset file write (dry-run) to verify paths

DIAGNOSTIC MODES:
  --show-peers         Show Raft cluster peer list and leader
  --show-datadir       Show data directory from all sources (config, process, filesystem)
  --show-reset         Show current ACL bootstrap reset state and next required index
  --simulate-reset     Dry-run simulation of ACL reset file write (shows paths, doesn't write)
  --watch-reset-file   Monitor acl-bootstrap-reset file for 30s (shows when Consul reads it)
  --reset-history      Show last 10 ACL bootstrap reset attempts from logs

EXAMPLES:
  # Full Raft diagnostics (all checks)
  sudo eos debug raft

  # Find where raft.db REALLY is (vs where config says it should be)
  sudo eos debug raft --show-datadir

  # Check Raft cluster health and leader
  sudo eos debug raft --show-peers

  # Show current ACL bootstrap reset index and next required
  sudo eos debug raft --show-reset

  # Simulate ACL reset file write without actually writing (dry-run)
  sudo eos debug raft --simulate-reset

  # Watch acl-bootstrap-reset file to see if Consul consumes it
  sudo eos debug raft --watch-reset-file

  # Show timeline of ACL reset attempts
  sudo eos debug raft --reset-history

TROUBLESHOOTING ACL BOOTSTRAP RESET FAILURES:

If 'eos update consul --bootstrap-token' keeps failing:
  1. Run: sudo eos debug raft --show-datadir
     → This shows if data_dir config matches actual raft.db location
  2. Run: sudo eos debug raft --simulate-reset
     → This shows WHERE reset file would be written (without writing it)
  3. If paths don't match, fix config or use: --data-dir flag
  4. Run: sudo eos debug raft --watch-reset-file
     → This proves if Consul actually reads the file

COMMON ISSUES THIS COMMAND DETECTS:
  ✗ Config says /opt/consul but raft.db is in /var/lib/consul
  ✗ Reset file written to /opt/consul but Consul reads from /var/lib/consul
  ✗ Multiple raft.db files (stale installations)
  ✗ raft.db doesn't exist anywhere (Consul never started successfully)
  ✗ Process running from /usr/bin/consul but Eos looks in /usr/local/bin
`,

	RunE: eos_cli.Wrap(runRaftDebug),
}

func init() {
	raftDebugCmd.Flags().BoolVar(&raftShowPeers, "show-peers", false, "Show Raft cluster peer list and leader")
	raftDebugCmd.Flags().BoolVar(&raftShowDataDir, "show-datadir", false, "Show data directory from all sources (config, process, filesystem)")
	raftDebugCmd.Flags().BoolVar(&raftShowReset, "show-reset", false, "Show current ACL bootstrap reset state")
	raftDebugCmd.Flags().BoolVar(&raftSimulateReset, "simulate-reset", false, "Simulate ACL reset file write (dry-run)")
	raftDebugCmd.Flags().BoolVar(&raftWatchResetFile, "watch-reset-file", false, "Monitor acl-bootstrap-reset file for 30s")
	raftDebugCmd.Flags().BoolVar(&raftResetHistory, "reset-history", false, "Show last 10 ACL reset attempts from logs")

	debugCmd.AddCommand(raftDebugCmd)
}

func runRaftDebug(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting comprehensive Consul Raft diagnostics")

	// Build configuration for which checks to run
	config := &debug.RaftDiagnosticConfig{
		RunAll:           !raftShowPeers && !raftShowDataDir && !raftShowReset && !raftSimulateReset && !raftWatchResetFile && !raftResetHistory,
		ShowPeers:        raftShowPeers,
		ShowDataDir:      raftShowDataDir,
		ShowResetState:   raftShowReset,
		SimulateReset:    raftSimulateReset,
		WatchResetFile:   raftWatchResetFile,
		ShowResetHistory: raftResetHistory,
	}

	// Run diagnostics
	results, err := debug.RunRaftDiagnostics(rc, config)
	if err != nil {
		logger.Error("Raft diagnostics failed", zap.Error(err))
		return err
	}

	// Display results (already logged via structured logging in pkg/consul/debug)
	logger.Info("Raft diagnostics completed",
		zap.Int("checks_run", len(results.Checks)),
		zap.Int("critical_issues", results.CriticalCount),
		zap.Int("warnings", results.WarningCount))

	if results.CriticalCount > 0 {
		logger.Error("Critical Raft issues detected - Consul cannot function properly",
			zap.Int("critical_count", results.CriticalCount))
		return nil // Don't return error - we already logged everything
	}

	if results.WarningCount > 0 {
		logger.Warn("Raft warnings detected - should be addressed",
			zap.Int("warning_count", results.WarningCount))
	}

	return nil
}
