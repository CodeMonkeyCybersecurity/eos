// cmd/debug/ceph.go
package debug

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/ceph"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

var (
	cephDebugVerbose bool
	cephDebugFix     bool
	cephDebugLogs    int
)

var cephDebugCmd = &cobra.Command{
	Use:   "ceph",
	Short: "Debug Ceph cluster issues and diagnose problems",
	Long: `Debug Ceph provides comprehensive troubleshooting for Ceph storage cluster issues.

Diagnostic checks performed:
1. Ceph binary verification (ceph, ceph-mon, ceph-mgr, ceph-osd)
2. Cluster connectivity and authentication
3. MON quorum status and health
4. MGR daemon status
5. OSD status (up/down, in/out)
6. Storage capacity and usage
7. PG (Placement Group) status
8. Network configuration
9. Clock synchronization (NTP/Chrony)
10. Log analysis (errors, warnings, critical issues)
11. Common misconfigurations

The debug command provides actionable recommendations for fixing issues.

FLAGS:
  --verbose         Show detailed diagnostic output
  --fix             Attempt to automatically fix common issues
  --logs N          Number of log lines to analyze (default: 50)

EXAMPLES:
  # Basic diagnostics
  sudo eos debug ceph

  # Verbose output with more details
  sudo eos debug ceph --verbose

  # Auto-fix common issues
  sudo eos debug ceph --fix

  # Analyze more log lines
  sudo eos debug ceph --logs 200

CODE MONKEY CYBERSECURITY - "Cybersecurity. With humans."`,

	RunE: eos_cli.WrapDebug("ceph", runCephDebug),
}

func init() {
	cephDebugCmd.Flags().BoolVarP(&cephDebugVerbose, "verbose", "v", false,
		"Show detailed diagnostic output")
	cephDebugCmd.Flags().BoolVar(&cephDebugFix, "fix", false,
		"Attempt to automatically fix common issues")
	cephDebugCmd.Flags().IntVar(&cephDebugLogs, "logs", 50,
		"Number of log lines to analyze")

	debugCmd.AddCommand(cephDebugCmd)
}

func runCephDebug(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("================================================================================")
	logger.Info("Ceph Cluster Diagnostics - Deep Debug Mode")
	logger.Info("================================================================================")
	logger.Info("")

	// Run all diagnostics via pkg/ceph
	opts := ceph.DiagnosticOptions{
		Verbose:  cephDebugVerbose,
		Fix:      cephDebugFix,
		LogLines: cephDebugLogs,
	}

	results, clusterReachable := ceph.RunFullDiagnostics(logger, opts)

	// Collect all issues from results
	criticalIssues := []ceph.Issue{}
	warnings := []ceph.Issue{}

	for _, result := range results {
		for _, issue := range result.Issues {
			switch issue.Severity {
			case "critical":
				criticalIssues = append(criticalIssues, issue)
			case "warning":
				warnings = append(warnings, issue)
			}
		}
	}

	// Summary
	logger.Info("================================================================================")
	logger.Info("Diagnostics Summary")
	logger.Info("================================================================================")

	if len(criticalIssues) == 0 && len(warnings) == 0 {
		logger.Info("✓ No critical issues detected - cluster appears healthy!")
	} else {
		if len(criticalIssues) > 0 {
			logger.Warn(fmt.Sprintf("❌ Found %d critical issue(s) requiring attention", len(criticalIssues)))
			logger.Info("")
			logger.Info("  CRITICAL ISSUES:")
			for i, issue := range criticalIssues {
				logger.Info(fmt.Sprintf("  %d. %s: %s", i+1, issue.Component, issue.Description))
				if issue.Impact != "" {
					logger.Info(fmt.Sprintf("     Impact: %s", issue.Impact))
				}
			}
		}

		if len(warnings) > 0 {
			logger.Info("")
			logger.Info("  WARNINGS:")
			for i, issue := range warnings {
				logger.Info(fmt.Sprintf("  %d. %s: %s", i+1, issue.Component, issue.Description))
			}
		}

		// Generate prioritized next steps
		logger.Info("")
		logger.Info("Next Steps (Prioritized):")

		if len(criticalIssues) > 0 {
			// Show remediation for highest priority critical issue
			highestPriority := criticalIssues[0]
			logger.Info(fmt.Sprintf("Fix CRITICAL issue: %s", highestPriority.Description))
			for i, step := range highestPriority.Remediation {
				logger.Info(fmt.Sprintf("  %d. %s", i+1, step))
			}
		} else if !clusterReachable {
			logger.Info("  1. Check if Ceph services are enabled: systemctl list-unit-files | grep ceph")
			logger.Info("  2. Start Ceph services: systemctl start ceph.target")
			logger.Info("  3. Check service logs: journalctl -u ceph-mon@* -xe")
			logger.Info("  4. Verify configuration: cat /etc/ceph/ceph.conf")
			logger.Info("  5. Check keyring permissions: ls -la /etc/ceph/*.keyring")
		} else {
			logger.Info("  1. Review warnings above for specific issues")
			logger.Info("  2. Use 'ceph health detail' for more information")
		}

		logger.Info("")
		logger.Info("General Recommendations:")
		logger.Info("  1. Review all error messages above for context")
		logger.Info("  2. Check Ceph documentation: https://docs.ceph.com/")
		logger.Info("  3. Check logs: journalctl -u 'ceph*' --since '1 hour ago'")
		logger.Info("  4. Review file permissions in /var/lib/ceph/ and /etc/ceph/")
		if !cephDebugFix {
			logger.Info("  5. Run with --fix flag to auto-fix common issues")
		}
	}
	logger.Info("")

	return nil
}
