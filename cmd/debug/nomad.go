package debug

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var debugNomadCmd = &cobra.Command{
	Use:   "nomad",
	Short: "Debug and diagnose Nomad issues",
	Long: `Comprehensive Nomad debugging tool that checks installation, configuration, 
and service status. Provides actionable recommendations for fixing issues.

This command will:
- Check if Nomad is installed
- Verify configuration files
- Check service status and logs
- Test connectivity
- Provide fix recommendations`,
	RunE: eos_cli.Wrap(runDebugNomad),
}

func init() {
	debugCmd.AddCommand(debugNomadCmd)

	debugNomadCmd.Flags().Bool("fix", false, "Attempt to automatically fix issues")
	debugNomadCmd.Flags().Bool("verbose", false, "Show detailed logs and configuration")
}

func runDebugNomad(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	autoFix, _ := cmd.Flags().GetBool("fix")
	verbose, _ := cmd.Flags().GetBool("verbose")

	logger.Info("Starting Nomad diagnostic check")

	// Check if running as root
	if os.Geteuid() != 0 && autoFix {
		return eos_err.NewUserError("debug nomad --fix requires root privileges, please run with sudo")
	}

	issues := []string{}
	warnings := []string{}
	fixes := []string{}

	// 1. Check if Nomad is installed
	logger.Info("Checking Nomad installation")
	nomadPath, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"nomad"},
		Capture: true,
	})

	if err != nil {
		issues = append(issues, "Nomad is not installed")
		fixes = append(fixes, "Run: eos create nomad")
		displayDiagnosticReport(logger, issues, warnings, fixes, nil)
		return fmt.Errorf("Nomad not installed")
	}

	nomadPath = strings.TrimSpace(nomadPath)
	logger.Info("terminal prompt: ✓ Nomad binary found", zap.String("path", nomadPath))

	// 2. Check Nomad version
	version, err := execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"version"},
		Capture: true,
	})
	if err == nil {
		logger.Info("terminal prompt: ✓ Nomad version", zap.String("version", strings.TrimSpace(strings.Split(version, "\n")[0])))
	}

	// 3. Check systemd service status
	logger.Info("Checking Nomad service status")
	statusOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"status", "nomad", "--no-pager"},
		Capture: true,
	})

	serviceActive := false
	serviceEnabled := false

	if err == nil {
		if strings.Contains(statusOutput, "Active: active") {
			serviceActive = true
			logger.Info("terminal prompt: ✓ Nomad service is active")
		} else {
			issues = append(issues, "Nomad service is not running")
			fixes = append(fixes, "Run: sudo systemctl start nomad")
		}

		if strings.Contains(statusOutput, "Loaded:") && strings.Contains(statusOutput, "enabled;") {
			serviceEnabled = true
			logger.Info("terminal prompt: ✓ Nomad service is enabled")
		} else {
			warnings = append(warnings, "Nomad service is not enabled (won't start on boot)")
			fixes = append(fixes, "Run: sudo systemctl enable nomad")
		}
	}

	// 4. Check configuration files
	logger.Info("Checking Nomad configuration")
	configPaths := []string{
		"/etc/nomad.d/nomad.hcl",
		"/etc/nomad.d/nomad.env",
		"/opt/nomad/nomad.hcl",
	}

	var configPath string
	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			configPath = path
			logger.Info("terminal prompt: ✓ Configuration file found", zap.String("path", path))
			break
		}
	}

	if configPath == "" {
		issues = append(issues, "No Nomad configuration file found")
		fixes = append(fixes, "Create configuration at /etc/nomad.d/nomad.hcl")
	}

	// 5. Check if Nomad port is accessible
	logger.Info("Checking Nomad port availability")
	portInUse := false

	// Check if something is listening on Nomad port
	ssOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ss",
		Args:    []string{"-tlnp"},
		Capture: true,
	})

	if err == nil && strings.Contains(ssOutput, fmt.Sprintf(":%d", shared.PortNomad)) {
		portInUse = true
		if serviceActive {
			logger.Info("terminal prompt: ✓ Nomad port is in use", zap.Int("port", shared.PortNomad))
		} else {
			issues = append(issues, fmt.Sprintf("Port %d is in use but Nomad service is not active", shared.PortNomad))
			fixes = append(fixes, "Check what's using the port: sudo lsof -i :"+fmt.Sprint(shared.PortNomad))
		}
	} else if serviceActive {
		warnings = append(warnings, fmt.Sprintf("Nomad service is active but not listening on port %d", shared.PortNomad))
	}

	// 6. Check recent logs for errors
	if serviceActive || verbose {
		logger.Info("Checking Nomad logs for errors")
		logs, err := execute.Run(rc.Ctx, execute.Options{
			Command: "journalctl",
			Args:    []string{"-u", "nomad", "-n", "50", "--no-pager"},
			Capture: true,
		})

		if err == nil {
			errorCount := strings.Count(strings.ToLower(logs), "error")
			if errorCount > 0 {
				warnings = append(warnings, fmt.Sprintf("Found %d error(s) in recent logs", errorCount))
				if verbose {
					logger.Info("terminal prompt: Recent log entries with errors:")
					for _, line := range strings.Split(logs, "\n") {
						if strings.Contains(strings.ToLower(line), "error") {
							logger.Info("terminal prompt:", zap.String("log", line))
						}
					}
				}
			} else {
				logger.Info("terminal prompt: ✓ No errors in recent logs")
			}
		}
	}

	// 7. Check Consul dependency
	logger.Info("Checking Consul dependency")
	consulPath, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"consul"},
		Capture: true,
	})

	if err != nil {
		issues = append(issues, "Consul is not installed (required for Nomad)")
		fixes = append(fixes, "Run: eos create consul")
	} else {
		// Check if Consul is running
		consulStatus, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"is-active", "consul"},
			Capture: true,
		})

		if err != nil || strings.TrimSpace(consulStatus) != "active" {
			issues = append(issues, "Consul is installed but not running")
			fixes = append(fixes, "Run: sudo systemctl start consul")
		} else {
			logger.Info("terminal prompt: ✓ Consul is installed and running")
		}
	}

	// 8. Test Nomad connectivity (if service is active)
	if serviceActive {
		logger.Info("Testing Nomad API connectivity")
		apiTest, err := execute.Run(rc.Ctx, execute.Options{
			Command: "nomad",
			Args:    []string{"server", "members"},
			Capture: true,
		})

		if err != nil {
			warnings = append(warnings, "Cannot connect to Nomad API")
			fixes = append(fixes, "Check Nomad configuration and firewall rules")
		} else {
			logger.Info("terminal prompt: ✓ Nomad API is responsive")
			if verbose {
				logger.Info("terminal prompt: Server members:", zap.String("output", strings.TrimSpace(apiTest)))
			}
		}
	}

	// Display diagnostic report
	diagnostics := map[string]interface{}{
		"installed":       nomadPath != "",
		"service_active":  serviceActive,
		"service_enabled": serviceEnabled,
		"port_in_use":     portInUse,
		"config_exists":   configPath != "",
		"consul_running":  consulPath != "" && strings.Contains(consulPath, "consul"),
	}

	displayDiagnosticReport(logger, issues, warnings, fixes, diagnostics)

	// Auto-fix if requested
	if autoFix && len(issues) > 0 {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt:  ATTEMPTING AUTO-FIX...")

		for i, fix := range fixes {
			if strings.Contains(fix, "systemctl start nomad") && !serviceActive {
				logger.Info("terminal prompt: Starting Nomad service...")
				if _, err := execute.Run(rc.Ctx, execute.Options{
					Command: "systemctl",
					Args:    []string{"start", "nomad"},
				}); err == nil {
					logger.Info("terminal prompt: ✓ Nomad service started")
					// Wait a moment for service to fully start
					time.Sleep(2 * time.Second)
				} else {
					logger.Error("terminal prompt: ✗ Failed to start Nomad service", zap.Error(err))
				}
			}

			if strings.Contains(fix, "systemctl enable nomad") && !serviceEnabled {
				logger.Info("terminal prompt: Enabling Nomad service...")
				if _, err := execute.Run(rc.Ctx, execute.Options{
					Command: "systemctl",
					Args:    []string{"enable", "nomad"},
				}); err == nil {
					logger.Info("terminal prompt: ✓ Nomad service enabled")
				}
			}

			if strings.Contains(fix, "systemctl start consul") {
				logger.Info("terminal prompt: Starting Consul service...")
				if _, err := execute.Run(rc.Ctx, execute.Options{
					Command: "systemctl",
					Args:    []string{"start", "consul"},
				}); err == nil {
					logger.Info("terminal prompt: ✓ Consul service started")
				}
			}

			// Skip auto-installation of missing services for safety
			if strings.Contains(fix, "eos create") {
				logger.Info("terminal prompt: ⚠ Manual action required", zap.Int("fix", i+1), zap.String("command", fix))
			}
		}

		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Auto-fix completed. Re-run 'eos debug nomad' to verify.")
	}

	// Don't return error for diagnostic command - we successfully diagnosed issues
	// Only return error if the diagnostic itself failed
	return nil
}

func displayDiagnosticReport(logger otelzap.LoggerWithCtx, issues, warnings, fixes []string, diagnostics map[string]interface{}) {
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ╔════════════════════════════════════════════════════════════════╗")
	logger.Info("terminal prompt: ║                 NOMAD DIAGNOSTIC REPORT                        ║")
	logger.Info("terminal prompt: ╚════════════════════════════════════════════════════════════════╝")
	logger.Info("terminal prompt: ")

	if len(issues) > 0 {
		logger.Info("terminal prompt:  CRITICAL ISSUES:")
		for _, issue := range issues {
			logger.Info("terminal prompt:", zap.String("issue", fmt.Sprintf("  • %s", issue)))
		}
		logger.Info("terminal prompt: ")
	}

	if len(warnings) > 0 {
		logger.Info("terminal prompt: WARNINGS:")
		for _, warning := range warnings {
			logger.Info("terminal prompt:", zap.String("warning", fmt.Sprintf("  • %s", warning)))
		}
		logger.Info("terminal prompt: ")
	}

	if len(fixes) > 0 {
		logger.Info("terminal prompt:  RECOMMENDED FIXES:")
		for i, fix := range fixes {
			logger.Info("terminal prompt:", zap.String("fix", fmt.Sprintf("  %d. %s", i+1, fix)))
		}
		logger.Info("terminal prompt: ")
	}

	if diagnostics != nil {
		logger.Info("terminal prompt:  DIAGNOSTIC SUMMARY:")
		logger.Info("terminal prompt:", zap.String("summary", fmt.Sprintf("  • Installed: %v", diagnostics["installed"])))
		logger.Info("terminal prompt:", zap.String("summary", fmt.Sprintf("  • Service Active: %v", diagnostics["service_active"])))
		logger.Info("terminal prompt:", zap.String("summary", fmt.Sprintf("  • Service Enabled: %v", diagnostics["service_enabled"])))
		logger.Info("terminal prompt:", zap.String("summary", fmt.Sprintf("  • Port In Use: %v", diagnostics["port_in_use"])))
		logger.Info("terminal prompt:", zap.String("summary", fmt.Sprintf("  • Config Exists: %v", diagnostics["config_exists"])))
		logger.Info("terminal prompt:", zap.String("summary", fmt.Sprintf("  • Consul Running: %v", diagnostics["consul_running"])))
	}

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ════════════════════════════════════════════════════════════════")

	if len(issues) == 0 && len(warnings) == 0 {
		logger.Info("terminal prompt:  Nomad appears to be healthy!")
	} else if len(issues) == 0 {
		logger.Info("terminal prompt: Nomad has minor issues but should be functional")
	} else {
		logger.Info("terminal prompt:  Nomad has critical issues that need resolution")
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Run 'eos debug nomad --fix' to attempt automatic fixes")
	}
}
