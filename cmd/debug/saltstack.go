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
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var debugSaltstackCmd = &cobra.Command{
	Use:   "saltstack",
	Short: "Debug and diagnose SaltStack issues",
	Long: `Comprehensive SaltStack debugging tool that checks installation, configuration, 
and service status. Provides actionable recommendations for fixing issues.

This command will:
- Check if SaltStack is installed (salt-master and/or salt-minion)
- Verify configuration files and syntax
- Check service status and logs
- Test Salt communication
- Verify pillar and state files
- Provide fix recommendations`,
	Aliases: []string{"salt"},
	RunE: eos_cli.Wrap(runDebugSaltstack),
}

func init() {
	debugCmd.AddCommand(debugSaltstackCmd)
	
	debugSaltstackCmd.Flags().Bool("fix", false, "Attempt to automatically fix issues")
	debugSaltstackCmd.Flags().Bool("verbose", false, "Show detailed logs and configuration")
	debugSaltstackCmd.Flags().Bool("master", false, "Check Salt Master specific issues")
	debugSaltstackCmd.Flags().Bool("minion", false, "Check Salt Minion specific issues")
	debugSaltstackCmd.Flags().Bool("test-states", false, "Test applying highstate")
}

func runDebugSaltstack(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	autoFix, _ := cmd.Flags().GetBool("fix")
	verbose, _ := cmd.Flags().GetBool("verbose")
	checkMaster, _ := cmd.Flags().GetBool("master")
	checkMinion, _ := cmd.Flags().GetBool("minion")
	testStates, _ := cmd.Flags().GetBool("test-states")
	
	// If neither specified, check both
	if !checkMaster && !checkMinion {
		checkMaster = true
		checkMinion = true
	}
	
	logger.Info("Starting SaltStack diagnostic check")
	
	// Check if running as root for fixes
	if os.Geteuid() != 0 && autoFix {
		return eos_err.NewUserError("debug saltstack --fix requires root privileges, please run with sudo")
	}
	
	issues := []string{}
	warnings := []string{}
	fixes := []string{}
	
	// 1. Check if salt-call is installed (minimum requirement)
	logger.Info("Checking SaltStack installation")
	saltCallPath, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"salt-call"},
		Capture: true,
	})
	
	if err != nil {
		issues = append(issues, "salt-call is not installed (core SaltStack component)")
		fixes = append(fixes, "Run: eos create saltstack")
		displaySaltDiagnosticReport(logger, issues, warnings, fixes, nil)
		return fmt.Errorf("SaltStack not installed")
	}
	
	saltCallPath = strings.TrimSpace(saltCallPath)
	logger.Info("terminal prompt: ✓ salt-call binary found", zap.String("path", saltCallPath))
	
	// 2. Check Salt version
	version, err := execute.Run(rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"--version"},
		Capture: true,
	})
	if err == nil {
		logger.Info("terminal prompt: ✓ SaltStack version", zap.String("version", strings.TrimSpace(strings.Split(version, "\n")[0])))
	}
	
	// 3. Check if running masterless or master-minion
	configMode := "unknown"
	isMasterless := false
	
	// Check for masterless configuration
	if _, err := os.Stat("/etc/salt/minion.d/masterless.conf"); err == nil {
		configMode = "masterless"
		isMasterless = true
		logger.Info("terminal prompt: ✓ Running in masterless mode")
	} else {
		// Check if minion is configured with master
		minionConfig, err := execute.Run(rc.Ctx, execute.Options{
			Command: "grep",
			Args:    []string{"-E", "^master:", "/etc/salt/minion"},
			Capture: true,
		})
		if err == nil && strings.TrimSpace(minionConfig) != "" {
			configMode = "master-minion"
			logger.Info("terminal prompt: ✓ Running in master-minion mode")
		}
	}
	
	// 4. Check configuration files
	logger.Info("Checking SaltStack configuration")
	configFiles := map[string]string{
		"/etc/salt/minion":     "Minion configuration",
		"/etc/salt/master":     "Master configuration",
		"/etc/salt/minion_id":  "Minion ID file",
	}
	
	configsFound := 0
	for path, desc := range configFiles {
		if _, err := os.Stat(path); err == nil {
			configsFound++
			logger.Info("terminal prompt: ✓ Found", zap.String("config", desc), zap.String("path", path))
			
			// Check config syntax if verbose
			if verbose && (strings.Contains(path, "minion") || strings.Contains(path, "master")) {
				_, err := execute.Run(rc.Ctx, execute.Options{
					Command: "salt-call",
					Args:    []string{"--local", "config.get", "test_config"},
					Capture: true,
				})
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("Configuration syntax may have issues in %s", path))
				}
			}
		}
	}
	
	if configsFound == 0 {
		issues = append(issues, "No SaltStack configuration files found")
		fixes = append(fixes, "Run: eos create saltstack --configure")
	}
	
	// 5. Check Salt Master service (if applicable)
	if checkMaster && !isMasterless {
		logger.Info("Checking Salt Master service")
		
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "which",
			Args:    []string{"salt-master"},
			Capture: true,
		}); err == nil {
			// Check service status
			statusOutput, err := execute.Run(rc.Ctx, execute.Options{
				Command: "systemctl",
				Args:    []string{"is-active", "salt-master"},
				Capture: true,
			})
			
			if err != nil || strings.TrimSpace(statusOutput) != "active" {
				issues = append(issues, "Salt Master service is not running")
				fixes = append(fixes, "Run: sudo systemctl start salt-master")
			} else {
				logger.Info("terminal prompt: ✓ Salt Master service is active")
			}
		} else if configMode == "master-minion" {
			warnings = append(warnings, "System configured for master-minion but salt-master not installed")
		}
	}
	
	// 6. Check Salt Minion service
	if checkMinion {
		logger.Info("Checking Salt Minion service")
		statusOutput, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"is-active", "salt-minion"},
			Capture: true,
		})
		
		if err != nil || strings.TrimSpace(statusOutput) != "active" {
			if !isMasterless {
				issues = append(issues, "Salt Minion service is not running")
				fixes = append(fixes, "Run: sudo systemctl start salt-minion")
			} else {
				logger.Info("terminal prompt: ℹ Salt Minion service not needed in masterless mode")
			}
		} else {
			logger.Info("terminal prompt: ✓ Salt Minion service is active")
		}
	}
	
	// 7. Check Salt directories
	logger.Info("Checking Salt directories")
	saltDirs := map[string]string{
		"/srv/salt":           "Salt states directory",
		"/srv/pillar":         "Salt pillar directory",
		"/etc/salt/pki":       "Salt PKI directory",
		"/var/cache/salt":     "Salt cache directory",
		"/var/log/salt":       "Salt log directory",
	}
	
	for dir, desc := range saltDirs {
		if info, err := os.Stat(dir); err == nil {
			if info.IsDir() {
				logger.Info("terminal prompt: ✓", zap.String("directory", desc), zap.String("path", dir))
			}
		} else {
			warnings = append(warnings, fmt.Sprintf("%s does not exist: %s", desc, dir))
			if autoFix {
				os.MkdirAll(dir, 0755)
			}
		}
	}
	
	// 8. Test Salt functionality
	logger.Info("Testing Salt functionality")
	
	// Test basic salt-call
	testOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"--local", "test.ping"},
		Capture: true,
	})
	
	if err != nil || !strings.Contains(testOutput, "True") {
		issues = append(issues, "Salt test.ping failed - Salt is not functioning properly")
		fixes = append(fixes, "Check Salt logs: sudo journalctl -u salt-minion -n 50")
	} else {
		logger.Info("terminal prompt: ✓ Salt test.ping successful")
	}
	
	// 9. Check Salt states if requested
	if testStates {
		logger.Info("Testing Salt states")
		
		// List available states
		statesOutput, err := execute.Run(rc.Ctx, execute.Options{
			Command: "salt-call",
			Args:    []string{"--local", "state.show_top"},
			Capture: true,
		})
		
		if err != nil {
			warnings = append(warnings, "Could not list Salt states")
		} else if verbose {
			logger.Info("terminal prompt: Available Salt states:", zap.String("states", statesOutput))
		}
		
		// Test highstate in test mode
		if _, err := os.Stat("/srv/salt/top.sls"); err == nil {
			logger.Info("Testing highstate (dry-run)")
			_, err := execute.Run(rc.Ctx, execute.Options{
				Command: "salt-call",
				Args:    []string{"--local", "state.highstate", "test=True"},
				Capture: true,
			})
			
			if err != nil {
				warnings = append(warnings, "Highstate test failed - check state files")
			} else {
				logger.Info("terminal prompt: ✓ Highstate test passed")
			}
		}
	}
	
	// 10. Check recent logs for errors
	if verbose {
		logger.Info("Checking Salt logs for errors")
		
		services := []string{"salt-master", "salt-minion"}
		for _, service := range services {
			logs, err := execute.Run(rc.Ctx, execute.Options{
				Command: "journalctl",
				Args:    []string{"-u", service, "-n", "30", "--no-pager"},
				Capture: true,
			})
			
			if err == nil && strings.TrimSpace(logs) != "" {
				errorCount := strings.Count(strings.ToLower(logs), "error")
				if errorCount > 0 {
					warnings = append(warnings, fmt.Sprintf("Found %d error(s) in %s logs", errorCount, service))
				}
			}
		}
	}
	
	// Display diagnostic report
	diagnostics := map[string]interface{}{
		"installed":       saltCallPath != "",
		"mode":            configMode,
		"configs_found":   configsFound,
		"test_ping":       err == nil && strings.Contains(testOutput, "True"),
		"is_masterless":   isMasterless,
	}
	
	displaySaltDiagnosticReport(logger, issues, warnings, fixes, diagnostics)
	
	// Auto-fix if requested
	if autoFix && len(issues) > 0 {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: 🔧 ATTEMPTING AUTO-FIX...")
		
		for _, fix := range fixes {
			if strings.Contains(fix, "systemctl start salt-master") {
				logger.Info("terminal prompt: Starting Salt Master service...")
				if _, err := execute.Run(rc.Ctx, execute.Options{
					Command: "systemctl",
					Args:    []string{"start", "salt-master"},
				}); err == nil {
					logger.Info("terminal prompt: ✓ Salt Master service started")
					time.Sleep(2 * time.Second)
				}
			}
			
			if strings.Contains(fix, "systemctl start salt-minion") {
				logger.Info("terminal prompt: Starting Salt Minion service...")
				if _, err := execute.Run(rc.Ctx, execute.Options{
					Command: "systemctl",
					Args:    []string{"start", "salt-minion"},
				}); err == nil {
					logger.Info("terminal prompt: ✓ Salt Minion service started")
					time.Sleep(2 * time.Second)
				}
			}
		}
		
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Auto-fix completed. Re-run 'eos debug saltstack' to verify.")
	}
	
	if len(issues) > 0 {
		return fmt.Errorf("SaltStack has %d critical issue(s) that need resolution", len(issues))
	}
	
	return nil
}

func displaySaltDiagnosticReport(logger otelzap.LoggerWithCtx, issues, warnings, fixes []string, diagnostics map[string]interface{}) {
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ╔════════════════════════════════════════════════════════════════╗")
	logger.Info("terminal prompt: ║              SALTSTACK DIAGNOSTIC REPORT                       ║")
	logger.Info("terminal prompt: ╚════════════════════════════════════════════════════════════════╝")
	logger.Info("terminal prompt: ")
	
	if len(issues) > 0 {
		logger.Info("terminal prompt: ❌ CRITICAL ISSUES:")
		for _, issue := range issues {
			logger.Info("terminal prompt:", zap.String("issue", fmt.Sprintf("  • %s", issue)))
		}
		logger.Info("terminal prompt: ")
	}
	
	if len(warnings) > 0 {
		logger.Info("terminal prompt: ⚠️  WARNINGS:")
		for _, warning := range warnings {
			logger.Info("terminal prompt:", zap.String("warning", fmt.Sprintf("  • %s", warning)))
		}
		logger.Info("terminal prompt: ")
	}
	
	if len(fixes) > 0 {
		logger.Info("terminal prompt: 🔧 RECOMMENDED FIXES:")
		for i, fix := range fixes {
			logger.Info("terminal prompt:", zap.String("fix", fmt.Sprintf("  %d. %s", i+1, fix)))
		}
		logger.Info("terminal prompt: ")
	}
	
	if diagnostics != nil {
		logger.Info("terminal prompt: 📊 DIAGNOSTIC SUMMARY:")
		logger.Info("terminal prompt:", zap.String("summary", fmt.Sprintf("  • Installed: %v", diagnostics["installed"])))
		logger.Info("terminal prompt:", zap.String("summary", fmt.Sprintf("  • Configuration Mode: %v", diagnostics["mode"])))
		logger.Info("terminal prompt:", zap.String("summary", fmt.Sprintf("  • Config Files Found: %v", diagnostics["configs_found"])))
		logger.Info("terminal prompt:", zap.String("summary", fmt.Sprintf("  • Test Ping Success: %v", diagnostics["test_ping"])))
		logger.Info("terminal prompt:", zap.String("summary", fmt.Sprintf("  • Masterless Mode: %v", diagnostics["is_masterless"])))
		
		// Add file system roots check
		if roots, err := getSaltFileRoots(); err == nil && len(roots) > 0 {
			logger.Info("terminal prompt:", zap.String("summary", fmt.Sprintf("  • Salt File Roots: %s", strings.Join(roots, ", "))))
		}
		
		if roots, err := getSaltPillarRoots(); err == nil && len(roots) > 0 {
			logger.Info("terminal prompt:", zap.String("summary", fmt.Sprintf("  • Salt Pillar Roots: %s", strings.Join(roots, ", "))))
		}
	}
	
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ════════════════════════════════════════════════════════════════")
	
	if len(issues) == 0 && len(warnings) == 0 {
		logger.Info("terminal prompt: ✅ SaltStack appears to be healthy!")
	} else if len(issues) == 0 {
		logger.Info("terminal prompt: ⚠️  SaltStack has minor issues but should be functional")
	} else {
		logger.Info("terminal prompt: ❌ SaltStack has critical issues that need resolution")
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Run 'eos debug saltstack --fix' to attempt automatic fixes")
	}
}

// Helper functions to get Salt configuration
func getSaltFileRoots() ([]string, error) {
	output, err := execute.Run(nil, execute.Options{
		Command: "salt-call",
		Args:    []string{"--local", "config.get", "file_roots"},
		Capture: true,
	})
	
	if err != nil {
		return nil, err
	}
	
	roots := []string{}
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "- /") {
			root := strings.TrimSpace(strings.TrimPrefix(line, "-"))
			if root != "" && root != "local:" {
				roots = append(roots, root)
			}
		}
	}
	
	return roots, nil
}

func getSaltPillarRoots() ([]string, error) {
	output, err := execute.Run(nil, execute.Options{
		Command: "salt-call",
		Args:    []string{"--local", "config.get", "pillar_roots"},
		Capture: true,
	})
	
	if err != nil {
		return nil, err
	}
	
	roots := []string{}
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "- /") {
			root := strings.TrimSpace(strings.TrimPrefix(line, "-"))
			if root != "" && root != "local:" {
				roots = append(roots, root)
			}
		}
	}
	
	return roots, nil
}