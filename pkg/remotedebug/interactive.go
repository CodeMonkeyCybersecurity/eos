package remotedebug

import (
	"fmt"
	"strings"
	"time"
	
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// InteractiveTroubleshooter provides guided troubleshooting
type InteractiveTroubleshooter struct {
	rc       *eos_io.RuntimeContext
	client   *SSHClient
	sudoPass string
}

// NewInteractiveTroubleshooter creates a new interactive troubleshooter
func NewInteractiveTroubleshooter(rc *eos_io.RuntimeContext, client *SSHClient, sudoPass string) *InteractiveTroubleshooter {
	return &InteractiveTroubleshooter{
		rc:       rc,
		client:   client,
		sudoPass: sudoPass,
	}
}

// Start begins the interactive troubleshooting session
func (it *InteractiveTroubleshooter) Start() error {
	logger := otelzap.Ctx(it.rc.Ctx)
	
	logger.Info("Starting interactive troubleshooting session")
	fmt.Println("\n=== Remote System Troubleshooter ===")
	fmt.Println("I'll help you diagnose and fix system issues interactively.")
	
	for {
		fmt.Println("\nWhat issue are you experiencing?")
		fmt.Println("1. SSH connection issues")
		fmt.Println("2. Disk space problems")
		fmt.Println("3. High memory usage")
		fmt.Println("4. Service not running")
		fmt.Println("5. System performance issues")
		fmt.Println("6. Run full diagnostics")
		fmt.Println("7. Exit")
		
		logger.Info("terminal prompt: Select issue type (1-7)")
		choice, err := eos_io.PromptInput(it.rc, "Select option (1-7): ", "menu_choice")
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}
		
		choice = strings.TrimSpace(choice)
		logger.Info("User selected option", zap.String("choice", choice))
		
		switch choice {
		case "1":
			if err := it.troubleshootSSH(); err != nil {
				return err
			}
		case "2":
			if err := it.troubleshootDiskSpace(); err != nil {
				return err
			}
		case "3":
			if err := it.troubleshootMemory(); err != nil {
				return err
			}
		case "4":
			if err := it.troubleshootService(); err != nil {
				return err
			}
		case "5":
			if err := it.troubleshootPerformance(); err != nil {
				return err
			}
		case "6":
			if err := it.runFullDiagnostics(); err != nil {
				return err
			}
		case "7":
			fmt.Println("Exiting troubleshooter. Goodbye!")
			return nil
		default:
			fmt.Println("Invalid option. Please select 1-7.")
		}
	}
}

// troubleshootSSH diagnoses SSH-related issues
func (it *InteractiveTroubleshooter) troubleshootSSH() error {
	logger := otelzap.Ctx(it.rc.Ctx)
	
	fmt.Println("\n=== SSH Troubleshooting ===")
	logger.Info("Starting SSH troubleshooting")
	
	// Check current SSH connections
	fmt.Println("\nChecking active SSH connections...")
	cmd := "ss -ant | grep -E ':22\\s' | wc -l"
	output, err := it.client.ExecuteCommand(cmd, false)
	if err == nil {
		connCount := strings.TrimSpace(output)
		fmt.Printf("✓ Active SSH connections: %s\n", connCount)
		
		if count, _ := fmt.Sscanf(connCount, "%d", new(int)); count > 50 {
			fmt.Println("⚠️  High number of SSH connections detected!")
			fmt.Println("   This might indicate connection flooding or misconfiguration.")
			
			logger.Info("terminal prompt: Check connection details?")
			if it.askYesNo("Would you like to see connection details?") {
				detailCmd := "ss -ant | grep -E ':22\\s' | head -20"
				details, _ := it.client.ExecuteCommand(detailCmd, false)
				fmt.Printf("\nConnection details:\n%s\n", details)
			}
		}
	}
	
	// Check SSH daemon status
	fmt.Println("\nChecking SSH daemon status...")
	statusCmd := "systemctl is-active sshd || systemctl is-active ssh"
	status, err := it.client.ExecuteCommand(statusCmd, false)
	if err != nil || !strings.Contains(status, "active") {
		fmt.Println("✗ SSH daemon is not active!")
		logger.Info("SSH daemon not active", zap.String("status", status))
		
		// Get more details
		detailCmd := "systemctl status sshd || systemctl status ssh"
		details, _ := it.client.ExecuteCommand(detailCmd, true)
		fmt.Printf("\nService status:\n%s\n", details)
		
		logger.Info("terminal prompt: Restart SSH service?")
		if it.askYesNo("Would you like to restart the SSH service?") {
			restartCmd := "systemctl restart sshd || systemctl restart ssh"
			if _, err := it.client.ExecuteCommand(restartCmd, true); err != nil {
				fmt.Printf("✗ Failed to restart SSH: %v\n", err)
			} else {
				fmt.Println("✓ SSH service restarted successfully")
			}
		}
	} else {
		fmt.Println("✓ SSH daemon is active")
	}
	
	// Check for failed login attempts
	fmt.Println("\nChecking for failed login attempts...")
	failedCmd := "journalctl -u sshd -u ssh --since '1 hour ago' | grep -i 'failed\\|error' | wc -l"
	failedOutput, _ := it.client.ExecuteCommand(failedCmd, true)
	if failedCount, _ := fmt.Sscanf(strings.TrimSpace(failedOutput), "%d", new(int)); failedCount > 10 {
		fmt.Printf("⚠️  Found %d failed login attempts in the last hour\n", failedCount)
		
		logger.Info("terminal prompt: Check fail2ban status?")
		if it.askYesNo("Would you like to check fail2ban status?") {
			f2bCmd := "fail2ban-client status sshd 2>/dev/null || echo 'fail2ban not installed'"
			f2bOutput, _ := it.client.ExecuteCommand(f2bCmd, true)
			fmt.Printf("\nfail2ban status:\n%s\n", f2bOutput)
		}
	}
	
	return nil
}

// troubleshootDiskSpace diagnoses disk space issues
func (it *InteractiveTroubleshooter) troubleshootDiskSpace() error {
	logger := otelzap.Ctx(it.rc.Ctx)
	
	fmt.Println("\n=== Disk Space Troubleshooting ===")
	logger.Info("Starting disk space troubleshooting")
	
	// Get disk usage
	collector := NewDiagnosticCollector(it.client, it.sudoPass)
	diskUsage, err := collector.getDiskUsage()
	if err != nil {
		return fmt.Errorf("failed to get disk usage: %w", err)
	}
	
	// Display disk usage
	fmt.Println("\nDisk Usage Summary:")
	criticalDisks := []DiskInfo{}
	
	for _, disk := range diskUsage {
		status := "✓"
		if disk.UsePercent >= 90 {
			status = "✗"
			criticalDisks = append(criticalDisks, disk)
		} else if disk.UsePercent >= 80 {
			status = "⚠️"
		}
		
		fmt.Printf("%s %s: %.1f%% used (%.2f GB free)\n", 
			status, disk.Mount, disk.UsePercent, 
			float64(disk.Available)/(1024*1024*1024))
	}
	
	if len(criticalDisks) > 0 {
		fmt.Println("\n🔴 CRITICAL: One or more disks are nearly full!")
		
		logger.Info("terminal prompt: Run emergency cleanup?")
		if it.askYesNo("Would you like to run emergency disk cleanup?") {
			fixer := NewAutomatedFixer(it.client, it.sudoPass, false)
			
			// Create minimal report for fixer
			report := &SystemReport{
				DiskUsage: diskUsage,
			}
			
			action := fixer.fixCriticalDiskSpace(report)
			fmt.Printf("\n%s\n", action.Message)
			
			if action.Success {
				fmt.Printf("✓ Freed approximately %.2f GB\n", float64(action.SpaceFreed)/(1024*1024*1024))
			}
		}
	} else {
		logger.Info("terminal prompt: Find large files?")
		if it.askYesNo("\nWould you like to find large files and directories?") {
			fmt.Println("\nSearching for large files...")
			
			// Find large files
			largeFiles, _ := collector.findLargeFiles()
			if len(largeFiles) > 0 {
				fmt.Println("\nLargest files:")
				for i, file := range largeFiles {
					if i >= 10 {
						break
					}
					fmt.Printf("  %.2f GB: %s\n", float64(file.Size)/(1024*1024*1024), file.Path)
				}
			}
			
			// Find large directories
			fmt.Println("\nSearching for large directories...")
			largeDirs, _ := collector.findLargeDirectories()
			if len(largeDirs) > 0 {
				fmt.Println("\nLargest directories:")
				count := 0
				for path, size := range largeDirs {
					if count >= 10 {
						break
					}
					fmt.Printf("  %.2f GB: %s\n", float64(size)/(1024*1024*1024), path)
					count++
				}
			}
		}
	}
	
	return nil
}

// troubleshootMemory diagnoses memory issues
func (it *InteractiveTroubleshooter) troubleshootMemory() error {
	logger := otelzap.Ctx(it.rc.Ctx)
	
	fmt.Println("\n=== Memory Troubleshooting ===")
	logger.Info("Starting memory troubleshooting")
	
	// Get memory info
	cmd := "free -h"
	output, err := it.client.ExecuteCommand(cmd, false)
	if err != nil {
		return fmt.Errorf("failed to get memory info: %w", err)
	}
	
	fmt.Printf("\nMemory Usage:\n%s\n", output)
	
	// Get top memory consumers
	fmt.Println("\nTop memory-consuming processes:")
	topCmd := "ps aux --sort=-%mem | head -10"
	topOutput, _ := it.client.ExecuteCommand(topCmd, false)
	
	lines := strings.Split(topOutput, "\n")
	for i, line := range lines {
		if i == 0 {
			// Header
			fmt.Println("USER       PID  %CPU  %MEM    VSZ   RSS COMMAND")
		} else if line != "" {
			fields := strings.Fields(line)
			if len(fields) >= 11 {
				fmt.Printf("%-10s %-5s %5s %5s %7s %5s %s\n",
					fields[0], fields[1], fields[2], fields[3], 
					fields[4], fields[5], strings.Join(fields[10:], " "))
			}
		}
	}
	
	// Check for OOM killer activity
	fmt.Println("\nChecking for OOM killer activity...")
	oomCmd := "dmesg | grep -i 'killed process' | tail -5"
	oomOutput, _ := it.client.ExecuteCommand(oomCmd, true)
	if oomOutput != "" {
		fmt.Println("⚠️  OOM killer has been active!")
		fmt.Printf("%s\n", oomOutput)
	} else {
		fmt.Println("✓ No recent OOM killer activity")
	}
	
	logger.Info("terminal prompt: Clear caches?")
	if it.askYesNo("\nWould you like to clear system caches to free memory?") {
		clearCmd := "sync && echo 3 > /proc/sys/vm/drop_caches"
		if _, err := it.client.ExecuteCommand(clearCmd, true); err != nil {
			fmt.Printf("✗ Failed to clear caches: %v\n", err)
		} else {
			fmt.Println("✓ System caches cleared")
			
			// Show new memory status
			newOutput, _ := it.client.ExecuteCommand("free -h", false)
			fmt.Printf("\nMemory after clearing caches:\n%s\n", newOutput)
		}
	}
	
	return nil
}

// troubleshootService diagnoses service issues
func (it *InteractiveTroubleshooter) troubleshootService() error {
	logger := otelzap.Ctx(it.rc.Ctx)
	
	fmt.Println("\n=== Service Troubleshooting ===")
	logger.Info("Starting service troubleshooting")
	
	logger.Info("terminal prompt: Enter service name")
	serviceName, err := eos_io.PromptInput(it.rc, "Enter service name to check: ", "service_name")
	if err != nil {
		return fmt.Errorf("failed to read service name: %w", err)
	}
	
	serviceName = strings.TrimSpace(serviceName)
	if serviceName == "" {
		fmt.Println("No service name provided")
		return nil
	}
	
	// Check service status
	fmt.Printf("\nChecking status of %s...\n", serviceName)
	statusCmd := fmt.Sprintf("systemctl status %s", serviceName)
	statusOutput, err := it.client.ExecuteCommand(statusCmd, false)
	
	if err != nil {
		fmt.Printf("✗ Service %s not found or error checking status\n", serviceName)
		return nil
	}
	
	fmt.Printf("%s\n", statusOutput)
	
	// Check if service is active
	isActiveCmd := fmt.Sprintf("systemctl is-active %s", serviceName)
	isActive, _ := it.client.ExecuteCommand(isActiveCmd, false)
	isActive = strings.TrimSpace(isActive)
	
	if isActive != "active" {
		fmt.Printf("\n⚠️  Service %s is not active (status: %s)\n", serviceName, isActive)
		
		// Check logs
		logger.Info("terminal prompt: View service logs?")
		if it.askYesNo("Would you like to view recent logs?") {
			logCmd := fmt.Sprintf("journalctl -u %s -n 50 --no-pager", serviceName)
			logs, _ := it.client.ExecuteCommand(logCmd, true)
			fmt.Printf("\nRecent logs for %s:\n%s\n", serviceName, logs)
		}
		
		// Offer to start/restart
		logger.Info("terminal prompt: Start/restart service?")
		action := "start"
		if isActive == "failed" {
			action = "restart"
		}
		
		if it.askYesNo(fmt.Sprintf("Would you like to %s the service?", action)) {
			actionCmd := fmt.Sprintf("systemctl %s %s", action, serviceName)
			if _, err := it.client.ExecuteCommand(actionCmd, true); err != nil {
				fmt.Printf("✗ Failed to %s service: %v\n", action, err)
			} else {
				fmt.Printf("✓ Service %s command executed\n", action)
				
				// Verify
				time.Sleep(2 * time.Second)
				newStatus, _ := it.client.ExecuteCommand(isActiveCmd, false)
				if strings.TrimSpace(newStatus) == "active" {
					fmt.Printf("✓ Service %s is now active\n", serviceName)
				} else {
					fmt.Printf("⚠️  Service %s is still not active\n", serviceName)
				}
			}
		}
	} else {
		fmt.Printf("✓ Service %s is active and running\n", serviceName)
	}
	
	return nil
}

// troubleshootPerformance diagnoses performance issues
func (it *InteractiveTroubleshooter) troubleshootPerformance() error {
	logger := otelzap.Ctx(it.rc.Ctx)
	
	fmt.Println("\n=== Performance Troubleshooting ===")
	logger.Info("Starting performance troubleshooting")
	
	// Check load average
	fmt.Println("\nChecking system load...")
	loadCmd := "uptime"
	loadOutput, _ := it.client.ExecuteCommand(loadCmd, false)
	fmt.Printf("%s\n", loadOutput)
	
	// Check CPU usage
	fmt.Println("\nTop CPU consumers:")
	cpuCmd := "ps aux --sort=-%cpu | head -10"
	cpuOutput, _ := it.client.ExecuteCommand(cpuCmd, false)
	
	lines := strings.Split(cpuOutput, "\n")
	for i, line := range lines {
		if i == 0 {
			fmt.Println("USER       PID  %CPU  %MEM COMMAND")
		} else if line != "" {
			fields := strings.Fields(line)
			if len(fields) >= 11 {
				fmt.Printf("%-10s %-5s %5s %5s %s\n",
					fields[0], fields[1], fields[2], fields[3],
					strings.Join(fields[10:], " "))
			}
		}
	}
	
	// Check I/O wait
	fmt.Println("\nChecking I/O wait...")
	ioCmd := "iostat -x 1 2 | tail -n +7"
	ioOutput, _ := it.client.ExecuteCommand(ioCmd, false)
	if ioOutput != "" {
		fmt.Printf("%s\n", ioOutput)
	} else {
		fmt.Println("iostat not available - skipping I/O analysis")
	}
	
	// Check for blocked processes
	fmt.Println("\nChecking for blocked processes...")
	blockedCmd := "ps aux | grep ' D ' | grep -v grep | wc -l"
	blockedOutput, _ := it.client.ExecuteCommand(blockedCmd, false)
	blockedCount, _ := fmt.Sscanf(strings.TrimSpace(blockedOutput), "%d", new(int))
	
	if blockedCount > 0 {
		fmt.Printf("⚠️  Found %d processes in uninterruptible sleep (D state)\n", blockedCount)
		fmt.Println("   This usually indicates I/O problems or hardware issues")
		
		logger.Info("terminal prompt: Show blocked processes?")
		if it.askYesNo("Would you like to see the blocked processes?") {
			detailCmd := "ps aux | grep ' D ' | grep -v grep"
			details, _ := it.client.ExecuteCommand(detailCmd, false)
			fmt.Printf("\n%s\n", details)
		}
	} else {
		fmt.Println("✓ No blocked processes detected")
	}
	
	return nil
}

// runFullDiagnostics runs comprehensive diagnostics
func (it *InteractiveTroubleshooter) runFullDiagnostics() error {
	logger := otelzap.Ctx(it.rc.Ctx)
	
	fmt.Println("\n=== Running Full System Diagnostics ===")
	logger.Info("Running full system diagnostics")
	
	// Create diagnostic collector
	collector := NewDiagnosticCollector(it.client, it.sudoPass)
	
	fmt.Println("Collecting system information...")
	report, err := collector.CollectDiagnostics(DiagnosticOptions{
		CheckType: "all",
	})
	
	if err != nil {
		return fmt.Errorf("diagnostics failed: %w", err)
	}
	
	// Analyze results
	analyzer := NewAnalyzer(report)
	report.Issues = analyzer.AnalyzeIssues()
	report.Warnings = analyzer.AnalyzeWarnings()
	report.Summary = analyzer.GenerateSummary()
	
	// Display results
	printer := NewReportPrinter()
	printer.PrintDiagnosticReport(report)
	
	// Offer to fix issues
	if len(report.Issues) > 0 {
		logger.Info("terminal prompt: Attempt fixes?")
		if it.askYesNo("\nWould you like to attempt to fix detected issues?") {
			fixer := NewAutomatedFixer(it.client, it.sudoPass, false)
			fixReport, err := fixer.FixIssues(report)
			if err != nil {
				fmt.Printf("✗ Fix process failed: %v\n", err)
			} else {
				printer.PrintFixReport(fixReport)
			}
		}
	}
	
	return nil
}

// askYesNo prompts for a yes/no answer
func (it *InteractiveTroubleshooter) askYesNo(question string) bool {
	logger := otelzap.Ctx(it.rc.Ctx)
	
	logger.Info("terminal prompt: " + question)
	answer, err := eos_io.PromptInput(it.rc, fmt.Sprintf("%s (y/n): ", question), "yes_no")
	if err != nil {
		return false
	}
	
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes"
}