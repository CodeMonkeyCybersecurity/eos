// pkg/bootstrap/debug/checks_bootstrap.go
package debug

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CheckBootstrapPrerequisites verifies required system utilities are installed
func CheckBootstrapPrerequisites(rc *eos_io.RuntimeContext) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	result := CheckResult{Name: "Bootstrap Prerequisites"}

	checks := []struct {
		name     string
		required bool
		check    func() (bool, string)
	}{
		{"systemd", true, func() (bool, string) {
			_, err := exec.LookPath("systemctl")
			return err == nil, "systemctl binary"
		}},
		{"wget", true, func() (bool, string) {
			_, err := exec.LookPath("wget")
			return err == nil, "wget binary"
		}},
		{"curl", true, func() (bool, string) {
			_, err := exec.LookPath("curl")
			return err == nil, "curl binary"
		}},
		{"unzip", true, func() (bool, string) {
			_, err := exec.LookPath("unzip")
			return err == nil, "unzip binary"
		}},
		{"iptables", false, func() (bool, string) {
			_, err := exec.LookPath("iptables")
			return err == nil, "iptables binary"
		}},
	}

	allRequired := true
	for _, c := range checks {
		passed, detail := c.check()
		if passed {
			result.Details = append(result.Details, fmt.Sprintf("✓ %s: found (%s)", c.name, detail))
		} else {
			if c.required {
				result.Details = append(result.Details, fmt.Sprintf("✗ %s: MISSING (required)", c.name))
				allRequired = false
			} else {
				result.Details = append(result.Details, fmt.Sprintf("⚠ %s: missing (optional)", c.name))
			}
		}
	}

	if !allRequired {
		result.Status = "FAIL"
		result.Message = "Missing required prerequisites"
	} else {
		result.Status = "PASS"
		result.Message = "All required prerequisites present"
	}

	logger.Debug("Prerequisites check complete", zap.String("status", result.Status))
	return result
}

// CheckBootstrapState examines bootstrap state markers and flags
func CheckBootstrapState(rc *eos_io.RuntimeContext) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	result := CheckResult{Name: "Bootstrap State"}

	// Check for bootstrap markers
	markers := map[string]string{
		"/var/lib/eos/.bootstrapped":      "Complete bootstrap marker",
		"/var/lib/eos/.consul_installed":  "Consul installation marker",
		"/var/lib/eos/.vault_installed":   "Vault installation marker",
		"/var/lib/eos/.nomad_installed":   "Nomad installation marker",
		"/tmp/.eos_bootstrap_in_progress": "Bootstrap in progress flag",
	}

	foundMarkers := []string{}
	for path, desc := range markers {
		if info, err := os.Stat(path); err == nil {
			foundMarkers = append(foundMarkers, desc)
			result.Details = append(result.Details,
				fmt.Sprintf("✓ Found: %s (%s, modified: %s)",
					desc, path, info.ModTime().Format("2006-01-02 15:04:05")))
		}
	}

	if len(foundMarkers) == 0 {
		result.Status = "PASS"
		result.Message = "No bootstrap state found (clean slate)"
	} else {
		result.Status = "WARN"
		result.Message = fmt.Sprintf("Found %d state marker(s) from previous bootstrap attempts", len(foundMarkers))
	}

	// Check environment variable
	if os.Getenv("EOS_BOOTSTRAP_IN_PROGRESS") != "" {
		result.Details = append(result.Details,
			fmt.Sprintf("⚠ Environment variable EOS_BOOTSTRAP_IN_PROGRESS=%s",
				os.Getenv("EOS_BOOTSTRAP_IN_PROGRESS")))
	}

	logger.Debug("Bootstrap state check complete", zap.Int("markers_found", len(foundMarkers)))
	return result
}

// CheckBootstrapLocks detects active and stale bootstrap lock files
func CheckBootstrapLocks(rc *eos_io.RuntimeContext) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	result := CheckResult{Name: "Bootstrap Locks"}

	lockFiles := []string{
		"/var/lock/eos-bootstrap.lock",
		"/var/lock/consul-install.lock",
		"/var/lock/vault-install.lock",
	}

	activeLocks := 0
	for _, lockPath := range lockFiles {
		if info, err := os.Stat(lockPath); err == nil {
			activeLocks++
			result.Details = append(result.Details,
				fmt.Sprintf("✗ Active lock: %s (created: %s)",
					lockPath, info.ModTime().Format("2006-01-02 15:04:05")))

			// Try to read lock contents (might contain PID)
			if content, err := os.ReadFile(lockPath); err == nil {
				pidStr := strings.TrimSpace(string(content))
				if pid, err := strconv.Atoi(pidStr); err == nil {
					// Check if process is still running
					process, err := os.FindProcess(pid)
					if err == nil {
						err = process.Signal(syscall.Signal(0))
						if err == nil {
							result.Details = append(result.Details,
								fmt.Sprintf("  → Lock held by running process PID %d", pid))
						} else {
							result.Details = append(result.Details,
								fmt.Sprintf("  → Lock references dead process PID %d (STALE)", pid))
						}
					}
				}
			}
		}
	}

	if activeLocks > 0 {
		result.Status = "FAIL"
		result.Message = fmt.Sprintf("Found %d active lock(s) - may prevent bootstrap", activeLocks)
		result.Details = append(result.Details, "\nTo clear stale locks:")
		result.Details = append(result.Details, "  sudo rm -f /var/lock/eos-*.lock")
	} else {
		result.Status = "PASS"
		result.Message = "No active bootstrap locks"
	}

	logger.Debug("Lock check complete", zap.Int("active_locks", activeLocks))
	return result
}

// CheckBootstrapPhases examines the status of each bootstrap phase
func CheckBootstrapPhases(rc *eos_io.RuntimeContext) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	result := CheckResult{Name: "Bootstrap Phases"}

	phases := []struct {
		name      string
		component string
		check     func() string
	}{
		{
			"Phase 1: Consul",
			"consul",
			func() string {
				binPath := consul.GetConsulBinaryPath()
				if _, err := os.Stat(binPath); err == nil {
					if out, err := exec.CommandContext(rc.Ctx, "systemctl", "is-active", "consul").Output(); err == nil {
						if strings.TrimSpace(string(out)) == "active" {
							return "COMPLETE"
						}
						return "INSTALLED (not running)"
					}
					return "INSTALLED (service not configured)"
				}
				return "NOT STARTED"
			},
		},
		{
			"Phase 2: Vault",
			"vault",
			func() string {
				if _, err := os.Stat(vault.VaultBinaryPath); err == nil {
					if out, err := exec.CommandContext(rc.Ctx, "systemctl", "is-active", "vault").Output(); err == nil {
						if strings.TrimSpace(string(out)) == "active" {
							return "COMPLETE"
						}
						return "INSTALLED (not running)"
					}
					return "INSTALLED (service not configured)"
				}
				return "NOT STARTED"
			},
		},
		{
			"Phase 3: Nomad",
			"nomad",
			func() string {
				if _, err := os.Stat("/usr/bin/nomad"); err == nil {
					if out, err := exec.CommandContext(rc.Ctx, "systemctl", "is-active", "nomad").Output(); err == nil {
						if strings.TrimSpace(string(out)) == "active" {
							return "COMPLETE"
						}
						return "INSTALLED (not running)"
					}
					return "INSTALLED (service not configured)"
				}
				return "NOT STARTED (optional)"
			},
		},
	}

	for _, phase := range phases {
		status := phase.check()
		icon := "○"
		if strings.Contains(status, "COMPLETE") {
			icon = "✓"
		} else if strings.Contains(status, "INSTALLED") {
			icon = "⚠"
		} else if strings.Contains(status, "NOT STARTED") && !strings.Contains(status, "optional") {
			icon = "✗"
		}
		result.Details = append(result.Details, fmt.Sprintf("%s %s: %s", icon, phase.name, status))
	}

	result.Status = "PASS"
	result.Message = "Phase status checked"
	logger.Debug("Bootstrap phases check complete")
	return result
}

// CheckPreviousAttempts analyzes logs and artifacts from previous bootstrap attempts
func CheckPreviousAttempts(rc *eos_io.RuntimeContext) CheckResult {
	logger := otelzap.Ctx(rc.Ctx)
	result := CheckResult{Name: "Previous Bootstrap Attempts"}

	// Check bootstrap logs
	logPaths := []string{
		"/var/log/eos/bootstrap.log",
		"/var/log/eos/eos.log",
	}

	for _, logPath := range logPaths {
		if info, err := os.Stat(logPath); err == nil {
			result.Details = append(result.Details,
				fmt.Sprintf("Log file: %s (size: %d bytes, modified: %s)",
					logPath, info.Size(), info.ModTime().Format("2006-01-02 15:04:05")))

			// Get last 20 lines
			out, err := exec.CommandContext(rc.Ctx, "tail", "-n", "20", logPath).CombinedOutput()
			if err == nil {
				result.Details = append(result.Details, "\nRecent log entries:")
				result.Details = append(result.Details, string(out))
			}
		}
	}

	// Check systemd journal for bootstrap-related entries
	out, err := exec.CommandContext(rc.Ctx, "journalctl", "-u", "eos-bootstrap", "-n", "10", "--no-pager").CombinedOutput()
	if err == nil && len(out) > 0 {
		result.Details = append(result.Details, "\nRecent systemd journal entries:")
		result.Details = append(result.Details, string(out))
	}

	// Check for backup files (indicates previous attempts)
	backupPattern := "/etc/systemd/system/*.backup.*"
	matches, _ := filepath.Glob(backupPattern)
	if len(matches) > 0 {
		result.Details = append(result.Details,
			fmt.Sprintf("\nFound %d backup file(s) from previous attempts:", len(matches)))
		for _, match := range matches {
			info, _ := os.Stat(match)
			result.Details = append(result.Details,
				fmt.Sprintf("  %s (created: %s)", match, info.ModTime().Format("2006-01-02 15:04:05")))
		}
	}

	result.Status = "PASS"
	result.Message = "Previous attempt information collected"
	logger.Debug("Previous attempts check complete")
	return result
}
