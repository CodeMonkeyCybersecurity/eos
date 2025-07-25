package remotedebug

import (
	"fmt"
	"strconv"
	"strings"
)

// SSHHealthChecker performs comprehensive SSH health checks
type SSHHealthChecker struct {
	client   *SSHClient
	sudoPass string
	issues   []Issue
	warnings []Warning
}

// NewSSHHealthChecker creates a new SSH health checker
func NewSSHHealthChecker(client *SSHClient, sudoPass string) *SSHHealthChecker {
	return &SSHHealthChecker{
		client:   client,
		sudoPass: sudoPass,
		issues:   []Issue{},
		warnings: []Warning{},
	}
}

// CheckSSHHealth performs comprehensive SSH connectivity diagnostics
func (shc *SSHHealthChecker) CheckSSHHealth() *SSHHealthResult {
	// Run all checks
	shc.checkResourceExhaustion()
	shc.checkNetworkHealth()
	shc.checkAuthenticationHealth()
	shc.checkSystemConfiguration()
	shc.checkSSHDaemonHealth()
	shc.checkSecurityMeasures()
	
	// Determine overall health
	healthy := len(shc.issues) == 0
	
	return &SSHHealthResult{
		Healthy:  healthy,
		Issues:   shc.issues,
		Warnings: shc.warnings,
	}
}

// checkResourceExhaustion looks for resource limits affecting SSH
func (shc *SSHHealthChecker) checkResourceExhaustion() {
	// Check memory pressure
	shc.checkMemoryPressure()
	
	// Check process limits
	shc.checkProcessLimits()
	
	// Check file descriptor limits
	shc.checkFileDescriptors()
}

// checkMemoryPressure detects memory exhaustion
func (shc *SSHHealthChecker) checkMemoryPressure() {
	cmd := `free -b && echo "---" && cat /proc/meminfo | grep -E "(MemAvailable|SwapFree)" && echo "---" && ps aux --sort=-%mem | head -5`
	
	output, err := shc.client.ExecuteCommand(cmd, false)
	if err != nil {
		return
	}
	
	// Parse memory info
	lines := strings.Split(output, "\n")
	var memTotal, memAvailable int64
	
	for _, line := range lines {
		if strings.Contains(line, "Mem:") && strings.Fields(line)[0] == "Mem:" {
			fields := strings.Fields(line)
			if len(fields) >= 7 {
				memTotal, _ = strconv.ParseInt(fields[1], 10, 64)
				memAvailable, _ = strconv.ParseInt(fields[6], 10, 64)
			}
		}
	}
	
	if memTotal > 0 && memAvailable > 0 {
		memPressure := float64(memTotal-memAvailable) / float64(memTotal) * 100
		
		if memPressure > 95 {
			shc.issues = append(shc.issues, Issue{
				Severity:    SeverityCritical,
				Category:    CategoryMemory,
				Description: fmt.Sprintf("Extreme memory pressure: %.1f%% used", memPressure),
				Evidence:    fmt.Sprintf("Available: %d MB of %d MB", memAvailable/(1024*1024), memTotal/(1024*1024)),
				Impact:      "SSH may fail to allocate memory for new sessions",
				Remediation: "Free memory by stopping processes or add swap space",
			})
		} else if memPressure > 85 {
			shc.warnings = append(shc.warnings, Warning{
				Category:    CategoryMemory,
				Description: fmt.Sprintf("High memory usage: %.1f%%", memPressure),
				Suggestion:  "Monitor for OOM kills and consider adding memory",
			})
		}
	}
	
	// Check for OOM killer activity
	oomCheck := `dmesg | grep -i "killed process" | tail -3`
	oomOutput, _ := shc.client.ExecuteCommand(oomCheck, true)
	if strings.Contains(oomOutput, "Killed process") {
		shc.issues = append(shc.issues, Issue{
			Severity:    SeverityHigh,
			Category:    CategoryMemory,
			Description: "OOM killer has been active recently",
			Evidence:    oomOutput,
			Impact:      "Processes being killed may affect SSH stability",
			Remediation: "Add memory or reduce memory usage",
		})
	}
}

// checkProcessLimits checks for process limit exhaustion
func (shc *SSHHealthChecker) checkProcessLimits() {
	// Get current process count and limits
	cmds := map[string]string{
		"pid_max":      "cat /proc/sys/kernel/pid_max",
		"proc_count":   "ps aux | wc -l",
		"thread_max":   "cat /proc/sys/kernel/threads-max",
		"user_limit":   "ulimit -u",
		"fork_bombs":   `ps aux | awk '{print $1}' | sort | uniq -c | sort -rn | head -5`,
	}
	
	results := make(map[string]string)
	for name, cmd := range cmds {
		output, _ := shc.client.ExecuteCommand(cmd, false)
		results[name] = strings.TrimSpace(output)
	}
	
	// Check process utilization
	pidMax, _ := strconv.Atoi(results["pid_max"])
	currentProcs, _ := strconv.Atoi(results["proc_count"])
	
	if pidMax > 0 && currentProcs > 0 {
		procUtilization := float64(currentProcs) / float64(pidMax) * 100
		
		if procUtilization > 80 {
			shc.issues = append(shc.issues, Issue{
				Severity:    SeverityHigh,
				Category:    "process_limits",
				Description: fmt.Sprintf("High process count: %d of %d max (%.1f%%)", currentProcs, pidMax, procUtilization),
				Evidence:    fmt.Sprintf("Current processes: %d", currentProcs),
				Impact:      "Cannot create new processes, SSH sessions will fail",
				Remediation: "Investigate process leak or increase pid_max",
			})
		} else if procUtilization > 60 {
			shc.warnings = append(shc.warnings, Warning{
				Category:    "process_limits",
				Description: fmt.Sprintf("Process count at %.1f%% of limit", procUtilization),
				Suggestion:  "Monitor process creation and consider increasing limits",
			})
		}
	}
	
	// Check for potential fork bombs
	if results["fork_bombs"] != "" {
		lines := strings.Split(results["fork_bombs"], "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				count, _ := strconv.Atoi(fields[0])
				user := fields[1]
				if count > 1000 {
					shc.issues = append(shc.issues, Issue{
						Severity:    SeverityCritical,
						Category:    "process_limits",
						Description: fmt.Sprintf("Possible fork bomb: user %s has %d processes", user, count),
						Evidence:    line,
						Impact:      "System resources exhausted",
						Remediation: fmt.Sprintf("Kill processes: pkill -u %s", user),
					})
				}
			}
		}
	}
}

// checkFileDescriptors checks file descriptor limits
func (shc *SSHHealthChecker) checkFileDescriptors() {
	// Get file descriptor usage
	cmd := `cat /proc/sys/fs/file-nr && echo "---" && ulimit -n`
	output, err := shc.client.ExecuteCommand(cmd, false)
	if err != nil {
		return
	}
	
	parts := strings.Split(output, "---")
	if len(parts) >= 1 {
		// Parse system-wide file descriptors
		fields := strings.Fields(parts[0])
		if len(fields) >= 3 {
			used, _ := strconv.Atoi(fields[0])
			max, _ := strconv.Atoi(fields[2])
			
			if max > 0 && used > 0 {
				utilization := float64(used) / float64(max) * 100
				
				if utilization > 80 {
					shc.issues = append(shc.issues, Issue{
						Severity:    SeverityHigh,
						Category:    "resources",
						Description: fmt.Sprintf("High file descriptor usage: %.1f%%", utilization),
						Evidence:    fmt.Sprintf("%d of %d file descriptors used", used, max),
						Impact:      "Cannot open new files or connections",
						Remediation: "Increase fs.file-max or investigate fd leaks",
					})
				}
			}
		}
	}
}

// checkNetworkHealth diagnoses network-related SSH issues
func (shc *SSHHealthChecker) checkNetworkHealth() {
	// Check SSH connection limits
	shc.checkConnectionLimits()
	
	// Check for firewall/security tool interference
	shc.checkFirewallRateLimits()
	
	// Check for network saturation
	shc.checkNetworkSaturation()
}

// checkConnectionLimits checks SSH connection limits
func (shc *SSHHealthChecker) checkConnectionLimits() {
	// Count current SSH connections
	cmd := `ss -ant | grep -E ":22\s" | wc -l`
	output, err := shc.client.ExecuteCommand(cmd, false)
	if err != nil {
		return
	}
	
	currentConnections, _ := strconv.Atoi(strings.TrimSpace(output))
	
	if currentConnections > 100 {
		shc.issues = append(shc.issues, Issue{
			Severity:    SeverityHigh,
			Category:    CategoryNetwork,
			Description: fmt.Sprintf("Very high number of SSH connections: %d", currentConnections),
			Evidence:    fmt.Sprintf("%d active connections on port 22", currentConnections),
			Impact:      "May hit MaxStartups limit, new connections rejected",
			Remediation: "Check for connection flooding or increase MaxStartups",
		})
	} else if currentConnections > 50 {
		shc.warnings = append(shc.warnings, Warning{
			Category:    CategoryNetwork,
			Description: fmt.Sprintf("High number of SSH connections: %d", currentConnections),
			Suggestion:  "Monitor for connection exhaustion",
		})
	}
	
	// Check for SYN flood
	synCmd := `ss -ant | grep SYN | grep ":22" | wc -l`
	synOutput, _ := shc.client.ExecuteCommand(synCmd, false)
	synCount, _ := strconv.Atoi(strings.TrimSpace(synOutput))
	
	if synCount > 50 {
		shc.issues = append(shc.issues, Issue{
			Severity:    SeverityHigh,
			Category:    CategoryNetwork,
			Description: fmt.Sprintf("Possible SYN flood on SSH: %d SYN connections", synCount),
			Evidence:    fmt.Sprintf("%d connections in SYN state", synCount),
			Impact:      "New SSH connections may timeout",
			Remediation: "Enable SYN cookies: echo 1 > /proc/sys/net/ipv4/tcp_syncookies",
		})
	}
}

// checkFirewallRateLimits checks for firewall interference
func (shc *SSHHealthChecker) checkFirewallRateLimits() {
	// Check fail2ban
	f2bCmd := `fail2ban-client status sshd 2>/dev/null | grep -E "(Currently banned|Total banned)"`
	f2bOutput, err := shc.client.ExecuteCommand(f2bCmd, true)
	
	if err == nil && f2bOutput != "" {
		if strings.Contains(f2bOutput, "Currently banned") {
			// Extract number of banned IPs
			shc.warnings = append(shc.warnings, Warning{
				Category:    CategorySecurity,
				Description: "fail2ban is actively blocking IPs for SSH",
				Suggestion:  "Check fail2ban-client status sshd for details",
			})
		}
	}
	
	// Check iptables for SSH rules
	iptablesCmd := `iptables -L -n -v 2>/dev/null | grep -E "dpt:22|ssh" | grep -E "(DROP|REJECT)"`
	iptablesOutput, _ := shc.client.ExecuteCommand(iptablesCmd, true)
	
	if iptablesOutput != "" {
		lines := strings.Split(iptablesOutput, "\n")
		if len(lines) > 5 {
			shc.warnings = append(shc.warnings, Warning{
				Category:    CategorySecurity,
				Description: fmt.Sprintf("Multiple firewall rules affecting SSH (%d rules)", len(lines)),
				Suggestion:  "Review iptables rules for potential SSH restrictions",
			})
		}
	}
}

// checkNetworkSaturation checks for network saturation
func (shc *SSHHealthChecker) checkNetworkSaturation() {
	// Check for TIME_WAIT exhaustion
	timeWaitCmd := `ss -ant | grep TIME_WAIT | wc -l`
	timeWaitOutput, _ := shc.client.ExecuteCommand(timeWaitCmd, false)
	timeWaitCount, _ := strconv.Atoi(strings.TrimSpace(timeWaitOutput))
	
	if timeWaitCount > 10000 {
		shc.issues = append(shc.issues, Issue{
			Severity:    SeverityMedium,
			Category:    CategoryNetwork,
			Description: fmt.Sprintf("High TIME_WAIT connections: %d", timeWaitCount),
			Evidence:    fmt.Sprintf("%d connections in TIME_WAIT state", timeWaitCount),
			Impact:      "May exhaust local port range",
			Remediation: "Tune tcp_tw_reuse and tcp_tw_recycle settings",
		})
	}
}

// checkAuthenticationHealth checks authentication subsystem
func (shc *SSHHealthChecker) checkAuthenticationHealth() {
	// Check systemd-logind
	shc.checkSystemdLogind()
	
	// Check for stale mounts that can hang PAM
	shc.checkStaleMounts()
	
	// Check LDAP/AD if configured
	shc.checkLDAPHealth()
}

// checkSystemdLogind checks if systemd-logind is healthy
func (shc *SSHHealthChecker) checkSystemdLogind() {
	cmd := `systemctl is-active systemd-logind`
	output, err := shc.client.ExecuteCommand(cmd, false)
	
	if err != nil || !strings.Contains(output, "active") {
		shc.issues = append(shc.issues, Issue{
			Severity:    SeverityHigh,
			Category:    CategoryAuth,
			Description: "systemd-logind is not active",
			Evidence:    strings.TrimSpace(output),
			Impact:      "PAM authentication may hang or fail",
			Remediation: "systemctl restart systemd-logind",
		})
	}
}

// checkStaleMounts checks for stale NFS mounts
func (shc *SSHHealthChecker) checkStaleMounts() {
	// This check uses timeout to avoid hanging
	cmd := `mount -t nfs,nfs4 | while read line; do 
		mp=$(echo $line | awk '{print $3}'); 
		timeout 2 ls $mp >/dev/null 2>&1 || echo "STALE: $mp"; 
	done`
	
	output, _ := shc.client.ExecuteCommand(cmd, false)
	
	if strings.Contains(output, "STALE:") {
		shc.issues = append(shc.issues, Issue{
			Severity:    SeverityCritical,
			Category:    CategoryAuth,
			Description: "Stale NFS mounts detected",
			Evidence:    output,
			Impact:      "PAM may hang trying to access home directories",
			Remediation: "Unmount stale mounts or fix NFS connectivity",
		})
	}
}

// checkLDAPHealth checks LDAP connectivity if configured
func (shc *SSHHealthChecker) checkLDAPHealth() {
	// Check if LDAP is in use
	checkCmd := `grep -l "pam_ldap\|pam_sss" /etc/pam.d/* 2>/dev/null | head -1`
	ldapConfig, _ := shc.client.ExecuteCommand(checkCmd, true)
	
	if ldapConfig != "" {
		// Test LDAP response time
		testCmd := `time timeout 5 getent passwd 2>&1 | grep real`
		output, err := shc.client.ExecuteCommand(testCmd, false)
		
		if err != nil || strings.Contains(output, "timeout") {
			shc.issues = append(shc.issues, Issue{
				Severity:    SeverityHigh,
				Category:    CategoryAuth,
				Description: "LDAP authentication timeout",
				Evidence:    "getent passwd timed out",
				Impact:      "SSH logins will be very slow or fail",
				Remediation: "Check LDAP server connectivity",
			})
		}
	}
}

// checkSystemConfiguration checks system config issues
func (shc *SSHHealthChecker) checkSystemConfiguration() {
	// Check SELinux
	shc.checkSELinux()
	
	// Check entropy
	shc.checkEntropy()
	
	// Check DNS
	shc.checkDNS()
}

// checkSELinux checks for SELinux issues
func (shc *SSHHealthChecker) checkSELinux() {
	cmd := `getenforce 2>/dev/null`
	output, err := shc.client.ExecuteCommand(cmd, false)
	
	if err == nil && strings.TrimSpace(output) == "Enforcing" {
		// Check for SSH-related denials
		auditCmd := `ausearch -m avc -ts recent 2>/dev/null | grep -i ssh | head -5`
		auditOutput, _ := shc.client.ExecuteCommand(auditCmd, true)
		
		if strings.Contains(auditOutput, "denied") {
			shc.issues = append(shc.issues, Issue{
				Severity:    SeverityHigh,
				Category:    "selinux",
				Description: "SELinux is blocking SSH operations",
				Evidence:    auditOutput,
				Impact:      "SSH connections or operations may fail",
				Remediation: "Review SELinux denials with ausearch",
			})
		}
	}
}

// checkEntropy checks available entropy
func (shc *SSHHealthChecker) checkEntropy() {
	cmd := `cat /proc/sys/kernel/random/entropy_avail`
	output, err := shc.client.ExecuteCommand(cmd, false)
	
	if err == nil {
		entropy, _ := strconv.Atoi(strings.TrimSpace(output))
		
		if entropy < 200 {
			shc.issues = append(shc.issues, Issue{
				Severity:    SeverityMedium,
				Category:    "system",
				Description: fmt.Sprintf("Low entropy available: %d bits", entropy),
				Evidence:    fmt.Sprintf("Only %d bits of entropy", entropy),
				Impact:      "SSH key operations may be slow",
				Remediation: "Install haveged or rng-tools",
			})
		}
	}
}

// checkDNS checks DNS resolution
func (shc *SSHHealthChecker) checkDNS() {
	// Test DNS resolution time
	cmd := `time timeout 5 nslookup google.com 2>&1 | grep real`
	output, err := shc.client.ExecuteCommand(cmd, false)
	
	if err != nil || strings.Contains(output, "timeout") {
		shc.warnings = append(shc.warnings, Warning{
			Category:    "dns",
			Description: "DNS resolution is slow or failing",
			Suggestion:  "Check /etc/resolv.conf and DNS server connectivity",
		})
	}
}

// checkSSHDaemonHealth checks SSH daemon specifics
func (shc *SSHHealthChecker) checkSSHDaemonHealth() {
	// Check SSH daemon status
	statusCmd := `systemctl is-active sshd || systemctl is-active ssh`
	status, _ := shc.client.ExecuteCommand(statusCmd, false)
	
	if !strings.Contains(status, "active") {
		shc.issues = append(shc.issues, Issue{
			Severity:    SeverityCritical,
			Category:    CategorySSH,
			Description: "SSH daemon is not running",
			Evidence:    strings.TrimSpace(status),
			Impact:      "No SSH connections possible",
			Remediation: "systemctl start sshd",
		})
		return
	}
	
	// Check configuration validity
	configTestCmd := `sshd -t 2>&1`
	configOutput, err := shc.client.ExecuteCommand(configTestCmd, true)
	
	if err != nil || configOutput != "" {
		shc.issues = append(shc.issues, Issue{
			Severity:    SeverityHigh,
			Category:    CategorySSH,
			Description: "SSH configuration has errors",
			Evidence:    configOutput,
			Impact:      "SSH daemon may fail to reload",
			Remediation: "Fix errors in /etc/ssh/sshd_config",
		})
	}
	
	// Check for port conflicts
	portCmd := `ss -tlnp | grep ":22 " 2>/dev/null | grep -v sshd`
	portOutput, _ := shc.client.ExecuteCommand(portCmd, true)
	
	if portOutput != "" {
		shc.issues = append(shc.issues, Issue{
			Severity:    SeverityCritical,
			Category:    CategorySSH,
			Description: "Another process is using SSH port",
			Evidence:    portOutput,
			Impact:      "SSH daemon cannot bind to port",
			Remediation: "Stop conflicting process or change SSH port",
		})
	}
}

// checkSecurityMeasures checks security tools that might interfere
func (shc *SSHHealthChecker) checkSecurityMeasures() {
	// Check hosts.deny
	denyCmd := `test -f /etc/hosts.deny && wc -l < /etc/hosts.deny`
	denyOutput, _ := shc.client.ExecuteCommand(denyCmd, false)
	
	if denyOutput != "" {
		denyCount, _ := strconv.Atoi(strings.TrimSpace(denyOutput))
		if denyCount > 100 {
			shc.warnings = append(shc.warnings, Warning{
				Category:    CategorySecurity,
				Description: fmt.Sprintf("Large hosts.deny file: %d entries", denyCount),
				Suggestion:  "Review and clean up /etc/hosts.deny",
			})
		}
	}
	
	// Check for DenyUsers/DenyGroups in sshd_config
	sshConfigCmd := `grep -E "^(DenyUsers|DenyGroups|AllowUsers|AllowGroups)" /etc/ssh/sshd_config 2>/dev/null`
	configOutput, _ := shc.client.ExecuteCommand(sshConfigCmd, true)
	
	if configOutput != "" {
		shc.warnings = append(shc.warnings, Warning{
			Category:    CategorySecurity,
			Description: "SSH access restrictions configured",
			Suggestion:  "Verify user access in sshd_config: " + strings.ReplaceAll(configOutput, "\n", "; "),
		})
	}
}