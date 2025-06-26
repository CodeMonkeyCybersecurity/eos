package ubuntu

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"go.uber.org/zap"
)

// setupMFAForUsers configures MFA for all identified sudo users
func (m *MFAManager) setupMFAForUsers(users []SudoUser) error {
	m.logger.Info(" Setting up MFA for users", zap.Int("user_count", len(users)))

	for _, user := range users {
		if user.HasMFA {
			m.logger.Info(" User already has MFA configured",
				zap.String("user", user.Username))
			continue
		}

		// Handle service accounts with NOPASSWD commands
		if len(user.NOPASSWDCmds) > 0 && m.config.PreserveNOPASSWD {
			// Evaluate if this user should bypass MFA
			if m.shouldBypassMFA(user) {
				m.logger.Info(" Adding user to service account group (has NOPASSWD commands)",
					zap.String("user", user.Username),
					zap.Strings("commands", user.NOPASSWDCmds))

				if err := m.addToServiceGroup(user.Username); err != nil {
					return fmt.Errorf("add %s to service group: %w", user.Username, err)
				}
				continue
			} else {
				m.logger.Warn("⚠️ User has NOPASSWD commands but requiring MFA for security",
					zap.String("user", user.Username),
					zap.Strings("nopasswd_commands", user.NOPASSWDCmds),
					zap.String("reason", "Commands too broad or security-critical"))
			}
		}

		// Handle interactive users - defer MFA setup to manual process
		m.logger.Info("📱 User needs MFA configuration",
			zap.String("user", user.Username),
			zap.String("home", user.HomeDir))

		// Create setup instructions for the user
		if err := m.createUserMFAInstructions(user); err != nil {
			m.logger.Warn("Failed to create MFA instructions for user",
				zap.String("user", user.Username),
				zap.Error(err))
		}
	}

	return nil
}

// addToServiceGroup adds a user to the service account group
func (m *MFAManager) addToServiceGroup(username string) error {
	if m.config.ServiceAccountGroup == "" {
		return fmt.Errorf("service account group not configured")
	}

	if err := execute.RunSimple(m.rc.Ctx, "usermod", "-a", "-G",
		m.config.ServiceAccountGroup, username); err != nil {
		return fmt.Errorf("add user to service group: %w", err)
	}

	m.logger.Info(" Added user to service account group",
		zap.String("user", username),
		zap.String("group", m.config.ServiceAccountGroup))

	return nil
}

// createUserMFAInstructions creates personalized MFA setup instructions
func (m *MFAManager) createUserMFAInstructions(user SudoUser) error {
	instructions := fmt.Sprintf(`# MFA Setup Instructions for %s

## IMPORTANT: Multi-Factor Authentication Required

Hello %s,

Multi-Factor Authentication (MFA) has been implemented on this system.
You must configure MFA to continue using sudo commands.

## Quick Setup:

1. Run this command to set up MFA:
   sudo setup-mfa

2. Follow the prompts to:
   - Install an authenticator app (Google Authenticator, Authy, etc.)
   - Scan the QR code or enter the secret key
   - Save your emergency backup codes

3. Test your setup:
   sudo whoami

## Your Account Details:
- Username: %s
- Home Directory: %s
- Sudo Groups: %s

## Authenticator Apps:
- Google Authenticator (iOS/Android)
- Microsoft Authenticator (iOS/Android)
- Authy (iOS/Android/Desktop)
- 1Password (with TOTP support)
- Bitwarden (with TOTP support)

## Emergency Access:
If you get locked out, contact your system administrator.
Emergency recovery options are available via console access.

## Questions?
- MFA Status: sudo mfa-status
- Emergency Help: /usr/local/share/eos/mfa-recovery.md

Generated: %s
`, user.Username, user.Username, user.Username, user.HomeDir,
		strings.Join(user.Groups, ", "), time.Now().Format("2006-01-02 15:04:05"))

	// Create instructions file in user's home directory
	instructionsPath := filepath.Join(user.HomeDir, "MFA_SETUP_REQUIRED.txt")
	if err := os.WriteFile(instructionsPath, []byte(instructions), 0644); err != nil {
		return fmt.Errorf("write instructions file: %w", err)
	}

	// Set proper ownership
	if err := execute.RunSimple(m.rc.Ctx, "chown",
		fmt.Sprintf("%s:%s", user.Username, user.Username),
		instructionsPath); err != nil {
		m.logger.Warn("Failed to set ownership of instructions file", zap.Error(err))
	}

	m.logger.Info(" Created MFA setup instructions",
		zap.String("user", user.Username),
		zap.String("file", instructionsPath))

	return nil
}

// testConfiguration performs comprehensive testing of the MFA setup
func (m *MFAManager) testConfiguration() error {
	m.logger.Info("🧪 Testing MFA configuration")

	tests := []struct {
		name string
		fn   func() error
	}{
		{"PAM Configuration Syntax", m.testPAMConfiguration},
		{"Emergency Access Methods", m.testEmergencyAccess},
		{"Service Account Bypass", m.testServiceAccounts},
		{"MFA Package Installation", m.testMFAPackages},
		{"System Security", m.testSystemSecurity},
	}

	for _, test := range tests {
		m.logger.Info("  Running test: " + test.name)
		if err := test.fn(); err != nil {
			m.logger.Error("❌ Test failed",
				zap.String("test", test.name),
				zap.Error(err))
			return fmt.Errorf("test '%s' failed: %w", test.name, err)
		}
		m.logger.Info("   " + test.name)
	}

	m.logger.Info(" All configuration tests passed")
	return nil
}

// testPAMConfiguration validates PAM configurations
func (m *MFAManager) testPAMConfiguration() error {
	pamFiles := []string{
		"/etc/pam.d/sudo",
		"/etc/pam.d/su",
	}

	if !m.config.ConsoleBypassMFA {
		pamFiles = append(pamFiles, "/etc/pam.d/login")
	}

	for _, file := range pamFiles {
		if err := m.validatePAMConfig(file); err != nil {
			return fmt.Errorf("PAM file %s validation failed: %w", file, err)
		}

		// Check that MFA module is referenced
		content, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("read %s: %w", file, err)
		}

		if !strings.Contains(string(content), "pam_google_authenticator") {
			return fmt.Errorf("MFA module not found in %s", file)
		}
	}

	return nil
}

// testEmergencyAccess validates emergency access mechanisms
func (m *MFAManager) testEmergencyAccess() error {
	// Check emergency group exists
	if m.config.EmergencyGroupName != "" {
		if err := execute.RunSimple(m.rc.Ctx, "getent", "group", m.config.EmergencyGroupName); err != nil {
			return fmt.Errorf("emergency group %s does not exist", m.config.EmergencyGroupName)
		}
	}

	// Check emergency bypass script exists and is executable
	scriptPath := "/usr/local/bin/emergency-mfa-bypass"
	info, err := os.Stat(scriptPath)
	if err != nil {
		return fmt.Errorf("emergency bypass script not found: %w", err)
	}

	if info.Mode()&0111 == 0 {
		return fmt.Errorf("emergency bypass script is not executable")
	}

	// Test script syntax
	if err := execute.RunSimple(m.rc.Ctx, "bash", "-n", scriptPath); err != nil {
		return fmt.Errorf("emergency bypass script has syntax errors: %w", err)
	}

	// Check backup admin exists (if configured)
	if m.config.CreateBackupAdmin && m.config.BackupAdminUser != "" {
		if err := execute.RunSimple(m.rc.Ctx, "id", m.config.BackupAdminUser); err != nil {
			return fmt.Errorf("backup admin user %s does not exist", m.config.BackupAdminUser)
		}
	}

	return nil
}

// testServiceAccounts validates service account handling
func (m *MFAManager) testServiceAccounts() error {
	if m.config.ServiceAccountGroup == "" {
		return nil // Not configured, skip test
	}

	// Check service account group exists
	if err := execute.RunSimple(m.rc.Ctx, "getent", "group", m.config.ServiceAccountGroup); err != nil {
		return fmt.Errorf("service account group %s does not exist", m.config.ServiceAccountGroup)
	}

	return nil
}

// testMFAPackages validates MFA packages are installed
func (m *MFAManager) testMFAPackages() error {
	packages := []string{
		"libpam-google-authenticator",
		"qrencode",
	}

	for _, pkg := range packages {
		if err := execute.RunSimple(m.rc.Ctx, "dpkg", "-l", pkg); err != nil {
			return fmt.Errorf("package %s not installed", pkg)
		}
	}

	// Check that google-authenticator binary exists
	if err := execute.RunSimple(m.rc.Ctx, "which", "google-authenticator"); err != nil {
		return fmt.Errorf("google-authenticator binary not found")
	}

	return nil
}

// testSystemSecurity performs additional security validation
func (m *MFAManager) testSystemSecurity() error {
	// Check PAM module exists
	pamModulePaths := []string{
		"/lib/x86_64-linux-gnu/security/pam_google_authenticator.so",
		"/lib64/security/pam_google_authenticator.so",
		"/usr/lib/x86_64-linux-gnu/security/pam_google_authenticator.so",
	}

	found := false
	for _, path := range pamModulePaths {
		if _, err := os.Stat(path); err == nil {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("pam_google_authenticator.so module not found")
	}

	// Check that /etc/security directory exists with proper permissions
	securityDir := "/etc/security"
	info, err := os.Stat(securityDir)
	if err != nil {
		return fmt.Errorf("security directory does not exist: %w", err)
	}

	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", securityDir)
	}

	// Check permissions (should be 755 or more restrictive)
	mode := info.Mode().Perm()
	if mode&0022 != 0 {
		return fmt.Errorf("security directory has overly permissive permissions: %o", mode)
	}

	return nil
}

// additionalHardening applies additional security measures
func (m *MFAManager) additionalHardening() error {
	m.logger.Info("🛡️ Applying additional security hardening")

	// Configure audit logging for sudo
	if err := m.configureAuditLogging(); err != nil {
		m.logger.Warn("Failed to configure audit logging", zap.Error(err))
	}

	// Set security limits
	if err := m.configureSecurityLimits(); err != nil {
		m.logger.Warn("Failed to configure security limits", zap.Error(err))
	}

	return nil
}

// configureAuditLogging sets up audit logging for sudo usage
func (m *MFAManager) configureAuditLogging() error {
	auditRules := []string{
		"-w /etc/sudoers -p wa -k sudo_changes",
		"-w /etc/sudoers.d/ -p wa -k sudo_changes",
		"-w /etc/pam.d/sudo -p wa -k pam_sudo_changes",
		"-w /usr/bin/sudo -p x -k sudo_usage",
		"-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -k sudo_exec",
	}

	// Check if audit system is in immutable mode
	auditStatus, err := execute.Run(m.rc.Ctx, execute.Options{
		Command: "auditctl",
		Args:    []string{"-s"},
	})
	
	isImmutable := false
	if err == nil && strings.Contains(auditStatus, "enabled 2") {
		isImmutable = true
		m.logger.Info(" Audit system is in immutable mode, rules will apply after reboot")
	}

	// Try to add rules to current session (unless immutable)
	if !isImmutable {
		rulesAdded := 0
		for _, rule := range auditRules {
			fields := strings.Fields(rule)
			if err := execute.RunSimple(m.rc.Ctx, "auditctl", fields...); err != nil {
				m.logger.Warn("Failed to add audit rule to active session",
					zap.String("rule", rule),
					zap.Error(err))
			} else {
				rulesAdded++
			}
		}
		
		if rulesAdded > 0 {
			m.logger.Info(" Added audit rules to active session",
				zap.Int("rules_added", rulesAdded),
				zap.Int("total_rules", len(auditRules)))
		}
	}

	// Always make rules persistent for reboot
	rulesFile := "/etc/audit/rules.d/50-mfa-sudo.rules"
	content := fmt.Sprintf(`# MFA Sudo Audit Rules - Generated by Eos
# These rules monitor sudo access and configuration changes

%s
`, strings.Join(auditRules, "\n"))

	if err := os.WriteFile(rulesFile, []byte(content), 0640); err != nil {
		return fmt.Errorf("write audit rules file: %w", err)
	}

	if isImmutable {
		m.logger.Info(" Audit rules written to file (will apply after reboot)",
			zap.String("file", rulesFile))
	} else {
		m.logger.Info(" Configured audit logging for sudo usage",
			zap.String("persistent_file", rulesFile))
	}
	
	return nil
}

// configureSecurityLimits sets up security limits
func (m *MFAManager) configureSecurityLimits() error {
	limitsConfig := `# Security limits for MFA-enabled system
# Limit login attempts
* hard maxlogins 3

# Limit processes
* soft nproc 1024
* hard nproc 2048

# Limit file descriptors
* soft nofile 1024
* hard nofile 2048
`

	limitsFile := "/etc/security/limits.d/99-mfa-security.conf"
	if err := os.WriteFile(limitsFile, []byte(limitsConfig), 0644); err != nil {
		return fmt.Errorf("write security limits: %w", err)
	}

	m.logger.Info(" Configured security limits")
	return nil
}

// shouldBypassMFA determines if a user should bypass MFA based on their NOPASSWD commands
func (m *MFAManager) shouldBypassMFA(user SudoUser) bool {
	// Never bypass for users with ALL permissions
	for _, cmd := range user.NOPASSWDCmds {
		if cmd == "ALL" {
			return false
		}
	}
	
	// Define safe service command patterns
	safeServicePatterns := []string{
		"/usr/sbin/smartctl",       // Disk monitoring
		"/usr/sbin/nvme",           // NVMe monitoring
		"/usr/bin/systemctl status", // Read-only service status
		"/usr/bin/journalctl",      // Log reading
		"/bin/cat /proc/",          // System info reading
		"/bin/ls",                  // Directory listing
		"/usr/bin/docker ps",       // Container status
		"/usr/bin/docker images",   // Container image listing
		"/usr/bin/kubectl get",     // K8s read-only operations
	}
	
	// Check if all commands match safe patterns
	for _, cmd := range user.NOPASSWDCmds {
		isSafe := false
		for _, pattern := range safeServicePatterns {
			if strings.HasPrefix(cmd, pattern) {
				isSafe = true
				break
			}
		}
		
		// If any command doesn't match safe patterns, require MFA
		if !isSafe {
			m.logger.Debug("Command requires MFA",
				zap.String("user", user.Username),
				zap.String("unsafe_command", cmd))
			return false
		}
	}
	
	// Only bypass if all commands are safe and user appears to be service account
	return len(user.NOPASSWDCmds) > 0 && m.looksLikeServiceAccount(user.Username)
}

// looksLikeServiceAccount determines if a username appears to be a service account
func (m *MFAManager) looksLikeServiceAccount(username string) bool {
	// Common service account patterns
	servicePatterns := []string{
		"jenkins", "gitlab", "docker", "k8s", "kubernetes", "prometheus", "grafana",
		"nagios", "zabbix", "monitoring", "backup", "service", "daemon", "worker",
		"ceph", "mysql", "postgres", "redis", "elasticsearch", "kibana", "logstash",
		"nginx", "apache", "www-data", "httpd", "tomcat", "application", "app",
	}
	
	lowerUsername := strings.ToLower(username)
	
	// Check if username matches common service patterns
	for _, pattern := range servicePatterns {
		if strings.Contains(lowerUsername, pattern) {
			return true
		}
	}
	
	// Check if username ends with common service suffixes
	serviceSuffixes := []string{"_service", "_daemon", "_worker", "_agent", "_bot"}
	for _, suffix := range serviceSuffixes {
		if strings.HasSuffix(lowerUsername, suffix) {
			return true
		}
	}
	
	return false
}

// finalizeConfiguration completes the MFA implementation
func (m *MFAManager) finalizeConfiguration() error {
	m.logger.Info(" Finalizing MFA configuration")

	// Create summary report
	if err := m.createImplementationReport(); err != nil {
		m.logger.Warn("Failed to create implementation report", zap.Error(err))
	}

	// Display completion message
	m.displayCompletionMessage()

	return nil
}

// createImplementationReport creates a comprehensive implementation report
func (m *MFAManager) createImplementationReport() error {
	report := fmt.Sprintf(`# MFA Implementation Report

Generated: %s
Backup Directory: %s
Test Mode: %t

## Configuration Applied:
- Emergency Group: %s
- Service Account Group: %s
- Console Bypass MFA: %t
- Backup Admin Created: %t
- Recovery Codes Enabled: %t

## Files Modified:
- /etc/pam.d/sudo - MFA required for sudo access
- /etc/pam.d/su - MFA required for su access
%s

## Emergency Access Methods:
1. Emergency bypass script: /usr/local/bin/emergency-mfa-bypass
2. Emergency group membership: %s
3. Console recovery mode (if enabled)
4. Backup admin account: %s
5. Manual restore script: %s/restore.sh

## Next Steps:
1. All sudo users must run: sudo setup-mfa
2. Test MFA access in new sessions before closing current session
3. Ensure emergency access methods are documented and accessible
4. Regular testing of MFA and emergency procedures

## Files Backed Up:
%s

## Recovery Documentation:
/usr/local/share/eos/mfa-recovery.md

---
Implementation completed successfully by Eos MFA Manager
`,
		time.Now().Format("2006-01-02 15:04:05"),
		m.backupDir,
		m.testMode,
		m.config.EmergencyGroupName,
		m.config.ServiceAccountGroup,
		m.config.ConsoleBypassMFA,
		m.config.CreateBackupAdmin,
		m.config.EnableRecoveryCodes,
		func() string {
			if !m.config.ConsoleBypassMFA {
				return "- /etc/pam.d/login - MFA required for console login"
			}
			return ""
		}(),
		m.config.EmergencyGroupName,
		m.config.BackupAdminUser,
		m.backupDir,
		m.backupDir)

	reportPath := filepath.Join(m.backupDir, "implementation-report.md")
	if err := os.WriteFile(reportPath, []byte(report), 0644); err != nil {
		return fmt.Errorf("write implementation report: %w", err)
	}

	m.logger.Info("📊 Created implementation report",
		zap.String("path", reportPath))

	return nil
}

// displayCompletionMessage shows the completion message to the user
func (m *MFAManager) displayCompletionMessage() {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("                    MFA IMPLEMENTATION COMPLETE ")
	fmt.Println(strings.Repeat("=", 80))

	if m.testMode {
		fmt.Println("\n🧪 TEST MODE ACTIVE")
		fmt.Println("   • MFA is configured but allows fallback during testing")
		fmt.Println("   • Users without MFA can still access sudo with password only")
		fmt.Println("   • Switch to enforced mode when ready: eos secure ubuntu --enforce-mfa")
	} else {
		fmt.Println("\n🔒 ENFORCED MODE ACTIVE")
		fmt.Println("   • MFA is required for ALL sudo/su operations")
		fmt.Println("   • Password-only access is disabled")
	}

	fmt.Println("\n🛡️ PROTECTED PRIVILEGE ESCALATION METHODS:")
	fmt.Println("    sudo - Multi-factor authentication required")
	fmt.Println("    su - Multi-factor authentication required")
	if !m.config.ConsoleBypassMFA {
		fmt.Println("    console login - Multi-factor authentication required")
	}

	fmt.Println("\n EMERGENCY ACCESS METHODS:")
	fmt.Printf("   • Emergency bypass: sudo emergency-mfa-bypass enable\n")
	if m.config.EmergencyGroupName != "" {
		fmt.Printf("   • Emergency group: %s\n", m.config.EmergencyGroupName)
	}
	if m.config.CreateBackupAdmin {
		fmt.Printf("   • Backup admin: %s (see %s/emergency-admin-creds.txt)\n",
			m.config.BackupAdminUser, m.backupDir)
	}
	fmt.Printf("   • Manual restore: bash %s/restore.sh\n", m.backupDir)

	fmt.Println("\n USER SETUP REQUIRED:")
	fmt.Println("   All sudo users must configure MFA:")
	fmt.Println("   1. Run: sudo setup-mfa")
	fmt.Println("   2. Install authenticator app and scan QR code")
	fmt.Println("   3. Save emergency backup codes")
	fmt.Println("   4. Test: sudo whoami")

	fmt.Println("\n MANAGEMENT COMMANDS:")
	fmt.Println("   • sudo setup-mfa - Configure MFA for current user")
	fmt.Println("   • sudo mfa-status - Check MFA configuration status")
	fmt.Println("   • sudo emergency-mfa-bypass - Emergency access controls")

	fmt.Printf("\n📚 DOCUMENTATION:")
	fmt.Printf("   • Implementation report: %s/implementation-report.md\n", m.backupDir)
	fmt.Printf("   • Recovery guide: /usr/local/share/eos/mfa-recovery.md\n")
	fmt.Printf("   • User instructions: ~/MFA_SETUP_REQUIRED.txt\n")

	fmt.Println("\n⚠️  IMPORTANT REMINDERS:")
	fmt.Println("   1. Test MFA access in a NEW terminal before closing this session")
	fmt.Println("   2. Ensure all users complete MFA setup")
	fmt.Println("   3. Keep emergency access credentials secure but accessible")
	fmt.Println("   4. Document any custom sudo configurations")

	fmt.Println("\n" + strings.Repeat("=", 80))

	m.logger.Info("🎉 MFA implementation completed successfully")
}
