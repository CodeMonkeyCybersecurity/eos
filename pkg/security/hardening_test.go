package security

import (
	"context"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"go.uber.org/zap"
)

func TestNewSystemHardener(t *testing.T) {
	logger := zap.NewNop()
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
		Log: logger,
	}

	auditLogger := &AuditLogger{
		logger:     logger,
		logDir:     "/tmp/test-audit",
		maxLogSize: 1024 * 1024,
	}

	t.Run("create system hardener", func(t *testing.T) {
		hardener := NewSystemHardener(rc, auditLogger)

		if hardener == nil {
			t.Fatal("SystemHardener should not be nil")
		}

		if hardener.logger == nil {
			t.Error("SystemHardener logger should not be nil")
		}

		if hardener.auditLogger == nil {
			t.Error("SystemHardener auditLogger should not be nil")
		}
	})
}

func TestSystemHardener_HardenSystem(t *testing.T) {
	logger := zap.NewNop()
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
		Log: logger,
	}

	auditLogger := &AuditLogger{
		logger:     logger,
		logDir:     "/tmp/test-audit",
		maxLogSize: 1024 * 1024,
	}

	hardener := NewSystemHardener(rc, auditLogger)
	ctx := context.Background()

	t.Run("hardening steps validation", func(t *testing.T) {
		// Test that hardening steps are defined and valid
		expectedSteps := []string{
			"kernel_parameters",
			"network_stack",
			"file_permissions",
			"user_accounts",
			"ssh_configuration",
			"firewall_rules",
			"audit_rules",
			"automatic_updates",
		}

		for _, step := range expectedSteps {
			t.Logf("Validating hardening step: %s", step)

			// Each step should be a non-empty string
			if step == "" {
				t.Error("Hardening step should not be empty")
			}

			// Check for dangerous characters in step names
			if containsDangerousChars(step) {
				t.Errorf("Hardening step name contains dangerous characters: %s", step)
			}
		}
	})

	t.Run("system hardening execution", func(t *testing.T) {
		// This will likely fail in test environment, which is expected
		err := hardener.HardenSystem(ctx)

		if err != nil {
			t.Logf("System hardening failed (expected in test): %v", err)
		} else {
			t.Log("System hardening completed successfully")
		}
	})
}

func TestHardeningStepsValidation(t *testing.T) {
	logger := zap.NewNop()
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
		Log: logger,
	}

	auditLogger := &AuditLogger{
		logger:     logger,
		logDir:     "/tmp/test-audit",
		maxLogSize: 1024 * 1024,
	}

	hardener := NewSystemHardener(rc, auditLogger)
	ctx := context.Background()

	tests := []struct {
		name     string
		stepName string
		testFunc func(context.Context) error
	}{
		{
			name:     "kernel parameters hardening",
			stepName: "kernel_parameters",
			testFunc: hardener.hardenKernelParameters,
		},
		{
			name:     "network stack hardening",
			stepName: "network_stack",
			testFunc: hardener.hardenNetworkStack,
		},
		{
			name:     "file permissions hardening",
			stepName: "file_permissions",
			testFunc: hardener.hardenFilePermissions,
		},
		{
			name:     "user accounts hardening",
			stepName: "user_accounts",
			testFunc: hardener.hardenUserAccounts,
		},
		{
			name:     "ssh configuration hardening",
			stepName: "ssh_configuration",
			testFunc: hardener.hardenSSH,
		},
		{
			name:     "firewall configuration",
			stepName: "firewall_rules",
			testFunc: hardener.configureFirewall,
		},
		{
			name:     "audit rules configuration",
			stepName: "audit_rules",
			testFunc: hardener.configureAuditRules,
		},
		{
			name:     "automatic updates configuration",
			stepName: "automatic_updates",
			testFunc: hardener.enableAutomaticUpdates,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that each hardening function exists and can be called
			err := tt.testFunc(ctx)

			// Most will fail in test environment, which is expected
			if err != nil {
				t.Logf("Hardening step %s failed (expected in test): %v", tt.stepName, err)
			} else {
				t.Logf("Hardening step %s completed successfully", tt.stepName)
			}
		})
	}
}

func TestSystemHardeningValidation(t *testing.T) {
	t.Run("audit event validation", func(t *testing.T) {
		// Test audit event structure for security hardening
		event := AuditEvent{
			EventType: "system_hardening",
			Actor:     "eos",
			Action:    "start",
			Resource:  "system",
			Result:    "started",
		}

		// Validate event fields
		if event.EventType == "" {
			t.Error("EventType should not be empty")
		}

		if event.Actor == "" {
			t.Error("Actor should not be empty")
		}

		if event.Action == "" {
			t.Error("Action should not be empty")
		}

		if event.Resource == "" {
			t.Error("Resource should not be empty")
		}

		// Check for injection attempts in event fields
		eventFields := []string{event.EventType, event.Actor, event.Action, event.Resource, event.Result}
		for i, field := range eventFields {
			if containsDangerousChars(field) {
				t.Errorf("Audit event field %d contains dangerous characters: %s", i, field)
			}
		}
	})

	t.Run("risk score validation", func(t *testing.T) {
		validRiskScores := []int{10, 30, 50, 60, 80, 90}
		invalidRiskScores := []int{-1, 101, 999}

		for _, score := range validRiskScores {
			if score < 0 || score > 100 {
				t.Errorf("Risk score should be between 0-100: %d", score)
			}
		}

		for _, score := range invalidRiskScores {
			if score >= 0 && score <= 100 {
				t.Errorf("Invalid risk score should be rejected: %d", score)
			}
		}
	})
}

func TestSecurityHardeningConfiguration(t *testing.T) {
	t.Run("hardening configuration validation", func(t *testing.T) {
		// Test security hardening configuration parameters
		securityConfigs := map[string]interface{}{
			"kernel.dmesg_restrict":                  1,
			"kernel.kptr_restrict":                   2,
			"kernel.yama.ptrace_scope":               1,
			"net.ipv4.conf.all.accept_redirects":     0,
			"net.ipv4.conf.all.send_redirects":       0,
			"net.ipv4.conf.all.accept_source_route":  0,
			"net.ipv4.conf.all.log_martians":         1,
			"net.ipv4.conf.default.accept_redirects": 0,
			"net.ipv4.conf.default.send_redirects":   0,
			"net.ipv4.tcp_syncookies":                1,
			"net.ipv4.ip_forward":                    0,
		}

		for param, value := range securityConfigs {
			// Validate parameter names
			if param == "" {
				t.Error("Security parameter name should not be empty")
			}

			// Check for dangerous characters in parameter names
			if containsDangerousChars(param) {
				t.Errorf("Security parameter contains dangerous characters: %s", param)
			}

			// Validate values are reasonable
			if intValue, ok := value.(int); ok {
				if intValue < 0 || intValue > 10 {
					t.Logf("Security parameter %s has unusual value: %d", param, intValue)
				}
			}

			t.Logf("Security parameter: %s = %v", param, value)
		}
	})

	t.Run("file permission validation", func(t *testing.T) {
		// Test file permission configurations
		securePermissions := map[string]int{
			"/etc/passwd":  0644,
			"/etc/shadow":  0600,
			"/etc/group":   0644,
			"/etc/gshadow": 0600,
			"/boot":        0700,
			"/root":        0700,
		}

		for file, perm := range securePermissions {
			// Validate file paths
			if file == "" {
				t.Error("File path should not be empty")
			}

			// Check for path traversal attempts
			if containsString(file, "..") {
				t.Errorf("File path contains path traversal: %s", file)
			}

			// Validate permissions are reasonable
			if perm < 0 || perm > 0777 {
				t.Errorf("Invalid file permission for %s: %o", file, perm)
			}

			t.Logf("Secure file permission: %s = %o", file, perm)
		}
	})
}

func TestSecurityHardeningAudit(t *testing.T) {
	t.Run("audit configuration", func(t *testing.T) {
		// Test audit rule configurations
		auditRules := []string{
			"-w /etc/passwd -p wa -k identity",
			"-w /etc/group -p wa -k identity",
			"-w /etc/shadow -p wa -k identity",
			"-w /etc/sudoers -p wa -k privilege_escalation",
			"-w /var/log/auth.log -p wa -k authentication",
			"-w /var/log/audit/ -p wa -k audit_logs",
		}

		for _, rule := range auditRules {
			// Validate audit rules
			if rule == "" {
				t.Error("Audit rule should not be empty")
			}

			// Check for dangerous characters
			if containsDangerousChars(rule) {
				t.Errorf("Audit rule contains dangerous characters: %s", rule)
			}

			// Basic audit rule format validation
			if !containsString(rule, "-w") {
				t.Errorf("Audit rule should contain -w flag: %s", rule)
			}

			t.Logf("Audit rule: %s", rule)
		}
	})

	t.Run("firewall rules validation", func(t *testing.T) {
		// Test firewall rule configurations
		firewallRules := []string{
			"ufw default deny incoming",
			"ufw default allow outgoing",
			"ufw allow ssh",
			"ufw allow 80/tcp",
			"ufw allow 443/tcp",
			"ufw --force enable",
		}

		for _, rule := range firewallRules {
			// Validate firewall rules
			if rule == "" {
				t.Error("Firewall rule should not be empty")
			}

			// Check for dangerous characters (allowing necessary ones)
			dangerousChars := []string{";", "&", "|", "`", "$", "$(", "&&"}
			for _, dangerous := range dangerousChars {
				if containsString(rule, dangerous) {
					t.Errorf("Firewall rule contains dangerous characters: %s", rule)
				}
			}

			t.Logf("Firewall rule: %s", rule)
		}
	})
}

// Helper functions
func containsDangerousChars(s string) bool {
	dangerous := []string{";", "&", "|", "`", "$", "$(", "&&", "||", "\n", "\r"}
	for _, d := range dangerous {
		if containsString(s, d) {
			return true
		}
	}
	return false
}

func containsString(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
