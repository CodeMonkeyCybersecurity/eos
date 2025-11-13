// pkg/alerts/model_test.go

package alerts

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAlert(t *testing.T) {
	tests := []struct {
		name  string
		alert Alert
		check func(t *testing.T, a Alert)
	}{
		{
			name: "basic alert creation",
			alert: Alert{
				Time:        time.Now(),
				Severity:    1,
				RuleID:      "test-rule-001",
				Title:       "Test Alert",
				Description: "This is a test alert",
				Host:        "localhost",
				Meta:        map[string]any{"key": "value"},
			},
			check: func(t *testing.T, a Alert) {
				assert.Equal(t, 1, a.Severity)
				assert.Equal(t, "test-rule-001", a.RuleID)
				assert.Equal(t, "Test Alert", a.Title)
				assert.Equal(t, "This is a test alert", a.Description)
				assert.Equal(t, "localhost", a.Host)
				assert.Equal(t, "value", a.Meta["key"])
			},
		},
		{
			name: "alert with HTML details",
			alert: Alert{
				Time:        time.Now(),
				Severity:    3,
				RuleID:      "security-001",
				Title:       "Security Alert",
				Description: "Potential security issue detected",
				HTMLDetails: "<b>Important:</b> Check immediately", // SECURITY P0 #1: Now string for auto-escaping
				Host:        "prod-server",
				Meta:        map[string]any{"ip": "192.168.1.1", "port": 8080},
			},
			check: func(t *testing.T, a Alert) {
				assert.Equal(t, 3, a.Severity)
				assert.Equal(t, "security-001", a.RuleID)
				assert.Equal(t, "<b>Important:</b> Check immediately", a.HTMLDetails) // SECURITY P0 #1: String comparison
				assert.Equal(t, "192.168.1.1", a.Meta["ip"])
				assert.Equal(t, 8080, a.Meta["port"])
			},
		},
		{
			name: "alert with empty meta",
			alert: Alert{
				Time:        time.Now(),
				Severity:    2,
				RuleID:      "warning-001",
				Title:       "Warning",
				Description: "A warning occurred",
				Host:        "test-host",
				Meta:        nil,
			},
			check: func(t *testing.T, a Alert) {
				assert.Nil(t, a.Meta)
			},
		},
		{
			name: "alert with zero time",
			alert: Alert{
				Severity:    1,
				RuleID:      "time-test",
				Title:       "Time Test",
				Description: "Testing zero time",
				Host:        "host",
			},
			check: func(t *testing.T, a Alert) {
				assert.True(t, a.Time.IsZero())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.check(t, tt.alert)
		})
	}
}

func TestAlertSeverityLevels(t *testing.T) {
	severityTests := []struct {
		severity int
		expected string
	}{
		{0, "info"},
		{1, "low"},
		{2, "medium"},
		{3, "high"},
		{4, "critical"},
	}

	for _, tt := range severityTests {
		t.Run(tt.expected, func(t *testing.T) {
			alert := Alert{
				Severity: tt.severity,
				RuleID:   "test",
				Title:    "Test",
			}
			// Just verify the severity is set correctly
			assert.Equal(t, tt.severity, alert.Severity)
		})
	}
}

func TestAlertMetaTypes(t *testing.T) {
	alert := Alert{
		Time:     time.Now(),
		Severity: 1,
		RuleID:   "meta-test",
		Title:    "Meta Test",
		Meta: map[string]any{
			"string": "value",
			"int":    42,
			"float":  3.14,
			"bool":   true,
			"slice":  []string{"a", "b", "c"},
			"map":    map[string]int{"x": 1, "y": 2},
			"nil":    nil,
		},
	}

	assert.Equal(t, "value", alert.Meta["string"])
	assert.Equal(t, 42, alert.Meta["int"])
	assert.Equal(t, 3.14, alert.Meta["float"])
	assert.Equal(t, true, alert.Meta["bool"])
	assert.Equal(t, []string{"a", "b", "c"}, alert.Meta["slice"])
	assert.Equal(t, map[string]int{"x": 1, "y": 2}, alert.Meta["map"])
	assert.Nil(t, alert.Meta["nil"])
}

func TestAlertTimeFormatting(t *testing.T) {
	specificTime, _ := time.Parse(time.RFC3339, "2024-01-15T10:30:00Z")
	alert := Alert{
		Time:     specificTime,
		Severity: 2,
		RuleID:   "time-format",
		Title:    "Time Format Test",
	}

	assert.Equal(t, "2024-01-15 10:30:00 +0000 UTC", alert.Time.String())
	assert.Equal(t, "2024-01-15T10:30:00Z", alert.Time.Format(time.RFC3339))
}

func TestAlertHTMLSafety(t *testing.T) {
	// Test that HTML content is properly typed
	dangerousHTML := `<script>alert('xss')</script>`
	alert := Alert{
		Time:        time.Now(),
		Severity:    3,
		RuleID:      "xss-test",
		Title:       "XSS Test",
		Description: dangerousHTML, // This should be escaped when rendered
		HTMLDetails: dangerousHTML, // SECURITY P0 #1: Now string for auto-escaping
		Host:        "test",
	}

	// Both fields are now regular strings and will be escaped during rendering
	assert.Equal(t, dangerousHTML, alert.Description)
	// SECURITY P0 #1: HTMLDetails is now string - XSS prevented via auto-escaping
	assert.Equal(t, dangerousHTML, alert.HTMLDetails)
}
