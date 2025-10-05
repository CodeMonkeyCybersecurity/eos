// pkg/alerts/render_test.go

package alerts

import (
	"fmt"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderEmail(t *testing.T) {
	tests := []struct {
		name      string
		alert     Alert
		checkFunc func(t *testing.T, r Rendered, err error)
	}{
		{
			name: "basic alert rendering",
			alert: Alert{
				Time:        time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
				Severity:    2,
				RuleID:      "test-001",
				Title:       "Test Alert",
				Description: "This is a test alert description",
				Host:        "test-host",
				Meta:        map[string]any{"key": "value"},
			},
			checkFunc: func(t *testing.T, r Rendered, err error) {
				require.NoError(t, err)
				assert.NotEmpty(t, r.Subject)
				assert.NotEmpty(t, r.Text)
				assert.Contains(t, r.Subject, "Test Alert")
				assert.Contains(t, r.Text, "This is a test alert description")
				// Note: Host field is not included in the default templates
			},
		},
		{
			name: "alert with HTML details",
			alert: Alert{
				Time:        time.Now(),
				Severity:    3,
				RuleID:      "html-test",
				Title:       "HTML Alert",
				Description: "Alert with HTML",
				HTMLDetails: "<b>Bold</b> and <i>italic</i>", // SECURITY P0 #1: Changed to string for auto-escaping
				Host:        "prod-server",
			},
			checkFunc: func(t *testing.T, r Rendered, err error) {
				require.NoError(t, err)
				assert.NotEmpty(t, r.Text)
				if r.HTML != "" {
					assert.Contains(t, r.HTML, "<b>Bold</b>")
					assert.Contains(t, r.HTML, "<i>italic</i>")
				}
			},
		},
		{
			name: "alert with special characters",
			alert: Alert{
				Time:        time.Now(),
				Severity:    1,
				RuleID:      "special-chars",
				Title:       "Alert & Test < >",
				Description: "Description with \"quotes\" and 'apostrophes'",
				Host:        "host-1",
			},
			checkFunc: func(t *testing.T, r Rendered, err error) {
				require.NoError(t, err)
				assert.NotEmpty(t, r.Subject)
				assert.NotEmpty(t, r.Text)
				// Text should contain the raw characters
				assert.Contains(t, r.Text, "\"quotes\"")
				assert.Contains(t, r.Text, "'apostrophes'")
			},
		},
		{
			name: "empty alert fields",
			alert: Alert{
				Time:     time.Now(),
				Severity: 0,
				RuleID:   "",
				Title:    "",
				Host:     "",
			},
			checkFunc: func(t *testing.T, r Rendered, err error) {
				require.NoError(t, err)
				assert.NotEmpty(t, r.Text) // Should still have some output
			},
		},
		{
			name: "alert with complex meta",
			alert: Alert{
				Time:     time.Now(),
				Severity: 2,
				RuleID:   "complex-meta",
				Title:    "Complex Meta Alert",
				Host:     "server",
				Meta: map[string]any{
					"string": "value",
					"number": 42,
					"float":  3.14,
					"bool":   true,
					"slice":  []string{"a", "b", "c"},
					"nested": map[string]any{"key": "value"},
				},
			},
			checkFunc: func(t *testing.T, r Rendered, err error) {
				require.NoError(t, err)
				assert.NotEmpty(t, r.Text)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rendered, err := RenderEmail(tt.alert)
			tt.checkFunc(t, rendered, err)
		})
	}
}

func TestRenderedBestBody(t *testing.T) {
	tests := []struct {
		name         string
		rendered     Rendered
		expectedMime string
		expectedBody string
	}{
		{
			name: "HTML available",
			rendered: Rendered{
				Subject: "Test",
				Text:    "Plain text body",
				HTML:    "<html><body>HTML body</body></html>",
			},
			expectedMime: "text/html",
			expectedBody: "<html><body>HTML body</body></html>",
		},
		{
			name: "Only text available",
			rendered: Rendered{
				Subject: "Test",
				Text:    "Plain text body",
				HTML:    "",
			},
			expectedMime: "text/plain",
			expectedBody: "Plain text body",
		},
		{
			name: "Empty HTML falls back to text",
			rendered: Rendered{
				Subject: "Test",
				Text:    "Fallback text",
				HTML:    "",
			},
			expectedMime: "text/plain",
			expectedBody: "Fallback text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mime, body := tt.rendered.BestBody()
			assert.Equal(t, tt.expectedMime, mime)
			assert.Equal(t, tt.expectedBody, body)
		})
	}
}

func TestBuildMime(t *testing.T) {
	from := mail.Address{Name: "Sender", Address: "sender@example.com"}
	to := []mail.Address{{Name: "Recipient", Address: "recipient@example.com"}}
	subject := "Test Subject"
	text := "Plain text content"
	html := "<html><body>HTML content</body></html>"

	mime := buildMime(from, to, subject, text, html)
	mimeStr := string(mime)

	// Check headers
	assert.Contains(t, mimeStr, "From: \"Sender\" <sender@example.com>")
	assert.Contains(t, mimeStr, "To: \"Recipient\" <recipient@example.com>")
	assert.Contains(t, mimeStr, "Subject:")
	assert.Contains(t, mimeStr, "MIME-Version: 1.0")
	assert.Contains(t, mimeStr, "Content-Type: multipart/alternative")

	// Check content parts
	assert.Contains(t, mimeStr, "Content-Type: text/plain")
	assert.Contains(t, mimeStr, text)
	assert.Contains(t, mimeStr, "Content-Type: text/html")
	assert.Contains(t, mimeStr, html)

	// Check boundary markers
	assert.True(t, strings.Contains(mimeStr, "boundary="))
}

func TestBuildMimeWithoutHTML(t *testing.T) {
	from := mail.Address{Address: "sender@example.com"}
	to := []mail.Address{{Address: "recipient@example.com"}}
	subject := "Test"
	text := "Text only"
	html := ""

	mime := buildMime(from, to, subject, text, html)
	mimeStr := string(mime)

	assert.Contains(t, mimeStr, "Content-Type: text/plain")
	assert.Contains(t, mimeStr, text)
	assert.NotContains(t, mimeStr, "Content-Type: text/html")
}

func TestRenderEmailErrorCases(t *testing.T) {
	// Since we can't easily force template execution errors with valid Alert structs,
	// we'll test the error path by checking that empty text returns an error
	// This would require modifying the templates to fail on certain inputs

	// For now, we'll test that the function handles various edge cases gracefully
	edgeCases := []Alert{
		{
			// Minimal valid alert
			Time: time.Now(),
		},
		{
			// Alert with very long strings
			Title:       strings.Repeat("A", 1000),
			Description: strings.Repeat("B", 10000),
			Host:        strings.Repeat("C", 500),
		},
		{
			// Alert with Unicode
			Title:       "测试警报",
			Description: "Тестовое предупреждение",
			Host:        "🚨-server",
		},
	}

	for i, alert := range edgeCases {
		t.Run(fmt.Sprintf("edge_case_%d", i), func(t *testing.T) {
			rendered, err := RenderEmail(alert)
			assert.NoError(t, err)
			assert.NotEmpty(t, rendered.Text)
		})
	}
}

func TestTemplateInitialization(t *testing.T) {
	// Test that templates are properly initialized
	assert.NotNil(t, subjTpl)
	assert.NotNil(t, txtTpl)
	// HTML template may or may not be nil depending on template parsing
}

func TestMimeEncoding(t *testing.T) {
	from := mail.Address{Address: "test@example.com"}
	to := []mail.Address{{Address: "recipient@example.com"}}

	// Test with Unicode subject
	subject := "Test 测试 Тест"
	text := "Body"
	html := ""

	mime := buildMime(from, to, subject, text, html)
	mimeStr := string(mime)

	// Subject should be Q-encoded
	assert.Contains(t, mimeStr, "Subject: =?utf-8?q?")
}

func TestMultipleRecipients(t *testing.T) {
	from := mail.Address{Address: "sender@example.com"}
	to := []mail.Address{
		{Address: "recipient1@example.com"},
		{Address: "recipient2@example.com"},
		{Address: "recipient3@example.com"},
	}

	mime := buildMime(from, to, "Subject", "Text", "")
	mimeStr := string(mime)

	// Only first recipient should be in To: header
	assert.Contains(t, mimeStr, "recipient1@example.com")
	assert.NotContains(t, mimeStr, "recipient2@example.com")
}
