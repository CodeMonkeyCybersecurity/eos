// pkg/alerts/fuzz_test.go

package alerts

import (
	"fmt"
	"html/template"
	"net/mail"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// FuzzRenderEmail tests email rendering with various inputs
func FuzzRenderEmail(f *testing.F) {
	// Add seed corpus
	seeds := []struct {
		title       string
		description string
		host        string
		ruleID      string
		htmlDetails string
	}{
		{"Normal Alert", "This is a normal alert", "localhost", "rule-001", ""},
		{"", "", "", "", ""},
		{"Alert with <script>", "Description with <script>alert('xss')</script>", "host", "xss-test", "<script>alert('xss')</script>"},
		{"Very Long Title " + strings.Repeat("A", 1000), strings.Repeat("B", 10000), "host", "long", ""},
		{"Unicode 测试 Тест", "Unicode description 中文 русский", "🚨-host", "unicode", ""},
		{"Special Chars !@#$%^&*()", "Special <>&\"'", "host", "special", ""},
		{"Newlines\nand\rcarriage\r\nreturns", "Multiple\n\nlines", "host", "newline", ""},
		{"${variable} injection", "$(command) `backtick`", "host", "injection", ""},
		{"SQL ' OR '1'='1", "SQL injection test", "host", "sql", ""},
		{"Path ../../../etc/passwd", "Path traversal", "host", "path", ""},
	}

	for _, seed := range seeds {
		f.Add(seed.title, seed.description, seed.host, seed.ruleID, seed.htmlDetails)
	}

	f.Fuzz(func(t *testing.T, title, description, host, ruleID, htmlDetails string) {
		// Skip invalid UTF-8
		if !utf8.ValidString(title) || !utf8.ValidString(description) || 
		   !utf8.ValidString(host) || !utf8.ValidString(ruleID) || !utf8.ValidString(htmlDetails) {
			t.Skip("Skipping non-UTF8 input")
		}

		alert := Alert{
			Time:        time.Now(),
			Severity:    2,
			RuleID:      ruleID,
			Title:       title,
			Description: description,
			Host:        host,
			Meta:        map[string]any{"fuzz": true},
		}
		
		if htmlDetails != "" {
			alert.HTMLDetails = template.HTML(htmlDetails)
		}

		// Should not panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("RenderEmail panicked with inputs: title=%q, desc=%q, host=%q: %v", 
						title, description, host, r)
				}
			}()

			rendered, err := RenderEmail(alert)
			
			// Check basic invariants
			if err == nil {
				// Must have text output
				if rendered.Text == "" {
					t.Errorf("Empty text output for alert: %+v", alert)
				}
				
				// Subject should not be empty (unless title is empty)
				if title != "" && rendered.Subject == "" {
					t.Errorf("Empty subject for non-empty title: %q", title)
				}
				
				// Check for potential security issues in output
				checkSecurityInvariants(t, rendered, alert)
			}
		}()
	})
}

// FuzzBuildMime tests MIME message building
func FuzzBuildMime(f *testing.F) {
	// Add seed corpus
	seeds := []struct {
		fromName  string
		fromAddr  string
		toName    string
		toAddr    string
		subject   string
		text      string
		html      string
	}{
		{"Sender", "sender@example.com", "Recipient", "recipient@example.com", "Subject", "Text", "<p>HTML</p>"},
		{"", "minimal@example.com", "", "minimal@example.com", "", "", ""},
		{"Unicode 中文", "unicode@example.com", "Юникод", "unicode@example.com", "测试 Subject", "Text", ""},
		{"Special <>&", "special@example.com", "Special \"'", "special@example.com", "Special <>&\"'", "Text", ""},
		{strings.Repeat("A", 100), "long@example.com", strings.Repeat("B", 100), "long@example.com", strings.Repeat("C", 200), strings.Repeat("D", 1000), ""},
		{"Newline\nName", "newline@example.com", "Carriage\rReturn", "cr@example.com", "Subject\nWith\nNewlines", "Text\nWith\nNewlines", ""},
	}

	for _, seed := range seeds {
		f.Add(seed.fromName, seed.fromAddr, seed.toName, seed.toAddr, seed.subject, seed.text, seed.html)
	}

	f.Fuzz(func(t *testing.T, fromName, fromAddr, toName, toAddr, subject, text, html string) {
		// Skip invalid UTF-8
		if !utf8.ValidString(fromName) || !utf8.ValidString(fromAddr) ||
		   !utf8.ValidString(toName) || !utf8.ValidString(toAddr) ||
		   !utf8.ValidString(subject) || !utf8.ValidString(text) || !utf8.ValidString(html) {
			t.Skip("Skipping non-UTF8 input")
		}

		// Skip invalid email addresses
		if !isValidEmailFormat(fromAddr) || !isValidEmailFormat(toAddr) {
			t.Skip("Skipping invalid email format")
		}

		from := mail.Address{Name: fromName, Address: fromAddr}
		to := []mail.Address{{Name: toName, Address: toAddr}}

		// Should not panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("buildMime panicked: %v", r)
				}
			}()

			mime := buildMime(from, to, subject, text, html)
			mimeStr := string(mime)

			// Verify MIME structure
			if !strings.Contains(mimeStr, "MIME-Version: 1.0") {
				t.Error("Missing MIME-Version header")
			}
			
			if !strings.Contains(mimeStr, "Content-Type: multipart/alternative") {
				t.Error("Missing multipart/alternative content type")
			}
			
			// Check for header injection
			checkHeaderInjection(t, mimeStr, subject, fromName, toName)
		}()
	})
}

// FuzzSMTPConfig tests SMTP configuration handling
func FuzzSMTPConfig(f *testing.F) {
	// Add seed corpus
	seeds := []struct {
		host string
		user string
		pass string
		from string
		to   string
		port int
	}{
		{"smtp.example.com", "user@example.com", "password", "from@example.com", "to@example.com", 587},
		{"localhost", "user", "pass", "from@localhost", "to@localhost", 25},
		{"", "", "", "", "", 0},
		{"mail.server.com", "user@domain.com", "p@$$w0rd!", "sender@domain.com", "recipient@domain.com", 465},
		{"192.168.1.1", "admin", "admin123", "admin@local", "user@local", 2525},
		{"[::1]", "ipv6user", "ipv6pass", "ipv6@localhost", "ipv6@localhost", 25},
		{strings.Repeat("A", 255), strings.Repeat("B", 100), strings.Repeat("C", 100), "long@example.com", "long@example.com", 65535},
	}

	for _, seed := range seeds {
		f.Add(seed.host, seed.user, seed.pass, seed.from, seed.to, seed.port)
	}

	f.Fuzz(func(t *testing.T, host, user, pass, from, to string, port int) {
		// Skip invalid UTF-8
		if !utf8.ValidString(host) || !utf8.ValidString(user) || 
		   !utf8.ValidString(pass) || !utf8.ValidString(from) || !utf8.ValidString(to) {
			t.Skip("Skipping non-UTF8 input")
		}

		// Skip clearly invalid configs
		if port < 0 || port > 65535 {
			t.Skip("Invalid port number")
		}

		if from != "" && !isValidEmailFormat(from) {
			t.Skip("Invalid from email format")
		}

		if to != "" && !isValidEmailFormat(to) {
			t.Skip("Invalid to email format")
		}

		config := SMTPConfig{
			Host: host,
			User: user,
			Pass: pass,
			From: from,
			To:   to,
			Port: port,
		}

		// Should not panic
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("NewSMTPSender panicked with config: %+v: %v", config, r)
				}
			}()

			sender := NewSMTPSender(config)
			
			// Type assert to verify internal state
			if s, ok := sender.(*smtpSender); ok {
				// Verify address formatting
				expectedAddr := fmt.Sprintf("%s:%d", host, port)
				if s.addr != expectedAddr {
					t.Errorf("Unexpected address: got %q, want %q", s.addr, expectedAddr)
				}
				
				// Check for potential security issues
				if strings.Contains(pass, "\n") || strings.Contains(pass, "\r") {
					t.Log("Warning: Password contains newline characters")
				}
			}
		}()
	})
}

// FuzzAlertMeta tests alert metadata handling
func FuzzAlertMeta(f *testing.F) {
	// Add various metadata combinations
	f.Add("key1", "value1", "key2", "value2")
	f.Add("", "", "", "")
	f.Add("unicode_key_中文", "unicode_value_русский", "emoji_🔑", "emoji_value_🚨")
	f.Add("injection_${}", "injection_$()", "backtick_`", "semicolon_;")
	f.Add(strings.Repeat("long_key_", 100), strings.Repeat("long_value_", 100), "k", "v")

	f.Fuzz(func(t *testing.T, key1, value1, key2, value2 string) {
		// Skip invalid UTF-8
		if !utf8.ValidString(key1) || !utf8.ValidString(value1) ||
		   !utf8.ValidString(key2) || !utf8.ValidString(value2) {
			t.Skip("Skipping non-UTF8 input")
		}

		alert := Alert{
			Time:        time.Now(),
			Severity:    1,
			RuleID:      "fuzz-meta",
			Title:       "Fuzz Meta Test",
			Description: "Testing metadata",
			Host:        "test-host",
			Meta:        make(map[string]any),
		}

		// Add metadata
		if key1 != "" {
			alert.Meta[key1] = value1
		}
		if key2 != "" {
			alert.Meta[key2] = value2
		}

		// Test rendering with metadata
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("RenderEmail panicked with meta keys %q, %q: %v", key1, key2, r)
				}
			}()

			rendered, err := RenderEmail(alert)
			if err != nil {
				// Error is acceptable for edge cases
				return
			}

			// Verify metadata doesn't break output
			if rendered.Text == "" {
				t.Error("Empty text with metadata")
			}
		}()
	})
}

// Helper functions

func isValidEmailFormat(email string) bool {
	if email == "" {
		return false
	}
	// Basic validation - must contain @ and not start/end with it
	atIndex := strings.Index(email, "@")
	if atIndex <= 0 || atIndex >= len(email)-1 {
		return false
	}
	// No multiple @
	if strings.Count(email, "@") != 1 {
		return false
	}
	// No newlines or carriage returns
	if strings.ContainsAny(email, "\n\r") {
		return false
	}
	return true
}

func checkSecurityInvariants(t *testing.T, rendered Rendered, alert Alert) {
	// Check that plain text doesn't contain unescaped HTML from description
	if strings.Contains(alert.Description, "<script>") {
		if strings.Contains(rendered.Text, "<script>") {
			// This might be OK for plain text, but log it
			t.Log("Warning: Plain text contains script tags")
		}
	}
	
	// Check for null bytes
	if strings.Contains(rendered.Subject, "\x00") ||
	   strings.Contains(rendered.Text, "\x00") ||
	   strings.Contains(rendered.HTML, "\x00") {
		t.Error("Output contains null bytes")
	}
}

func checkHeaderInjection(t *testing.T, mimeStr, subject, fromName, toName string) {
	// Count newlines in headers vs body
	headerEnd := strings.Index(mimeStr, "\r\n\r\n")
	if headerEnd == -1 {
		t.Error("Invalid MIME structure: no header/body separator")
		return
	}
	
	headers := mimeStr[:headerEnd]
	
	// Check if user input added extra headers
	if strings.Contains(subject, "\n") || strings.Contains(subject, "\r") {
		// Subject should be properly encoded
		lines := strings.Split(headers, "\r\n")
		subjectLines := 0
		for _, line := range lines {
			if strings.HasPrefix(line, "Subject:") {
				subjectLines++
			}
		}
		if subjectLines > 1 {
			t.Error("Subject header injection detected")
		}
	}
}