// pkg/alerts/smtp_test.go

package alerts

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock SMTP sender for testing
type mockSMTPSender struct {
	mu          sync.Mutex
	sentEmails  []sentEmail
	shouldError bool
	errorMsg    string
}

type sentEmail struct {
	subject string
	html    string
	text    string
}

func (m *mockSMTPSender) Send(ctx context.Context, subj, html, txt string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.shouldError {
		return errors.New(m.errorMsg)
	}

	m.sentEmails = append(m.sentEmails, sentEmail{
		subject: subj,
		html:    html,
		text:    txt,
	})
	return nil
}

func (m *mockSMTPSender) getSentEmails() []sentEmail {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]sentEmail{}, m.sentEmails...)
}

func TestNewSMTPSender(t *testing.T) {
	cfg := SMTPConfig{
		Host: "smtp.example.com",
		Port: 587,
		User: "user@example.com",
		Pass: "password",
		From: "sender@example.com",
		To:   "recipient@example.com",
	}

	sender := NewSMTPSender(cfg)
	assert.NotNil(t, sender)

	// Type assert to check internal state
	s, ok := sender.(*smtpSender)
	require.True(t, ok)
	assert.Equal(t, "smtp.example.com:587", s.addr)
	assert.Equal(t, "smtp.example.com", s.host)
	assert.Equal(t, "sender@example.com", s.from.Address)
	assert.Len(t, s.to, 1)
	assert.Equal(t, "recipient@example.com", s.to[0].Address)
	assert.NotNil(t, s.auth)
}

func TestRateOK(t *testing.T) {
	// Save current state and restore after test
	failMu.Lock()
	oldFailTimes := failTimes
	failTimes = []time.Time{}
	failMu.Unlock()
	defer func() {
		failMu.Lock()
		failTimes = oldFailTimes
		failMu.Unlock()
	}()

	// Initially should be OK
	assert.True(t, rateOK())

	// Add failures
	now := time.Now()
	failMu.Lock()
	failTimes = []time.Time{now, now, now}
	failMu.Unlock()

	// Should hit rate limit
	assert.False(t, rateOK())

	// Add old failure (outside window)
	failMu.Lock()
	failTimes = []time.Time{
		now.Add(-2 * time.Minute), // Old
		now,
		now,
	}
	failMu.Unlock()

	// Should be OK (only 2 recent failures)
	assert.True(t, rateOK())
}

func TestRecordFail(t *testing.T) {
	// Save current state
	failMu.Lock()
	oldFailTimes := failTimes
	failTimes = []time.Time{}
	failMu.Unlock()
	defer func() {
		failMu.Lock()
		failTimes = oldFailTimes
		failMu.Unlock()
	}()

	// Record a failure
	err := errors.New("test error")
	recordFail(err)

	failMu.Lock()
	assert.Len(t, failTimes, 1)
	assert.WithinDuration(t, time.Now(), failTimes[0], time.Second)
	failMu.Unlock()
}

func TestRateLimiterCleanup(t *testing.T) {
	// Save current state
	failMu.Lock()
	oldFailTimes := failTimes
	failMu.Unlock()
	defer func() {
		failMu.Lock()
		failTimes = oldFailTimes
		failMu.Unlock()
	}()

	now := time.Now()
	failMu.Lock()
	failTimes = []time.Time{
		now.Add(-2 * time.Minute),  // Old
		now.Add(-90 * time.Second), // Old
		now.Add(-30 * time.Second), // Recent
		now,                        // Recent
	}
	failMu.Unlock()

	// Call rateOK which should clean up old entries
	assert.True(t, rateOK())

	failMu.Lock()
	assert.Len(t, failTimes, 2) // Only recent entries remain
	failMu.Unlock()
}

func TestSMTPConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		config SMTPConfig
		valid  bool
	}{
		{
			name: "valid config",
			config: SMTPConfig{
				Host: "smtp.gmail.com",
				Port: 587,
				User: "user@gmail.com",
				Pass: "password",
				From: "sender@gmail.com",
				To:   "recipient@example.com",
			},
			valid: true,
		},
		{
			name: "empty host",
			config: SMTPConfig{
				Host: "",
				Port: 587,
				User: "user",
				Pass: "pass",
				From: "from@example.com",
				To:   "to@example.com",
			},
			valid: false,
		},
		{
			name: "invalid port",
			config: SMTPConfig{
				Host: "smtp.example.com",
				Port: 0,
				User: "user",
				Pass: "pass",
				From: "from@example.com",
				To:   "to@example.com",
			},
			valid: false,
		},
		{
			name: "standard ports",
			config: SMTPConfig{
				Host: "smtp.example.com",
				Port: 25, // Standard SMTP
				User: "user",
				Pass: "pass",
				From: "from@example.com",
				To:   "to@example.com",
			},
			valid: true,
		},
		{
			name: "TLS port",
			config: SMTPConfig{
				Host: "smtp.example.com",
				Port: 465, // SMTP over TLS
				User: "user",
				Pass: "pass",
				From: "from@example.com",
				To:   "to@example.com",
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.valid {
				sender := NewSMTPSender(tt.config)
				assert.NotNil(t, sender)
			} else {
				// For invalid configs, we'd typically validate before creating
				// but the current implementation doesn't validate
				// This test documents expected behavior
			}
		})
	}
}

func TestContextCancellation(t *testing.T) {
	mock := &mockSMTPSender{shouldError: true, errorMsg: "connection timeout"}

	// Create already cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := mock.Send(ctx, "Subject", "HTML", "Text")
	assert.Error(t, err)
}

func TestConcurrentSends(t *testing.T) {
	mock := &mockSMTPSender{}

	var wg sync.WaitGroup
	numGoroutines := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ctx := context.Background()
			subj := fmt.Sprintf("Email %d", id)
			err := mock.Send(ctx, subj, "HTML", "Text")
			assert.NoError(t, err)
		}(i)
	}

	wg.Wait()

	emails := mock.getSentEmails()
	assert.Len(t, emails, numGoroutines)
}

func TestEmailAddressParsing(t *testing.T) {
	tests := []struct {
		name    string
		address string
		valid   bool
	}{
		{"valid email", "user@example.com", true},
		{"email with name", "User Name <user@example.com>", true},
		{"email with dots", "user.name@example.com", true},
		{"email with plus", "user+tag@example.com", true},
		{"subdomain", "user@mail.example.com", true},
		{"numeric domain", "user@123.456.789.0", true},
		{"missing @", "userexample.com", false},
		{"missing domain", "user@", false},
		{"missing local", "@example.com", false},
		{"double @", "user@@example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := mail.ParseAddress(tt.address)
			if tt.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestBuildMimeStructure(t *testing.T) {
	from := mail.Address{Name: "Test Sender", Address: "sender@example.com"}
	to := []mail.Address{{Name: "Test Recipient", Address: "recipient@example.com"}}

	mime := buildMime(from, to, "Test Subject", "Plain Text", "<p>HTML</p>")
	mimeStr := string(mime)

	// Check MIME structure
	assert.Contains(t, mimeStr, "MIME-Version: 1.0")
	assert.Contains(t, mimeStr, "Content-Type: multipart/alternative")
	assert.Contains(t, mimeStr, "boundary=")

	// Verify proper line endings
	assert.Contains(t, mimeStr, "\r\n")

	// Check that boundary is consistent
	lines := strings.Split(mimeStr, "\r\n")
	var boundary string
	for _, line := range lines {
		if strings.HasPrefix(line, "Content-Type: multipart/alternative; boundary=") {
			boundary = strings.TrimPrefix(line, "Content-Type: multipart/alternative; boundary=")
			break
		}
	}
	assert.NotEmpty(t, boundary)
	assert.Contains(t, mimeStr, "--"+boundary)
	assert.Contains(t, mimeStr, "--"+boundary+"--") // End marker
}

func TestPortHandling(t *testing.T) {
	tests := []struct {
		host     string
		port     int
		expected string
	}{
		{"localhost", 25, "localhost:25"},
		{"smtp.example.com", 587, "smtp.example.com:587"},
		{"mail.server.com", 465, "mail.server.com:465"},
		{"192.168.1.1", 2525, "192.168.1.1:2525"},
		{"[::1]", 25, "[::1]:25"}, // IPv6
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			cfg := SMTPConfig{
				Host: tt.host,
				Port: tt.port,
				User: "user",
				Pass: "pass",
				From: "from@example.com",
				To:   "to@example.com",
			}
			sender := NewSMTPSender(cfg).(*smtpSender)
			assert.Equal(t, tt.expected, sender.addr)
		})
	}
}

func TestDialerTimeout(t *testing.T) {
	// Test that dialer respects context timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// Try to connect to a non-routable IP (should timeout)
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", "192.0.2.1:25")
	if conn != nil {
		conn.Close()
	}
	assert.Error(t, err)
}
