// pkg/security/audit.go
package security

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"go.uber.org/zap"
)

// AuditEvent represents a security audit event
type AuditEvent struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	EventType string                 `json:"event_type"`
	Actor     string                 `json:"actor"`
	Resource  string                 `json:"resource"`
	Action    string                 `json:"action"`
	Result    string                 `json:"result"`
	IP        string                 `json:"ip,omitempty"`
	UserAgent string                 `json:"user_agent,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	RiskScore int                    `json:"risk_score"`
}

// AuditLogger provides comprehensive security audit logging
type AuditLogger struct {
	logDir     string
	maxLogSize int64
	logger     *zap.Logger
}

// NewAuditLogger creates a new security audit logger
func NewAuditLogger(rc *eos_io.RuntimeContext, logDir string) (*AuditLogger, error) {
	// Ensure audit log directory exists with secure permissions
	if err := os.MkdirAll(logDir, shared.SecretDirPerm); err != nil {
		return nil, fmt.Errorf("creating audit log directory: %w", err)
	}

	return &AuditLogger{
		logDir:     logDir,
		maxLogSize: 100 * 1024 * 1024, // 100MB
		logger:     rc.Log,
	}, nil
}

// LogEvent logs a security audit event
func (al *AuditLogger) LogEvent(ctx context.Context, event AuditEvent) error {
	// Add timestamp if not set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Add context information
	if event.ID == "" {
		event.ID = generateEventID()
	}

	// Calculate risk score if not set
	if event.RiskScore == 0 {
		event.RiskScore = calculateRiskScore(event)
	}

	// Log to structured logger
	al.logger.Info("Security audit event",
		zap.String("event_id", event.ID),
		zap.String("event_type", event.EventType),
		zap.String("actor", event.Actor),
		zap.String("action", event.Action),
		zap.String("result", event.Result),
		zap.Int("risk_score", event.RiskScore))

	// Write to audit log file
	return al.writeToFile(event)
}

// writeToFile writes the audit event to a file
func (al *AuditLogger) writeToFile(event AuditEvent) error {
	// Create daily log file
	filename := filepath.Join(al.logDir, fmt.Sprintf("audit-%s.log",
		event.Timestamp.Format("2006-01-02")))

	// Open file with append mode and secure permissions
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("opening audit log file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			// Log error if needed
		}
	}()

	// Check file size for rotation
	info, err := file.Stat()
	if err == nil && info.Size() > al.maxLogSize {
		if err := al.rotateLog(filename); err != nil {
			al.logger.Error("Failed to rotate audit log", zap.Error(err))
		}
	}

	// Write event as JSON
	encoder := json.NewEncoder(file)
	if err := encoder.Encode(event); err != nil {
		return fmt.Errorf("writing audit event: %w", err)
	}

	// Sync to ensure write
	return file.Sync()
}

// rotateLog rotates the audit log file
func (al *AuditLogger) rotateLog(filename string) error {
	timestamp := time.Now().Unix()
	rotatedName := fmt.Sprintf("%s.%d", filename, timestamp)

	return os.Rename(filename, rotatedName)
}

// calculateRiskScore calculates a risk score for the event
func calculateRiskScore(event AuditEvent) int {
	score := 0

	// Failed actions increase risk
	if event.Result == "failure" || event.Result == "denied" {
		score += 30
	}

	// Certain event types are higher risk
	riskEventTypes := map[string]int{
		"authentication_failure": 40,
		"authorization_failure":  35,
		"privilege_escalation":   50,
		"configuration_change":   25,
		"secret_access":          30,
		"system_command":         35,
	}

	if typeScore, ok := riskEventTypes[event.EventType]; ok {
		score += typeScore
	}

	// Suspicious patterns
	if event.IP != "" && !isInternalIP(event.IP) {
		score += 10
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// generateEventID creates a unique event ID
func generateEventID() string {
	return fmt.Sprintf("evt_%d_%s", time.Now().UnixNano(), generateRandomString(8))
}

// isInternalIP checks if an IP address is internal/private
func isInternalIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check for loopback
	if parsedIP.IsLoopback() {
		return true
	}

	// Check for private ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil && network.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// generateRandomString generates a random string of specified length
func generateRandomString(length int) string {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		return "fallback"
	}
	return hex.EncodeToString(bytes)[:length]
}
