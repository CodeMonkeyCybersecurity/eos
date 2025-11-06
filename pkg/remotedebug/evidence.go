// pkg/remotedebug/evidence.go
// Structured evidence collection for forensic analysis and compliance

package remotedebug

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// EvidenceType categorizes different types of evidence
type EvidenceType string

const (
	EvidenceTypeFile     EvidenceType = "file"     // File system evidence
	EvidenceTypeCommand  EvidenceType = "command"  // Command output
	EvidenceTypeLogEntry EvidenceType = "log"      // Log file entry
	EvidenceTypeMetric   EvidenceType = "metric"   // System metric
	EvidenceTypeConfig   EvidenceType = "config"   // Configuration file
	EvidenceTypeProcess  EvidenceType = "process"  // Process information
	EvidenceTypeNetwork  EvidenceType = "network"  // Network state
	EvidenceTypeSnapshot EvidenceType = "snapshot" // System snapshot
)

// StructuredEvidence represents a single piece of evidence with metadata
type StructuredEvidence struct {
	Type      EvidenceType      `json:"type"`               // Type of evidence
	Timestamp time.Time         `json:"timestamp"`          // When collected
	Source    string            `json:"source"`             // Where from (hostname/IP)
	Collector string            `json:"collector"`          // Who collected (user@host)
	Data      json.RawMessage   `json:"data"`               // Actual evidence (structured JSON)
	Checksum  string            `json:"checksum"`           // SHA256 for integrity verification
	Metadata  map[string]string `json:"metadata,omitempty"` // Additional context
}

// EvidenceSession represents a complete evidence collection session
type EvidenceSession struct {
	SessionID string               `json:"session_id"` // Unique session identifier
	StartTime time.Time            `json:"start_time"` // Session start
	EndTime   time.Time            `json:"end_time"`   // Session end
	Host      string               `json:"host"`       // Target hostname
	Collector string               `json:"collector"`  // Who ran the collection
	Command   string               `json:"command"`    // Command that triggered collection
	Evidence  []StructuredEvidence `json:"evidence"`   // All collected evidence
	Issues    []Issue              `json:"issues"`     // Detected issues
	Warnings  []Warning            `json:"warnings"`   // Warnings
	Report    *SystemReport        `json:"report"`     // Complete system report
}

// EvidenceRepository manages evidence storage and retrieval
type EvidenceRepository struct {
	baseDir string // Base directory for evidence storage (~/.eos/evidence/)
}

// NewEvidenceRepository creates a new evidence repository
func NewEvidenceRepository() (*EvidenceRepository, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fallback to /tmp if can't get home dir
		homeDir = "/tmp"
	}

	baseDir := filepath.Join(homeDir, ".eos", "evidence")
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create evidence directory: %w", err)
	}

	return &EvidenceRepository{
		baseDir: baseDir,
	}, nil
}

// StoreSession saves a complete evidence session to disk
func (r *EvidenceRepository) StoreSession(session *EvidenceSession) (string, error) {
	// Create session directory
	// Format: ~/.eos/evidence/20251022-143052-hostname/
	sessionDir := filepath.Join(r.baseDir, fmt.Sprintf("%s-%s",
		session.StartTime.Format("20060102-150405"),
		sanitizeFilename(session.Host)))

	if err := os.MkdirAll(sessionDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create session directory: %w", err)
	}

	// Write manifest.json (session metadata)
	manifestPath := filepath.Join(sessionDir, "manifest.json")
	manifestData, err := json.MarshalIndent(map[string]interface{}{
		"session_id":     session.SessionID,
		"start_time":     session.StartTime,
		"end_time":       session.EndTime,
		"host":           session.Host,
		"collector":      session.Collector,
		"command":        session.Command,
		"evidence_count": len(session.Evidence),
		"issue_count":    len(session.Issues),
		"warning_count":  len(session.Warnings),
	}, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal manifest: %w", err)
	}
	if err := os.WriteFile(manifestPath, manifestData, 0644); err != nil {
		return "", fmt.Errorf("failed to write manifest: %w", err)
	}

	// Write evidence.json (all structured evidence)
	evidencePath := filepath.Join(sessionDir, "evidence.json")
	evidenceData, err := json.MarshalIndent(session.Evidence, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal evidence: %w", err)
	}
	if err := os.WriteFile(evidencePath, evidenceData, 0644); err != nil {
		return "", fmt.Errorf("failed to write evidence: %w", err)
	}

	// Write issues.json (detected issues with evidence references)
	issuesPath := filepath.Join(sessionDir, "issues.json")
	issuesData, err := json.MarshalIndent(session.Issues, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal issues: %w", err)
	}
	if err := os.WriteFile(issuesPath, issuesData, 0644); err != nil {
		return "", fmt.Errorf("failed to write issues: %w", err)
	}

	// Write warnings.json
	warningsPath := filepath.Join(sessionDir, "warnings.json")
	warningsData, err := json.MarshalIndent(session.Warnings, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal warnings: %w", err)
	}
	if err := os.WriteFile(warningsPath, warningsData, 0644); err != nil {
		return "", fmt.Errorf("failed to write warnings: %w", err)
	}

	// Write report.json (complete system report)
	reportPath := filepath.Join(sessionDir, "report.json")
	reportData, err := json.MarshalIndent(session.Report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal report: %w", err)
	}
	if err := os.WriteFile(reportPath, reportData, 0644); err != nil {
		return "", fmt.Errorf("failed to write report: %w", err)
	}

	// Write human-readable summary.txt
	summaryPath := filepath.Join(sessionDir, "summary.txt")
	summary := fmt.Sprintf(`Evidence Collection Summary
===========================
Session ID: %s
Host: %s
Collector: %s
Start Time: %s
End Time: %s
Duration: %s

Evidence Collected: %d items
Issues Found: %d
Warnings: %d

Files:
  - manifest.json:  Session metadata
  - evidence.json:  All structured evidence
  - issues.json:    Detected issues
  - warnings.json:  Warnings
  - report.json:    Complete system report

Evidence Location: %s
`,
		session.SessionID,
		session.Host,
		session.Collector,
		session.StartTime.Format(time.RFC3339),
		session.EndTime.Format(time.RFC3339),
		session.EndTime.Sub(session.StartTime).String(),
		len(session.Evidence),
		len(session.Issues),
		len(session.Warnings),
		sessionDir,
	)
	if err := os.WriteFile(summaryPath, []byte(summary), 0644); err != nil {
		return "", fmt.Errorf("failed to write summary: %w", err)
	}

	return sessionDir, nil
}

// CreateEvidence creates a new structured evidence item
func CreateEvidence(evidenceType EvidenceType, source string, data interface{}) (*StructuredEvidence, error) {
	// Marshal data to JSON
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal evidence data: %w", err)
	}

	// Calculate checksum for integrity
	checksum := calculateChecksum(dataJSON)

	// Get collector info (user@hostname)
	collector := getCollectorInfo()

	return &StructuredEvidence{
		Type:      evidenceType,
		Timestamp: time.Now(),
		Source:    source,
		Collector: collector,
		Data:      dataJSON,
		Checksum:  checksum,
		Metadata:  make(map[string]string),
	}, nil
}

// calculateChecksum computes SHA256 checksum for evidence integrity
func calculateChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// getCollectorInfo returns collector identification string
func getCollectorInfo() string {
	// Format: user@hostname
	hostname, _ := os.Hostname()
	// Note: os.User requires CGO, so we use environment variables
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME") // Windows fallback
	}
	if user == "" {
		user = "unknown"
	}

	if hostname == "" {
		hostname = "unknown"
	}

	return fmt.Sprintf("%s@%s", user, hostname)
}

// sanitizeFilename removes characters that aren't safe for filenames
func sanitizeFilename(s string) string {
	// Use filepath.Base to remove path separators
	result := filepath.Base(s)

	// Ensure it's not empty or special directory references
	if result == "" || result == "." || result == ".." {
		result = "unknown"
	}
	return result
}

// VerifyEvidence checks evidence integrity using stored checksum
func (e *StructuredEvidence) VerifyEvidence() bool {
	calculatedChecksum := calculateChecksum([]byte(e.Data))
	return calculatedChecksum == e.Checksum
}

// GetBaseDir returns the evidence repository base directory
func (r *EvidenceRepository) GetBaseDir() string {
	return r.baseDir
}
