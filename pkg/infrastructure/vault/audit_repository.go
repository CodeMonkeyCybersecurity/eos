// Package vault provides infrastructure implementations for vault domain interfaces
package vault

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/vault"
)

// FileAuditRepository implements vault.AuditRepository using file system storage
type FileAuditRepository struct {
	logDir     string
	logFile    string
	mutex      sync.RWMutex
	logger     *zap.Logger
	file       *os.File
	bufWriter  *bufio.Writer
	eventCount int64
}

// NewFileAuditRepository creates a new file-based audit repository
func NewFileAuditRepository(logDir string, logger *zap.Logger) *FileAuditRepository {
	repo := &FileAuditRepository{
		logDir:  logDir,
		logFile: filepath.Join(logDir, "vault-audit.log"),
		logger:  logger.Named("vault.audit"),
	}

	// Ensure log directory exists
	if err := os.MkdirAll(logDir, 0750); err != nil {
		logger.Error("Failed to create audit log directory",
			zap.String("dir", logDir),
			zap.Error(err))
	}

	// Open log file for appending
	if err := repo.openLogFile(); err != nil {
		logger.Error("Failed to open audit log file", zap.Error(err))
	}

	return repo
}

// openLogFile opens the audit log file for writing
func (r *FileAuditRepository) openLogFile() error {
	file, err := os.OpenFile(r.logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return fmt.Errorf("failed to open audit log file: %w", err)
	}

	r.file = file
	r.bufWriter = bufio.NewWriter(file)
	return nil
}

// Record records an audit event
func (r *FileAuditRepository) Record(ctx context.Context, event *vault.AuditEvent) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Ensure file is open
	if r.file == nil {
		if err := r.openLogFile(); err != nil {
			return fmt.Errorf("failed to open audit log: %w", err)
		}
	}

	// Set timestamp if not provided
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Generate ID if not provided
	if event.ID == "" {
		event.ID = fmt.Sprintf("audit_%d_%d", time.Now().Unix(), r.eventCount)
		r.eventCount++
	}

	// Marshal event to JSON
	data, err := json.Marshal(event)
	if err != nil {
		r.logger.Error("Failed to marshal audit event", zap.Error(err))
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	// Write to file
	if _, err := r.bufWriter.Write(data); err != nil {
		r.logger.Error("Failed to write audit event", zap.Error(err))
		return fmt.Errorf("failed to write audit event: %w", err)
	}

	// Add newline
	if _, err := r.bufWriter.WriteString("\n"); err != nil {
		return fmt.Errorf("failed to write newline: %w", err)
	}

	// Flush buffer
	if err := r.bufWriter.Flush(); err != nil {
		return fmt.Errorf("failed to flush audit log: %w", err)
	}

	// Sync to disk
	if err := r.file.Sync(); err != nil {
		r.logger.Warn("Failed to sync audit log to disk", zap.Error(err))
	}

	r.logger.Debug("Audit event recorded",
		zap.String("id", event.ID),
		zap.String("type", event.Type))

	return nil
}

// Query retrieves audit events based on filter criteria
func (r *FileAuditRepository) Query(ctx context.Context, filter *vault.AuditFilter) ([]*vault.AuditEvent, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Read and parse log file
	events, err := r.readLogFile()
	if err != nil {
		return nil, fmt.Errorf("failed to read audit log: %w", err)
	}

	// Apply filters
	filteredEvents := r.applyFilter(events, filter)

	// Apply pagination
	if filter != nil {
		if filter.Offset > 0 && filter.Offset < len(filteredEvents) {
			filteredEvents = filteredEvents[filter.Offset:]
		}
		if filter.Limit > 0 && filter.Limit < len(filteredEvents) {
			filteredEvents = filteredEvents[:filter.Limit]
		}
	}

	r.logger.Debug("Audit events queried",
		zap.Int("total", len(events)),
		zap.Int("filtered", len(filteredEvents)))

	return filteredEvents, nil
}

// GetStats returns audit statistics
func (r *FileAuditRepository) GetStats(ctx context.Context) (*vault.AuditStats, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	events, err := r.readLogFile()
	if err != nil {
		return nil, fmt.Errorf("failed to read audit log: %w", err)
	}

	stats := &vault.AuditStats{
		TotalEvents:  int64(len(events)),
		EventsByType: make(map[string]int64),
		EventsByPath: make(map[string]int64),
	}

	var earliest, latest *time.Time

	for _, event := range events {
		// Count by type
		stats.EventsByType[event.Type]++

		// Count by path
		if event.Request != nil {
			stats.EventsByPath[event.Request.Path]++
		}

		// Track time range
		if earliest == nil || event.Timestamp.Before(*earliest) {
			earliest = &event.Timestamp
		}
		if latest == nil || event.Timestamp.After(*latest) {
			latest = &event.Timestamp
		}
	}

	if latest != nil {
		stats.LastEvent = latest
		stats.TimeRange = &vault.AuditTimeRange{
			Earliest: earliest,
			Latest:   latest,
		}
	}

	r.logger.Debug("Audit statistics calculated",
		zap.Int64("total_events", stats.TotalEvents))

	return stats, nil
}

// readLogFile reads and parses the entire audit log file
func (r *FileAuditRepository) readLogFile() ([]*vault.AuditEvent, error) {
	file, err := os.Open(r.logFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []*vault.AuditEvent{}, nil
		}
		return nil, fmt.Errorf("failed to open audit log for reading: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			r.logger.Warn("Failed to close audit log file", zap.Error(closeErr))
		}
	}()

	var events []*vault.AuditEvent
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var event vault.AuditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			r.logger.Warn("Failed to parse audit log line",
				zap.String("line", line),
				zap.Error(err))
			continue
		}

		events = append(events, &event)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading audit log: %w", err)
	}

	// Sort events by timestamp (newest first)
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.After(events[j].Timestamp)
	})

	return events, nil
}

// applyFilter applies filter criteria to events
func (r *FileAuditRepository) applyFilter(events []*vault.AuditEvent, filter *vault.AuditFilter) []*vault.AuditEvent {
	if filter == nil {
		return events
	}

	var filtered []*vault.AuditEvent

	for _, event := range events {
		// Time range filter
		if filter.StartTime != nil && event.Timestamp.Before(*filter.StartTime) {
			continue
		}
		if filter.EndTime != nil && event.Timestamp.After(*filter.EndTime) {
			continue
		}

		// Operation filter
		if filter.Operation != "" && event.Request != nil {
			if !strings.Contains(event.Request.Operation, filter.Operation) {
				continue
			}
		}

		// Path filter
		if filter.Path != "" && event.Request != nil {
			if !strings.Contains(event.Request.Path, filter.Path) {
				continue
			}
		}

		// User ID filter (from auth display name)
		if filter.UserID != "" && event.Auth != nil {
			if !strings.Contains(event.Auth.DisplayName, filter.UserID) {
				continue
			}
		}

		// Remote address filter
		if filter.RemoteAddr != "" && event.Request != nil {
			if !strings.Contains(event.Request.RemoteAddress, filter.RemoteAddr) {
				continue
			}
		}

		filtered = append(filtered, event)
	}

	return filtered
}

// Close closes the audit repository and flushes any pending writes
func (r *FileAuditRepository) Close() error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.bufWriter != nil {
		if err := r.bufWriter.Flush(); err != nil {
			r.logger.Error("Failed to flush audit buffer on close", zap.Error(err))
		}
	}

	if r.file != nil {
		if err := r.file.Close(); err != nil {
			r.logger.Error("Failed to close audit file", zap.Error(err))
			return err
		}
		r.file = nil
		r.bufWriter = nil
	}

	return nil
}
