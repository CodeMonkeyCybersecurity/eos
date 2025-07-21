package disk_safety

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/google/uuid"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)


// JournalStorage manages disk operation journaling
type JournalStorage struct {
	mu       sync.RWMutex
	basePath string
}

// NewJournalStorage creates a new journal storage instance
func NewJournalStorage() (*JournalStorage, error) {
	js := &JournalStorage{
		basePath: JournalDir,
	}

	// Create directory structure
	dirs := []string{
		filepath.Join(js.basePath, ActiveDir),
		filepath.Join(js.basePath, ArchiveDir),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("create journal dir %s: %w", dir, err)
		}
	}

	return js, nil
}

// Create creates a new journal entry for a disk operation
func (js *JournalStorage) Create(operationType string, target DiskTarget) (*JournalEntry, error) {
	js.mu.Lock()
	defer js.mu.Unlock()

	entry := &JournalEntry{
		ID:            uuid.New().String(),
		StartTime:     time.Now(),
		OperationType: operationType,
		Target:        target,
		Status:        StatusPending,
		Commands:      []ExecutedCommand{},
		User:          getCurrentUser(),
		Parameters:    make(map[string]interface{}),
	}

	// Save to active directory
	if err := js.save(entry); err != nil {
		return nil, fmt.Errorf("save journal entry: %w", err)
	}

	return entry, nil
}

// Load loads a journal entry by ID
func (js *JournalStorage) Load(id string) (*JournalEntry, error) {
	js.mu.RLock()
	defer js.mu.RUnlock()

	// Try active directory first
	activePath := filepath.Join(js.basePath, ActiveDir, id+".json")
	if data, err := os.ReadFile(activePath); err == nil {
		var entry JournalEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			return nil, fmt.Errorf("unmarshal active entry: %w", err)
		}
		return &entry, nil
	}

	// Try archive directory
	archivePath := filepath.Join(js.basePath, ArchiveDir, id+".json")
	if data, err := os.ReadFile(archivePath); err == nil {
		var entry JournalEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			return nil, fmt.Errorf("unmarshal archived entry: %w", err)
		}
		return &entry, nil
	}

	return nil, fmt.Errorf("journal entry %s not found", id)
}

// UpdateStatus updates the status of a journal entry
func (js *JournalStorage) UpdateStatus(id string, status OperationStatus) error {
	entry, err := js.Load(id)
	if err != nil {
		return err
	}

	entry.Status = status
	if status == StatusCompleted || status == StatusFailed || status == StatusRolledBack {
		now := time.Now()
		entry.EndTime = &now
	}

	return js.save(entry)
}

// RecordCommand records an executed command in the journal
func (js *JournalStorage) RecordCommand(id string, cmd *exec.Cmd, output []byte, err error) error {
	entry, entryErr := js.Load(id)
	if entryErr != nil {
		return entryErr
	}

	executed := ExecutedCommand{
		Timestamp: time.Now(),
		Command:   cmd.Path,
		Args:      cmd.Args[1:], // Skip program name
		Output:    string(output),
		ExitCode:  0,
	}

	if err != nil {
		executed.Error = err.Error()
		if exitErr, ok := err.(*exec.ExitError); ok {
			executed.ExitCode = exitErr.ExitCode()
		} else {
			executed.ExitCode = 1
		}
	}

	entry.Commands = append(entry.Commands, executed)
	return js.save(entry)
}

// SetPreState captures the pre-operation state
func (js *JournalStorage) SetPreState(id string, state *DiskState) error {
	entry, err := js.Load(id)
	if err != nil {
		return err
	}

	entry.PreState = state
	return js.save(entry)
}

// SetPostState captures the post-operation state
func (js *JournalStorage) SetPostState(id string, state *DiskState) error {
	entry, err := js.Load(id)
	if err != nil {
		return err
	}

	entry.PostState = state
	return js.save(entry)
}

// RecordError records an error for the operation
func (js *JournalStorage) RecordError(id string, operationErr error) error {
	entry, err := js.Load(id)
	if err != nil {
		return err
	}

	entry.Error = operationErr.Error()
	return js.save(entry)
}

// AddSnapshot records a snapshot associated with the operation
func (js *JournalStorage) AddSnapshot(id string, snapshot *Snapshot) error {
	entry, err := js.Load(id)
	if err != nil {
		return err
	}

	entry.Snapshot = snapshot
	return js.save(entry)
}

// SetRollbackPlan sets the rollback plan for the operation
func (js *JournalStorage) SetRollbackPlan(id string, plan *RollbackPlan) error {
	entry, err := js.Load(id)
	if err != nil {
		return err
	}

	entry.RollbackPlan = plan
	return js.save(entry)
}

// ListActive returns all active (non-completed) journal entries
func (js *JournalStorage) ListActive() ([]*JournalEntry, error) {
	js.mu.RLock()
	defer js.mu.RUnlock()

	activeDir := filepath.Join(js.basePath, ActiveDir)
	entries, err := os.ReadDir(activeDir)
	if err != nil {
		return nil, fmt.Errorf("read active directory: %w", err)
	}

	var activeEntries []*JournalEntry
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			id := entry.Name()[:len(entry.Name())-5] // Remove .json
			if journalEntry, err := js.Load(id); err == nil {
				if journalEntry.Status == StatusPending || journalEntry.Status == StatusInProgress {
					activeEntries = append(activeEntries, journalEntry)
				}
			}
		}
	}

	return activeEntries, nil
}

// Archive moves completed entries to archive directory
func (js *JournalStorage) Archive(id string) error {
	js.mu.Lock()
	defer js.mu.Unlock()

	activePath := filepath.Join(js.basePath, ActiveDir, id+".json")
	archivePath := filepath.Join(js.basePath, ArchiveDir, id+".json")

	// Check if file exists in active directory
	if _, err := os.Stat(activePath); os.IsNotExist(err) {
		return fmt.Errorf("entry %s not found in active directory", id)
	}

	// Move file to archive
	if err := os.Rename(activePath, archivePath); err != nil {
		return fmt.Errorf("archive entry %s: %w", id, err)
	}

	return nil
}

// Cleanup removes old archived entries
func (js *JournalStorage) Cleanup(maxAge time.Duration) error {
	js.mu.Lock()
	defer js.mu.Unlock()

	archiveDir := filepath.Join(js.basePath, ArchiveDir)
	entries, err := os.ReadDir(archiveDir)
	if err != nil {
		return fmt.Errorf("read archive directory: %w", err)
	}

	cutoff := time.Now().Add(-maxAge)
	var cleaned int

	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			info, err := entry.Info()
			if err != nil {
				continue
			}

			if info.ModTime().Before(cutoff) {
				entryPath := filepath.Join(archiveDir, entry.Name())
				if err := os.Remove(entryPath); err == nil {
					cleaned++
				}
			}
		}
	}

	return nil
}

// save persists a journal entry to disk
func (js *JournalStorage) save(entry *JournalEntry) error {
	// Determine correct directory based on status
	var dir string
	if entry.Status == StatusCompleted || entry.Status == StatusFailed || entry.Status == StatusRolledBack {
		dir = ArchiveDir
	} else {
		dir = ActiveDir
	}

	// Generate checksum for integrity
	entry.Checksum = js.generateChecksum(entry)

	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal entry: %w", err)
	}

	filePath := filepath.Join(js.basePath, dir, entry.ID+".json")
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("write entry file: %w", err)
	}

	return nil
}

// generateChecksum creates a simple checksum for integrity verification
func (js *JournalStorage) generateChecksum(entry *JournalEntry) string {
	// Simple checksum based on key fields
	content := fmt.Sprintf("%s-%s-%s-%v", 
		entry.ID, 
		entry.OperationType, 
		entry.StartTime.Format(time.RFC3339),
		entry.Status)
	
	// In a production system, you'd use a proper hash function
	return fmt.Sprintf("%x", len(content))
}

// getCurrentUser gets the current system user
func getCurrentUser() string {
	if user := os.Getenv("USER"); user != "" {
		return user
	}
	if user := os.Getenv("USERNAME"); user != "" {
		return user
	}
	return "unknown"
}

// JournalWrapper wraps operations with journaling
type JournalWrapper struct {
	journal *JournalStorage
	rc      *eos_io.RuntimeContext
}

// NewJournalWrapper creates a new journal wrapper
func NewJournalWrapper(rc *eos_io.RuntimeContext) (*JournalWrapper, error) {
	journal, err := NewJournalStorage()
	if err != nil {
		return nil, err
	}

	return &JournalWrapper{
		journal: journal,
		rc:      rc,
	}, nil
}

// WrapCommand wraps command execution with journaling
func (jw *JournalWrapper) WrapCommand(journalID string, cmd *exec.Cmd) error {
	logger := otelzap.Ctx(jw.rc.Ctx)
	
	logger.Debug("Executing command with journaling",
		zap.String("journal_id", journalID),
		zap.String("command", cmd.Path),
		zap.Strings("args", cmd.Args[1:]))

	// Execute command and capture output
	output, err := cmd.CombinedOutput()

	// Record in journal
	if recordErr := jw.journal.RecordCommand(journalID, cmd, output, err); recordErr != nil {
		logger.Warn("Failed to record command in journal",
			zap.Error(recordErr),
			zap.String("journal_id", journalID))
	}

	return err
}