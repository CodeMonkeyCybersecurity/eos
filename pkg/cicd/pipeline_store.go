package cicd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
)

// FilePipelineStore implements PipelineStore using filesystem storage
type FilePipelineStore struct {
	mu       sync.RWMutex
	basePath string
	logger   *zap.Logger
}

// NewFilePipelineStore creates a new filesystem-based pipeline store
func NewFilePipelineStore(basePath string, logger *zap.Logger) (*FilePipelineStore, error) {
	// Ensure base path exists
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create store directory: %w", err)
	}

	// Create subdirectories
	for _, subdir := range []string{"executions", "stages", "artifacts", "logs"} {
		if err := os.MkdirAll(filepath.Join(basePath, subdir), 0755); err != nil {
			return nil, fmt.Errorf("failed to create %s directory: %w", subdir, err)
		}
	}

	return &FilePipelineStore{
		basePath: basePath,
		logger:   logger,
	}, nil
}

// SaveExecution saves a pipeline execution to storage
func (s *FilePipelineStore) SaveExecution(execution *PipelineExecution) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create execution directory
	execDir := filepath.Join(s.basePath, "executions", execution.PipelineID)
	if err := os.MkdirAll(execDir, 0755); err != nil {
		return fmt.Errorf("failed to create execution directory: %w", err)
	}

	// Save execution data
	execFile := filepath.Join(execDir, fmt.Sprintf("%s.json", execution.ID))
	data, err := json.MarshalIndent(execution, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal execution: %w", err)
	}

	if err := os.WriteFile(execFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write execution file: %w", err)
	}

	// Update latest symlink
	latestLink := filepath.Join(execDir, "latest")
	_ = os.Remove(latestLink) // Ignore error
	if err := os.Symlink(execFile, latestLink); err != nil {
		s.logger.Warn("Failed to create latest symlink", zap.Error(err))
	}

	// Save execution index
	if err := s.updateExecutionIndex(execution.PipelineID, execution.ID); err != nil {
		s.logger.Warn("Failed to update execution index", zap.Error(err))
	}

	s.logger.Debug("Saved pipeline execution",
		zap.String("execution_id", execution.ID),
		zap.String("pipeline_id", execution.PipelineID),
		zap.String("status", string(execution.Status)))

	return nil
}

// GetExecution retrieves a pipeline execution by ID
func (s *FilePipelineStore) GetExecution(id string) (*PipelineExecution, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Search through all pipeline directories
	pipelinesDir := filepath.Join(s.basePath, "executions")
	entries, err := os.ReadDir(pipelinesDir)
	if err != nil {
		return nil, fmt.Errorf("failed to list pipelines: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pipeline := entry.Name()
		execFile := filepath.Join(pipelinesDir, pipeline, fmt.Sprintf("%s.json", id))
		if _, err := os.Stat(execFile); err == nil {
			data, err := os.ReadFile(execFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read execution file: %w", err)
			}

			var execution PipelineExecution
			if err := json.Unmarshal(data, &execution); err != nil {
				return nil, fmt.Errorf("failed to unmarshal execution: %w", err)
			}

			return &execution, nil
		}
	}

	return nil, fmt.Errorf("execution not found: %s", id)
}

// ListExecutions lists executions for a pipeline
func (s *FilePipelineStore) ListExecutions(pipelineID string, limit int) ([]*PipelineExecution, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	indexFile := filepath.Join(s.basePath, "executions", pipelineID, "index.json")
	if _, err := os.Stat(indexFile); os.IsNotExist(err) {
		return []*PipelineExecution{}, nil
	}

	// Read index
	data, err := os.ReadFile(indexFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read index: %w", err)
	}

	var index executionIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, fmt.Errorf("failed to unmarshal index: %w", err)
	}

	// Load executions in reverse chronological order
	executions := make([]*PipelineExecution, 0, limit)
	count := 0
	for i := len(index.ExecutionIDs) - 1; i >= 0 && count < limit; i-- {
		exec, err := s.GetExecution(index.ExecutionIDs[i])
		if err != nil {
			s.logger.Warn("Failed to load execution from index",
				zap.String("execution_id", index.ExecutionIDs[i]),
				zap.Error(err))
			continue
		}
		executions = append(executions, exec)
		count++
	}

	return executions, nil
}

// UpdateExecutionStatus updates the status of an execution
func (s *FilePipelineStore) UpdateExecutionStatus(id string, status ExecutionStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Find and load execution
	execution, err := s.GetExecution(id)
	if err != nil {
		return err
	}

	// Update status
	execution.Status = status
	if status == StatusRunning && execution.StartTime.IsZero() {
		execution.StartTime = time.Now()
	} else if isTerminalStatus(status) && execution.EndTime == nil {
		now := time.Now()
		execution.EndTime = &now
		execution.Duration = now.Sub(execution.StartTime)
	}

	// Save updated execution
	return s.SaveExecution(execution)
}

// SaveStageExecution saves a stage execution
func (s *FilePipelineStore) SaveStageExecution(executionID string, stage *StageExecution) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Load execution
	execution, err := s.GetExecution(executionID)
	if err != nil {
		return err
	}

	// Update or add stage
	found := false
	for i, existing := range execution.Stages {
		if existing.Name == stage.Name {
			execution.Stages[i] = *stage
			found = true
			break
		}
	}
	if !found {
		execution.Stages = append(execution.Stages, *stage)
	}

	// Save updated execution
	return s.SaveExecution(execution)
}

// updateExecutionIndex updates the execution index for a pipeline
func (s *FilePipelineStore) updateExecutionIndex(pipelineID, executionID string) error {
	indexFile := filepath.Join(s.basePath, "executions", pipelineID, "index.json")

	var index executionIndex
	if _, err := os.Stat(indexFile); err == nil {
		data, err := os.ReadFile(indexFile)
		if err != nil {
			return fmt.Errorf("failed to read index: %w", err)
		}
		if err := json.Unmarshal(data, &index); err != nil {
			return fmt.Errorf("failed to unmarshal index: %w", err)
		}
	}

	// Add execution ID if not already present
	found := false
	for _, id := range index.ExecutionIDs {
		if id == executionID {
			found = true
			break
		}
	}
	if !found {
		index.ExecutionIDs = append(index.ExecutionIDs, executionID)
		index.UpdatedAt = time.Now()
	}

	// Save index
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal index: %w", err)
	}

	return os.WriteFile(indexFile, data, 0644)
}

// executionIndex tracks execution IDs for a pipeline
type executionIndex struct {
	PipelineID   string    `json:"pipeline_id"`
	ExecutionIDs []string  `json:"execution_ids"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// isTerminalStatus checks if a status is terminal
func isTerminalStatus(status ExecutionStatus) bool {
	switch status {
	case StatusSucceeded, StatusFailed, StatusCancelled, StatusRolledBack:
		return true
	default:
		return false
	}
}

// PostgreSQLPipelineStore implements PipelineStore using PostgreSQL
type PostgreSQLPipelineStore struct {
	mu     sync.RWMutex
	db     PipelineDatabase
	logger *zap.Logger
}

// PipelineDatabase interface for database operations
type PipelineDatabase interface {
	SaveExecution(execution *PipelineExecution) error
	GetExecution(id string) (*PipelineExecution, error)
	ListExecutions(pipelineID string, limit int) ([]*PipelineExecution, error)
	UpdateExecutionStatus(id string, status ExecutionStatus) error
	SaveStageExecution(executionID string, stage *StageExecution) error
}

// NewPostgreSQLPipelineStore creates a new PostgreSQL-based pipeline store
func NewPostgreSQLPipelineStore(db PipelineDatabase, logger *zap.Logger) *PostgreSQLPipelineStore {
	return &PostgreSQLPipelineStore{
		db:     db,
		logger: logger,
	}
}

// SaveExecution saves a pipeline execution to the database
func (s *PostgreSQLPipelineStore) SaveExecution(execution *PipelineExecution) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.db.SaveExecution(execution); err != nil {
		return fmt.Errorf("failed to save execution: %w", err)
	}

	s.logger.Debug("Saved pipeline execution to database",
		zap.String("execution_id", execution.ID),
		zap.String("pipeline_id", execution.PipelineID),
		zap.String("status", string(execution.Status)))

	return nil
}

// GetExecution retrieves a pipeline execution by ID
func (s *PostgreSQLPipelineStore) GetExecution(id string) (*PipelineExecution, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.db.GetExecution(id)
}

// ListExecutions lists executions for a pipeline
func (s *PostgreSQLPipelineStore) ListExecutions(pipelineID string, limit int) ([]*PipelineExecution, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.db.ListExecutions(pipelineID, limit)
}

// UpdateExecutionStatus updates the status of an execution
func (s *PostgreSQLPipelineStore) UpdateExecutionStatus(id string, status ExecutionStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.db.UpdateExecutionStatus(id, status)
}

// SaveStageExecution saves a stage execution
func (s *PostgreSQLPipelineStore) SaveStageExecution(executionID string, stage *StageExecution) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.db.SaveStageExecution(executionID, stage)
}

// CachingPipelineStore wraps another store with caching
type CachingPipelineStore struct {
	mu         sync.RWMutex
	underlying PipelineStore
	cache      map[string]*PipelineExecution
	maxCache   int
	logger     *zap.Logger
}

// NewCachingPipelineStore creates a new caching pipeline store
func NewCachingPipelineStore(underlying PipelineStore, maxCache int, logger *zap.Logger) *CachingPipelineStore {
	return &CachingPipelineStore{
		underlying: underlying,
		cache:      make(map[string]*PipelineExecution),
		maxCache:   maxCache,
		logger:     logger,
	}
}

// SaveExecution saves and caches an execution
func (s *CachingPipelineStore) SaveExecution(execution *PipelineExecution) error {
	if err := s.underlying.SaveExecution(execution); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Add to cache
	s.cache[execution.ID] = execution

	// Evict oldest if cache is full
	if len(s.cache) > s.maxCache {
		s.evictOldest()
	}

	return nil
}

// GetExecution retrieves from cache or underlying store
func (s *CachingPipelineStore) GetExecution(id string) (*PipelineExecution, error) {
	s.mu.RLock()
	if cached, ok := s.cache[id]; ok {
		s.mu.RUnlock()
		return cached, nil
	}
	s.mu.RUnlock()

	// Load from underlying store
	execution, err := s.underlying.GetExecution(id)
	if err != nil {
		return nil, err
	}

	// Add to cache
	s.mu.Lock()
	s.cache[id] = execution
	if len(s.cache) > s.maxCache {
		s.evictOldest()
	}
	s.mu.Unlock()

	return execution, nil
}

// ListExecutions passes through to underlying store
func (s *CachingPipelineStore) ListExecutions(pipelineID string, limit int) ([]*PipelineExecution, error) {
	return s.underlying.ListExecutions(pipelineID, limit)
}

// UpdateExecutionStatus updates cache and underlying store
func (s *CachingPipelineStore) UpdateExecutionStatus(id string, status ExecutionStatus) error {
	if err := s.underlying.UpdateExecutionStatus(id, status); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Update cache if present
	if cached, ok := s.cache[id]; ok {
		cached.Status = status
		if isTerminalStatus(status) {
			// Remove from cache when execution is complete
			delete(s.cache, id)
		}
	}

	return nil
}

// SaveStageExecution updates cache and underlying store
func (s *CachingPipelineStore) SaveStageExecution(executionID string, stage *StageExecution) error {
	if err := s.underlying.SaveStageExecution(executionID, stage); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Invalidate cache entry
	delete(s.cache, executionID)

	return nil
}

// evictOldest removes the oldest cache entry
func (s *CachingPipelineStore) evictOldest() {
	var oldestID string
	var oldestTime time.Time

	for id, exec := range s.cache {
		if oldestID == "" || exec.StartTime.Before(oldestTime) {
			oldestID = id
			oldestTime = exec.StartTime
		}
	}

	if oldestID != "" {
		delete(s.cache, oldestID)
	}
}
