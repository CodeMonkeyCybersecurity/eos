package cicd

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"go.uber.org/zap"
)

// StatusTracker tracks and reports pipeline execution status
type StatusTracker struct {
	mu             sync.RWMutex
	executions     map[string]*ExecutionTracker
	listeners      map[string]chan StatusUpdate
	history        []StatusUpdate
	maxHistory     int
	store          PipelineStore
	logger         *zap.Logger
	subscriptionID int64
}

// ExecutionTracker tracks status for a single execution
type ExecutionTracker struct {
	ExecutionID string                    `json:"execution_id"`
	PipelineID  string                    `json:"pipeline_id"`
	Status      ExecutionStatus           `json:"status"`
	StartTime   time.Time                 `json:"start_time"`
	EndTime     *time.Time                `json:"end_time,omitempty"`
	Duration    time.Duration             `json:"duration"`
	Stages      map[string]*StageTracker  `json:"stages"`
	Progress    *ProgressInfo             `json:"progress"`
	Metrics     *ExecutionMetrics         `json:"metrics"`
	History     []StatusUpdate            `json:"history"`
}

// StageTracker tracks status for a single stage
type StageTracker struct {
	Name      string          `json:"name"`
	Status    ExecutionStatus `json:"status"`
	StartTime time.Time       `json:"start_time"`
	EndTime   *time.Time      `json:"end_time,omitempty"`
	Duration  time.Duration   `json:"duration"`
	Progress  *ProgressInfo   `json:"progress"`
	Error     string          `json:"error,omitempty"`
}

// ProgressInfo provides detailed progress information
type ProgressInfo struct {
	Current     int     `json:"current"`
	Total       int     `json:"total"`
	Percentage  float64 `json:"percentage"`
	Description string  `json:"description"`
	ETA         *time.Time `json:"eta,omitempty"`
}

// ExecutionMetrics provides performance metrics
type ExecutionMetrics struct {
	CPUUsage    float64   `json:"cpu_usage"`
	MemoryUsage int64     `json:"memory_usage"`
	DiskIO      int64     `json:"disk_io"`
	NetworkIO   int64     `json:"network_io"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// StatusReport provides comprehensive status information
type StatusReport struct {
	ExecutionID    string                      `json:"execution_id"`
	PipelineID     string                      `json:"pipeline_id"`
	Status         ExecutionStatus             `json:"status"`
	StartTime      time.Time                   `json:"start_time"`
	Duration       time.Duration               `json:"duration"`
	Progress       *ProgressInfo               `json:"progress"`
	Stages         []StageStatusReport         `json:"stages"`
	Metrics        *ExecutionMetrics           `json:"metrics"`
	RecentEvents   []StatusUpdate              `json:"recent_events"`
	EstimatedTime  *time.Duration              `json:"estimated_time,omitempty"`
	GeneratedAt    time.Time                   `json:"generated_at"`
}

// StageStatusReport provides stage-specific status information
type StageStatusReport struct {
	Name        string          `json:"name"`
	Status      ExecutionStatus `json:"status"`
	StartTime   time.Time       `json:"start_time"`
	Duration    time.Duration   `json:"duration"`
	Progress    *ProgressInfo   `json:"progress"`
	Error       string          `json:"error,omitempty"`
	Logs        []LogEntry      `json:"logs,omitempty"`
	Artifacts   []ArtifactInfo  `json:"artifacts,omitempty"`
}

// NewStatusTracker creates a new status tracker
func NewStatusTracker(store PipelineStore, maxHistory int, logger *zap.Logger) *StatusTracker {
	return &StatusTracker{
		executions: make(map[string]*ExecutionTracker),
		listeners:  make(map[string]chan StatusUpdate),
		history:    make([]StatusUpdate, 0, maxHistory),
		maxHistory: maxHistory,
		store:      store,
		logger:     logger,
	}
}

// TrackExecution starts tracking a new execution
func (st *StatusTracker) TrackExecution(execution *PipelineExecution) {
	st.mu.Lock()
	defer st.mu.Unlock()

	tracker := &ExecutionTracker{
		ExecutionID: execution.ID,
		PipelineID:  execution.PipelineID,
		Status:      execution.Status,
		StartTime:   execution.StartTime,
		EndTime:     execution.EndTime,
		Duration:    execution.Duration,
		Stages:      make(map[string]*StageTracker),
		Progress:    &ProgressInfo{},
		Metrics:     &ExecutionMetrics{},
		History:     make([]StatusUpdate, 0),
	}

	// Initialize stage trackers
	for _, stage := range execution.Stages {
		tracker.Stages[stage.Name] = &StageTracker{
			Name:      stage.Name,
			Status:    stage.Status,
			StartTime: stage.StartTime,
			EndTime:   stage.EndTime,
			Duration:  stage.Duration,
			Progress:  &ProgressInfo{},
			Error:     stage.Error,
		}
	}

	st.executions[execution.ID] = tracker

	st.logger.Info("Started tracking execution",
		zap.String("execution_id", execution.ID),
		zap.String("pipeline_id", execution.PipelineID))
}

// UpdateStatus updates the status of an execution or stage
func (st *StatusTracker) UpdateStatus(update StatusUpdate) {
	st.mu.Lock()
	defer st.mu.Unlock()

	// Add to history
	st.history = append(st.history, update)
	if len(st.history) > st.maxHistory {
		st.history = st.history[1:]
	}

	// Update execution tracker
	tracker, exists := st.executions[update.ExecutionID]
	if !exists {
		st.logger.Warn("Received update for unknown execution",
			zap.String("execution_id", update.ExecutionID))
		return
	}

	// Add to execution history
	tracker.History = append(tracker.History, update)

	// Update execution or stage status
	if update.Stage == "pipeline" {
		tracker.Status = update.Status
		if isTerminalStatus(update.Status) {
			now := time.Now()
			tracker.EndTime = &now
			tracker.Duration = now.Sub(tracker.StartTime)
		}
	} else {
		// Update stage status
		if stageTracker, exists := tracker.Stages[update.Stage]; exists {
			stageTracker.Status = update.Status
			if isTerminalStatus(update.Status) {
				now := time.Now()
				stageTracker.EndTime = &now
				stageTracker.Duration = now.Sub(stageTracker.StartTime)
			}
		}
	}

	// Update overall progress
	st.updateProgress(tracker)

	// Notify listeners
	st.notifyListeners(update)

	st.logger.Debug("Updated execution status",
		zap.String("execution_id", update.ExecutionID),
		zap.String("stage", update.Stage),
		zap.String("status", string(update.Status)))
}

// Subscribe creates a subscription for status updates
func (st *StatusTracker) Subscribe(executionID string) (string, <-chan StatusUpdate) {
	st.mu.Lock()
	defer st.mu.Unlock()

	st.subscriptionID++
	id := fmt.Sprintf("sub-%d", st.subscriptionID)
	
	ch := make(chan StatusUpdate, 100)
	key := fmt.Sprintf("%s:%s", executionID, id)
	st.listeners[key] = ch

	st.logger.Debug("Created subscription",
		zap.String("subscription_id", id),
		zap.String("execution_id", executionID))

	return id, ch
}

// Unsubscribe removes a status update subscription
func (st *StatusTracker) Unsubscribe(executionID, subscriptionID string) {
	st.mu.Lock()
	defer st.mu.Unlock()

	key := fmt.Sprintf("%s:%s", executionID, subscriptionID)
	if ch, exists := st.listeners[key]; exists {
		close(ch)
		delete(st.listeners, key)
		
		st.logger.Debug("Removed subscription",
			zap.String("subscription_id", subscriptionID),
			zap.String("execution_id", executionID))
	}
}

// GetStatus returns the current status of an execution
func (st *StatusTracker) GetStatus(executionID string) (*StatusReport, error) {
	st.mu.RLock()
	defer st.mu.RUnlock()

	tracker, exists := st.executions[executionID]
	if !exists {
		return nil, fmt.Errorf("execution not found: %s", executionID)
	}

	// Load full execution details from store
	execution, err := st.store.GetExecution(executionID)
	if err != nil {
		return nil, fmt.Errorf("failed to load execution: %w", err)
	}

	// Build stage reports
	stageReports := make([]StageStatusReport, 0, len(tracker.Stages))
	for _, stage := range execution.Stages {
		stageTracker := tracker.Stages[stage.Name]
		if stageTracker == nil {
			continue
		}

		report := StageStatusReport{
			Name:      stage.Name,
			Status:    stageTracker.Status,
			StartTime: stageTracker.StartTime,
			Duration:  stageTracker.Duration,
			Progress:  stageTracker.Progress,
			Error:     stageTracker.Error,
			Logs:      stage.Logs,
			Artifacts: stage.Artifacts,
		}
		stageReports = append(stageReports, report)
	}

	// Sort stages by start time
	sort.Slice(stageReports, func(i, j int) bool {
		return stageReports[i].StartTime.Before(stageReports[j].StartTime)
	})

	// Get recent events (last 10)
	recentEvents := tracker.History
	if len(recentEvents) > 10 {
		recentEvents = recentEvents[len(recentEvents)-10:]
	}

	// Calculate estimated completion time
	var estimatedTime *time.Duration
	if tracker.Status == StatusRunning && tracker.Progress.Total > 0 {
		elapsed := time.Since(tracker.StartTime)
		if tracker.Progress.Current > 0 {
			totalEstimate := time.Duration(float64(elapsed) * float64(tracker.Progress.Total) / float64(tracker.Progress.Current))
			remaining := totalEstimate - elapsed
			estimatedTime = &remaining
		}
	}

	report := &StatusReport{
		ExecutionID:   tracker.ExecutionID,
		PipelineID:    tracker.PipelineID,
		Status:        tracker.Status,
		StartTime:     tracker.StartTime,
		Duration:      tracker.Duration,
		Progress:      tracker.Progress,
		Stages:        stageReports,
		Metrics:       tracker.Metrics,
		RecentEvents:  recentEvents,
		EstimatedTime: estimatedTime,
		GeneratedAt:   time.Now(),
	}

	return report, nil
}

// ListActiveExecutions returns all currently tracked executions
func (st *StatusTracker) ListActiveExecutions() []string {
	st.mu.RLock()
	defer st.mu.RUnlock()

	executions := make([]string, 0, len(st.executions))
	for id := range st.executions {
		executions = append(executions, id)
	}

	return executions
}

// GetHistory returns recent status updates
func (st *StatusTracker) GetHistory(limit int) []StatusUpdate {
	st.mu.RLock()
	defer st.mu.RUnlock()

	if limit <= 0 || limit > len(st.history) {
		limit = len(st.history)
	}

	history := make([]StatusUpdate, limit)
	start := len(st.history) - limit
	copy(history, st.history[start:])

	return history
}

// UpdateMetrics updates performance metrics for an execution
func (st *StatusTracker) UpdateMetrics(executionID string, metrics *ExecutionMetrics) {
	st.mu.Lock()
	defer st.mu.Unlock()

	tracker, exists := st.executions[executionID]
	if !exists {
		return
	}

	metrics.UpdatedAt = time.Now()
	tracker.Metrics = metrics

	st.logger.Debug("Updated execution metrics",
		zap.String("execution_id", executionID),
		zap.Float64("cpu_usage", metrics.CPUUsage),
		zap.Int64("memory_usage", metrics.MemoryUsage))
}

// UpdateProgress updates progress information for an execution or stage
func (st *StatusTracker) UpdateProgress(executionID, stage string, progress *ProgressInfo) {
	st.mu.Lock()
	defer st.mu.Unlock()

	tracker, exists := st.executions[executionID]
	if !exists {
		return
	}

	if stage == "" || stage == "pipeline" {
		// Update overall progress
		tracker.Progress = progress
	} else {
		// Update stage progress
		if stageTracker, exists := tracker.Stages[stage]; exists {
			stageTracker.Progress = progress
		}
	}

	st.logger.Debug("Updated progress",
		zap.String("execution_id", executionID),
		zap.String("stage", stage),
		zap.Float64("percentage", progress.Percentage))
}

// CleanupCompleted removes completed executions from active tracking
func (st *StatusTracker) CleanupCompleted(maxAge time.Duration) {
	st.mu.Lock()
	defer st.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	removed := 0

	for id, tracker := range st.executions {
		if isTerminalStatus(tracker.Status) && tracker.EndTime != nil && tracker.EndTime.Before(cutoff) {
			delete(st.executions, id)
			removed++
		}
	}

	if removed > 0 {
		st.logger.Info("Cleaned up completed executions",
			zap.Int("removed", removed))
	}
}

// ExportReport exports a status report in various formats
func (st *StatusTracker) ExportReport(executionID, format string) ([]byte, error) {
	report, err := st.GetStatus(executionID)
	if err != nil {
		return nil, err
	}

	switch format {
	case "json":
		return json.MarshalIndent(report, "", "  ")
	case "summary":
		return st.generateSummary(report), nil
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

// updateProgress calculates overall progress based on stage progress
func (st *StatusTracker) updateProgress(tracker *ExecutionTracker) {
	if len(tracker.Stages) == 0 {
		return
	}

	completed := 0
	total := len(tracker.Stages)
	
	for _, stage := range tracker.Stages {
		if isTerminalStatus(stage.Status) {
			completed++
		}
	}

	tracker.Progress.Current = completed
	tracker.Progress.Total = total
	tracker.Progress.Percentage = float64(completed) / float64(total) * 100
	tracker.Progress.Description = fmt.Sprintf("%d of %d stages completed", completed, total)

	// Estimate completion time
	if completed > 0 && completed < total && tracker.Status == StatusRunning {
		elapsed := time.Since(tracker.StartTime)
		totalEstimate := time.Duration(float64(elapsed) * float64(total) / float64(completed))
		eta := tracker.StartTime.Add(totalEstimate)
		tracker.Progress.ETA = &eta
	}
}

// notifyListeners sends updates to all relevant listeners
func (st *StatusTracker) notifyListeners(update StatusUpdate) {
	for key, ch := range st.listeners {
		// Check if this listener is interested in this execution
		if executionID := extractExecutionID(key); executionID == "" || executionID == update.ExecutionID {
			select {
			case ch <- update:
			default:
				// Channel full, skip
				st.logger.Warn("Status update channel full, skipping",
					zap.String("listener", key))
			}
		}
	}
}

// extractExecutionID extracts execution ID from listener key
func extractExecutionID(key string) string {
	// Key format: "executionID:subscriptionID"
	for i, r := range key {
		if r == ':' {
			return key[:i]
		}
	}
	return ""
}

// generateSummary creates a human-readable summary
func (st *StatusTracker) generateSummary(report *StatusReport) []byte {
	summary := "Pipeline Execution Report\n"
	summary += "========================\n"
	summary += fmt.Sprintf("Execution ID: %s\n", report.ExecutionID)
	summary += fmt.Sprintf("Pipeline ID:  %s\n", report.PipelineID)
	summary += fmt.Sprintf("Status:       %s\n", report.Status)
	summary += fmt.Sprintf("Duration:     %s\n", report.Duration)
	summary += fmt.Sprintf("Progress:     %.1f%% (%s)\n", report.Progress.Percentage, report.Progress.Description)
	summary += "\nStages:\n"
	summary += "-------\n"

	for _, stage := range report.Stages {
		status := string(stage.Status)
		if stage.Error != "" {
			status += fmt.Sprintf(" (%s)", stage.Error)
		}
		summary += fmt.Sprintf("  %-20s %s\n", stage.Name+":", status)
	}

	if len(report.RecentEvents) > 0 {
		summary += "\nRecent Events:\n"
		summary += "--------------\n"
		for _, event := range report.RecentEvents {
			summary += fmt.Sprintf("%s [%s] %s: %s\n",
				event.Timestamp.Format("15:04:05"),
				event.Stage,
				event.Status,
				event.Message)
		}
	}
	
	return []byte(summary)
}