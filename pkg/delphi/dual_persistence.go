package delphi

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// DualPersistenceManager handles both Redis (speed) and PostgreSQL (audit) persistence
type DualPersistenceManager struct {
	redis  *redis.Client
	db     *gorm.DB
	logger *zap.Logger

	// Configuration
	config DualPersistenceConfig

	// Async processing
	auditQueue chan AuditEntry
	wg         sync.WaitGroup
	shutdown   chan struct{}
}

// DualPersistenceConfig configures the dual persistence behavior
type DualPersistenceConfig struct {
	// Redis configuration
	EnableRedisQueue bool
	RedisFailover    bool // Fallback to PostgreSQL if Redis fails

	// PostgreSQL audit configuration
	EnableAuditLog     bool
	AuditBufferSize    int
	AuditFlushInterval time.Duration
	AuditRetentionDays int

	// Performance tuning
	AsyncAuditWrites    bool
	MaxConcurrentAudits int
	AuditWriteTimeout   time.Duration
}

// DefaultDualPersistenceConfig returns sensible defaults
func DefaultDualPersistenceConfig() DualPersistenceConfig {
	return DualPersistenceConfig{
		EnableRedisQueue:    true,
		RedisFailover:       true,
		EnableAuditLog:      true,
		AuditBufferSize:     1000,
		AuditFlushInterval:  5 * time.Second,
		AuditRetentionDays:  90,
		AsyncAuditWrites:    true,
		MaxConcurrentAudits: 5,
		AuditWriteTimeout:   10 * time.Second,
	}
}

// AuditEntry represents an audit log entry for PostgreSQL
type AuditEntry struct {
	ID         string    `gorm:"primaryKey;type:uuid;default:gen_random_uuid()" json:"id"`
	AlertID    string    `gorm:"index;not null" json:"alert_id"`
	Stage      string    `gorm:"index;not null" json:"stage"`
	Action     string    `gorm:"index;not null" json:"action"` // RECEIVED, PROCESSED, FORWARDED, FAILED
	Timestamp  time.Time `gorm:"index;not null" json:"timestamp"`
	WorkerName string    `gorm:"index" json:"worker_name,omitempty"`

	// Detailed audit data
	AlertData          map[string]interface{} `gorm:"type:jsonb" json:"alert_data,omitempty"`
	ProcessingMetadata map[string]interface{} `gorm:"type:jsonb" json:"processing_metadata,omitempty"`

	// Performance metrics
	ProcessingDuration *time.Duration `json:"processing_duration,omitempty"`
	QueueDepth         *int           `json:"queue_depth,omitempty"`
	RetryCount         int            `json:"retry_count"`

	// Error information
	ErrorMessage string                 `json:"error_message,omitempty"`
	ErrorDetails map[string]interface{} `gorm:"type:jsonb" json:"error_details,omitempty"`

	// Circuit breaker state
	CircuitBreakerState string `json:"circuit_breaker_state,omitempty"`

	// Database fields
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

// AlertStatistics represents aggregated statistics for reporting
type AlertStatistics struct {
	ID   string    `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Date time.Time `gorm:"index;not null"`
	Hour int       `gorm:"index"`

	// Volume metrics
	TotalAlerts     int64 `json:"total_alerts"`
	ProcessedAlerts int64 `json:"processed_alerts"`
	FailedAlerts    int64 `json:"failed_alerts"`
	RetriedAlerts   int64 `json:"retried_alerts"`

	// Performance metrics
	AvgProcessingTime float64 `json:"avg_processing_time_seconds"`
	MaxProcessingTime float64 `json:"max_processing_time_seconds"`
	MinProcessingTime float64 `json:"min_processing_time_seconds"`

	// Stage breakdown
	StageBreakdown map[string]int64 `gorm:"type:jsonb" json:"stage_breakdown"`

	// Top error categories
	TopErrors map[string]int64 `gorm:"type:jsonb" json:"top_errors"`

	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}

// NewDualPersistenceManager creates a new dual persistence manager
func NewDualPersistenceManager(redis *redis.Client, db *gorm.DB, config DualPersistenceConfig, logger *zap.Logger) (*DualPersistenceManager, error) {
	// Auto-migrate audit tables
	if err := db.AutoMigrate(&AuditEntry{}, &AlertStatistics{}); err != nil {
		return nil, fmt.Errorf("failed to migrate audit tables: %w", err)
	}

	dpm := &DualPersistenceManager{
		redis:    redis,
		db:       db,
		logger:   logger,
		config:   config,
		shutdown: make(chan struct{}),
	}

	if config.AsyncAuditWrites {
		dpm.auditQueue = make(chan AuditEntry, config.AuditBufferSize)
		dpm.startAsyncAuditProcessor()
	}

	// Start statistics aggregation
	dpm.startStatisticsAggregator()

	logger.Info("Dual persistence manager initialized",
		zap.Bool("redis_queue", config.EnableRedisQueue),
		zap.Bool("audit_log", config.EnableAuditLog),
		zap.Bool("async_audit", config.AsyncAuditWrites),
		zap.Int("audit_buffer_size", config.AuditBufferSize))

	return dpm, nil
}

// PublishAlert publishes an alert with dual persistence
func (dpm *DualPersistenceManager) PublishAlert(ctx context.Context, alert *Alert, stage string) error {
	// Always audit the publish action
	auditEntry := AuditEntry{
		AlertID:   alert.ID,
		Stage:     stage,
		Action:    "PUBLISHED",
		Timestamp: time.Now(),
		AlertData: alert.Data,
		ProcessingMetadata: map[string]interface{}{
			"alert_version": alert.Version,
			"alert_state":   alert.State,
		},
	}

	// Primary: Try Redis for speed
	var redisErr error
	if dpm.config.EnableRedisQueue {
		msg := &StreamMessage{
			AlertID:   alert.ID,
			Stage:     stage,
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"alert": alert,
			},
		}

		redisErr = dpm.publishToRedis(ctx, msg, stage)
		if redisErr == nil {
			auditEntry.ProcessingMetadata["published_to"] = "redis"
		}
	}

	// Fallback: PostgreSQL NOTIFY if Redis fails
	var pgErr error
	if redisErr != nil && dpm.config.RedisFailover {
		pgErr = dpm.publishToPostgreSQL(ctx, alert, stage)
		if pgErr == nil {
			auditEntry.ProcessingMetadata["published_to"] = "postgresql"
			auditEntry.ProcessingMetadata["redis_fallback"] = true
			auditEntry.ErrorMessage = redisErr.Error()
		}
	}

	// Audit the operation
	if dpm.config.EnableAuditLog {
		if redisErr != nil && pgErr != nil {
			auditEntry.Action = "PUBLISH_FAILED"
			auditEntry.ErrorMessage = fmt.Sprintf("Redis: %v, PostgreSQL: %v", redisErr, pgErr)
		}

		dpm.auditOperation(auditEntry)
	}

	// Return appropriate error
	if redisErr != nil && pgErr != nil {
		return fmt.Errorf("failed to publish to both Redis (%v) and PostgreSQL (%v)", redisErr, pgErr)
	}

	return nil
}

// AuditProcessing logs processing events for analytics and compliance
func (dpm *DualPersistenceManager) AuditProcessing(alert *Alert, stage, action, workerName string, duration *time.Duration, err error) {
	if !dpm.config.EnableAuditLog {
		return
	}

	auditEntry := AuditEntry{
		AlertID:            alert.ID,
		Stage:              stage,
		Action:             action,
		Timestamp:          time.Now(),
		WorkerName:         workerName,
		ProcessingDuration: duration,
		RetryCount:         alert.Attempt,
		AlertData:          alert.Data,
		ProcessingMetadata: map[string]interface{}{
			"alert_version": alert.Version,
			"alert_state":   alert.State,
			"processed_by":  alert.ProcessedBy,
		},
	}

	if err != nil {
		auditEntry.ErrorMessage = err.Error()
		if delphiErr, ok := err.(*DelphiError); ok {
			auditEntry.ErrorDetails = map[string]interface{}{
				"error_code":    delphiErr.Code,
				"retryable":     delphiErr.IsRetryable(),
				"error_stage":   delphiErr.Stage,
				"error_context": delphiErr.Context,
			}
		}
	}

	dpm.auditOperation(auditEntry)
}

// AuditCircuitBreakerEvent logs circuit breaker state changes
func (dpm *DualPersistenceManager) AuditCircuitBreakerEvent(circuitName string, fromState, toState CircuitState, stats CircuitBreakerStats) {
	if !dpm.config.EnableAuditLog {
		return
	}

	auditEntry := AuditEntry{
		AlertID:             "SYSTEM",
		Stage:               "CIRCUIT_BREAKER",
		Action:              "STATE_CHANGE",
		Timestamp:           time.Now(),
		WorkerName:          circuitName,
		CircuitBreakerState: toState.String(),
		ProcessingMetadata: map[string]interface{}{
			"from_state":          fromState.String(),
			"to_state":            toState.String(),
			"failure_count":       stats.FailureCount,
			"success_count":       stats.SuccessCount,
			"concurrent_requests": stats.ConcurrentRequests,
			"failure_threshold":   stats.Config.FailureThreshold,
			"success_threshold":   stats.Config.SuccessThreshold,
		},
	}

	dpm.auditOperation(auditEntry)
}

// publishToRedis handles Redis Stream publishing
func (dpm *DualPersistenceManager) publishToRedis(ctx context.Context, msg *StreamMessage, stage string) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	streamName := fmt.Sprintf("delphi:alerts:%s", stage)

	_, err = dpm.redis.XAdd(ctx, &redis.XAddArgs{
		Stream: streamName,
		Values: map[string]interface{}{
			"alert_id": msg.AlertID,
			"stage":    msg.Stage,
			"data":     string(data),
		},
	}).Result()

	return err
}

// publishToPostgreSQL handles PostgreSQL NOTIFY fallback
func (dpm *DualPersistenceManager) publishToPostgreSQL(ctx context.Context, alert *Alert, stage string) error {
	notification := map[string]interface{}{
		"alert_id": alert.ID,
		"stage":    stage,
		"action":   "new_alert",
		"data":     alert.Data,
	}

	notificationJSON, err := json.Marshal(notification)
	if err != nil {
		return fmt.Errorf("failed to marshal notification: %w", err)
	}

	channel := fmt.Sprintf("delphi_%s", stage)
	return dpm.db.WithContext(ctx).Exec("SELECT pg_notify(?, ?)", channel, string(notificationJSON)).Error
}

// auditOperation handles audit entry persistence
func (dpm *DualPersistenceManager) auditOperation(entry AuditEntry) {
	if dpm.config.AsyncAuditWrites {
		select {
		case dpm.auditQueue <- entry:
			// Successfully queued
		default:
			// Queue full, log warning and write synchronously
			dpm.logger.Warn("Audit queue full, writing synchronously",
				zap.String("alert_id", entry.AlertID),
				zap.String("action", entry.Action))
			dpm.writeAuditEntry(entry)
		}
	} else {
		dpm.writeAuditEntry(entry)
	}
}

// writeAuditEntry writes a single audit entry to PostgreSQL
func (dpm *DualPersistenceManager) writeAuditEntry(entry AuditEntry) {
	ctx, cancel := context.WithTimeout(context.Background(), dpm.config.AuditWriteTimeout)
	defer cancel()

	if err := dpm.db.WithContext(ctx).Create(&entry).Error; err != nil {
		dpm.logger.Error("Failed to write audit entry",
			zap.String("alert_id", entry.AlertID),
			zap.String("action", entry.Action),
			zap.Error(err))
	}
}

// startAsyncAuditProcessor starts the background audit processor
func (dpm *DualPersistenceManager) startAsyncAuditProcessor() {
	for i := 0; i < dpm.config.MaxConcurrentAudits; i++ {
		dpm.wg.Add(1)
		go func(workerID int) {
			defer dpm.wg.Done()

			dpm.logger.Debug("Starting audit processor worker",
				zap.Int("worker_id", workerID))

			for {
				select {
				case entry := <-dpm.auditQueue:
					dpm.writeAuditEntry(entry)
				case <-dpm.shutdown:
					dpm.logger.Debug("Audit processor worker shutting down",
						zap.Int("worker_id", workerID))
					return
				}
			}
		}(i)
	}
}

// startStatisticsAggregator starts the background statistics aggregator
func (dpm *DualPersistenceManager) startStatisticsAggregator() {
	dpm.wg.Add(1)
	go func() {
		defer dpm.wg.Done()

		ticker := time.NewTicker(1 * time.Hour) // Aggregate hourly
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := dpm.aggregateStatistics(); err != nil {
					dpm.logger.Error("Failed to aggregate statistics", zap.Error(err))
				}
			case <-dpm.shutdown:
				dpm.logger.Debug("Statistics aggregator shutting down")
				return
			}
		}
	}()
}

// aggregateStatistics creates hourly statistics from audit entries
func (dpm *DualPersistenceManager) aggregateStatistics() error {
	now := time.Now()
	startHour := time.Date(now.Year(), now.Month(), now.Day(), now.Hour()-1, 0, 0, 0, now.Location())
	endHour := startHour.Add(time.Hour)

	dpm.logger.Debug("Aggregating statistics",
		zap.Time("start_hour", startHour),
		zap.Time("end_hour", endHour))

	// Aggregate metrics
	var stats AlertStatistics
	err := dpm.db.Raw(`
		SELECT 
			COUNT(*) as total_alerts,
			COUNT(CASE WHEN action = 'PROCESSED' THEN 1 END) as processed_alerts,
			COUNT(CASE WHEN action = 'FAILED' THEN 1 END) as failed_alerts,
			COUNT(CASE WHEN retry_count > 0 THEN 1 END) as retried_alerts,
			AVG(EXTRACT(EPOCH FROM processing_duration)) as avg_processing_time,
			MAX(EXTRACT(EPOCH FROM processing_duration)) as max_processing_time,
			MIN(EXTRACT(EPOCH FROM processing_duration)) as min_processing_time
		FROM audit_entries
		WHERE timestamp >= ? AND timestamp < ?
	`, startHour, endHour).Scan(&stats).Error

	if err != nil {
		return fmt.Errorf("failed to aggregate basic statistics: %w", err)
	}

	// Get stage breakdown
	var stageResults []struct {
		Stage string `json:"stage"`
		Count int64  `json:"count"`
	}

	err = dpm.db.Raw(`
		SELECT stage, COUNT(*) as count
		FROM audit_entries
		WHERE timestamp >= ? AND timestamp < ?
		GROUP BY stage
	`, startHour, endHour).Scan(&stageResults).Error

	if err != nil {
		return fmt.Errorf("failed to aggregate stage breakdown: %w", err)
	}

	stats.StageBreakdown = make(map[string]int64)
	for _, result := range stageResults {
		stats.StageBreakdown[result.Stage] = result.Count
	}

	// Get top errors
	var errorResults []struct {
		ErrorMessage string `json:"error_message"`
		Count        int64  `json:"count"`
	}

	err = dpm.db.Raw(`
		SELECT error_message, COUNT(*) as count
		FROM audit_entries
		WHERE timestamp >= ? AND timestamp < ? AND error_message != ''
		GROUP BY error_message
		ORDER BY count DESC
		LIMIT 10
	`, startHour, endHour).Scan(&errorResults).Error

	if err != nil {
		return fmt.Errorf("failed to aggregate error breakdown: %w", err)
	}

	stats.TopErrors = make(map[string]int64)
	for _, result := range errorResults {
		stats.TopErrors[result.ErrorMessage] = result.Count
	}

	// Set metadata
	stats.Date = startHour
	stats.Hour = startHour.Hour()

	// Save aggregated statistics
	return dpm.db.Create(&stats).Error
}

// GetStatistics retrieves statistics for a date range
func (dpm *DualPersistenceManager) GetStatistics(ctx context.Context, startDate, endDate time.Time) ([]AlertStatistics, error) {
	var stats []AlertStatistics

	err := dpm.db.WithContext(ctx).
		Where("date >= ? AND date <= ?", startDate, endDate).
		Order("date ASC, hour ASC").
		Find(&stats).Error

	return stats, err
}

// SearchAuditLogs provides flexible audit log searching
func (dpm *DualPersistenceManager) SearchAuditLogs(ctx context.Context, criteria AuditSearchCriteria) ([]AuditEntry, int64, error) {
	query := dpm.db.WithContext(ctx).Model(&AuditEntry{})

	// Apply filters
	if criteria.AlertID != "" {
		query = query.Where("alert_id = ?", criteria.AlertID)
	}
	if criteria.Stage != "" {
		query = query.Where("stage = ?", criteria.Stage)
	}
	if criteria.Action != "" {
		query = query.Where("action = ?", criteria.Action)
	}
	if criteria.WorkerName != "" {
		query = query.Where("worker_name = ?", criteria.WorkerName)
	}
	if !criteria.StartTime.IsZero() {
		query = query.Where("timestamp >= ?", criteria.StartTime)
	}
	if !criteria.EndTime.IsZero() {
		query = query.Where("timestamp <= ?", criteria.EndTime)
	}
	if criteria.HasError {
		query = query.Where("error_message != ''")
	}

	// Get total count
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Apply pagination and ordering
	var entries []AuditEntry
	err := query.
		Order("timestamp DESC").
		Limit(criteria.Limit).
		Offset(criteria.Offset).
		Find(&entries).Error

	return entries, total, err
}

// AuditSearchCriteria defines search parameters for audit logs
type AuditSearchCriteria struct {
	AlertID    string
	Stage      string
	Action     string
	WorkerName string
	StartTime  time.Time
	EndTime    time.Time
	HasError   bool
	Limit      int
	Offset     int
}

// Close gracefully shuts down the dual persistence manager
func (dpm *DualPersistenceManager) Close() error {
	dpm.logger.Info("Shutting down dual persistence manager")

	// Signal shutdown
	close(dpm.shutdown)

	// Drain audit queue if async
	if dpm.config.AsyncAuditWrites {
		close(dpm.auditQueue)
		for entry := range dpm.auditQueue {
			dpm.writeAuditEntry(entry)
		}
	}

	// Wait for workers to finish
	dpm.wg.Wait()

	dpm.logger.Info("Dual persistence manager shutdown complete")
	return nil
}
