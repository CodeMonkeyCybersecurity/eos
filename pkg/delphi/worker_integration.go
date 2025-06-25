package delphi

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// WorkerConfig holds configuration for Delphi workers
type WorkerConfig struct {
	WorkerName    string
	Stage         string
	RedisURL      string
	ConsumerGroup string
	BatchSize     int
	ProcessTimeout time.Duration
	
	// Circuit breaker configuration
	EnableCircuitBreaker bool
	CircuitBreakerConfig CircuitBreakerConfig
	
	// Retry configuration
	MaxRetries    int
	RetryBackoff  time.Duration
}

// DefaultWorkerConfig returns sensible defaults for a worker
func DefaultWorkerConfig(workerName, stage string) WorkerConfig {
	return WorkerConfig{
		WorkerName:    workerName,
		Stage:         stage,
		RedisURL:      getEnvOrDefault("DELPHI_REDIS_URL", "redis://localhost:6379/0"),
		ConsumerGroup: getEnvOrDefault("DELPHI_CONSUMER_GROUP", "delphi-workers"),
		BatchSize:     getEnvIntOrDefault("DELPHI_BATCH_SIZE", 10),
		ProcessTimeout: getEnvDurationOrDefault("DELPHI_PROCESS_TIMEOUT", 5*time.Minute),
		
		EnableCircuitBreaker: getEnvBoolOrDefault("DELPHI_ENABLE_CIRCUIT_BREAKERS", true),
		CircuitBreakerConfig: DefaultCircuitBreakerConfig(fmt.Sprintf("%s-cb", workerName)),
		
		MaxRetries:   getEnvIntOrDefault("DELPHI_MAX_RETRIES", 3),
		RetryBackoff: getEnvDurationOrDefault("DELPHI_RETRY_BACKOFF", 30*time.Second),
	}
}

// EnhancedWorker provides a foundation for all Delphi workers with observability and reliability
type EnhancedWorker struct {
	config          WorkerConfig
	streamHandler   *StreamHandler
	circuitBreaker  *CircuitBreaker
	metrics         *ObservabilityMetrics
	logger          *zap.Logger
	
	// Worker-specific processor
	processor AlertProcessor
}

// AlertProcessor defines the interface that each worker must implement
type AlertProcessor interface {
	ProcessAlert(ctx context.Context, alert *Alert) (*Alert, error)
	GetProcessorName() string
	ValidateAlert(alert *Alert) error
}

// Alert represents a Delphi alert throughout the pipeline
type Alert struct {
	ID        string                 `json:"id"`
	Stage     string                 `json:"stage"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
	
	// Processing metadata
	Attempt   int       `json:"attempt,omitempty"`
	ProcessedAt time.Time `json:"processed_at,omitempty"`
	ProcessedBy string    `json:"processed_by,omitempty"`
	
	// Pipeline state tracking
	State     string    `json:"state"`
	Version   int       `json:"version"`
	Checksum  string    `json:"checksum,omitempty"`
}

// NewEnhancedWorker creates a new enhanced worker
func NewEnhancedWorker(config WorkerConfig, processor AlertProcessor, logger *zap.Logger) (*EnhancedWorker, error) {
	// Initialize stream handler
	streamHandler, err := NewStreamHandler(config.RedisURL, config.ConsumerGroup, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create stream handler: %w", err)
	}
	
	// Initialize metrics
	metrics, err := NewObservabilityMetrics(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create metrics: %w", err)
	}
	
	// Initialize circuit breaker if enabled
	var circuitBreaker *CircuitBreaker
	if config.EnableCircuitBreaker {
		opts, _ := redis.ParseURL(config.RedisURL)
		redisClient := redis.NewClient(opts)
		
		circuitBreaker = NewCircuitBreaker(config.CircuitBreakerConfig, redisClient, logger)
		
		// Set up circuit breaker state change logging
		circuitBreaker.setState(context.Background(), StateClosed) // Initialize to closed
	}
	
	worker := &EnhancedWorker{
		config:         config,
		streamHandler:  streamHandler,
		circuitBreaker: circuitBreaker,
		metrics:        metrics,
		logger:         logger,
		processor:      processor,
	}
	
	logger.Info("Enhanced worker created",
		zap.String("worker_name", config.WorkerName),
		zap.String("stage", config.Stage),
		zap.String("processor", processor.GetProcessorName()),
		zap.Bool("circuit_breaker_enabled", config.EnableCircuitBreaker))
	
	return worker, nil
}

// Start begins processing alerts from the queue
func (ew *EnhancedWorker) Start(ctx context.Context) error {
	ew.logger.Info("Starting enhanced worker",
		zap.String("worker_name", ew.config.WorkerName),
		zap.String("stage", ew.config.Stage))
	
	// Create message handler
	handler := MessageHandlerFunc(func(ctx context.Context, msg *StreamMessage) error {
		return ew.processMessage(ctx, msg)
	})
	
	// Start consuming messages
	return ew.streamHandler.ConsumeMessages(ctx, ew.config.Stage, ew.config.WorkerName, handler)
}

// processMessage processes a single message with full observability and error handling
func (ew *EnhancedWorker) processMessage(ctx context.Context, msg *StreamMessage) error {
	// Start processing context for observability
	processingCtx := ew.metrics.StartProcessing(ctx, msg.AlertID, ew.config.Stage)
	defer func() {
		// Always end the processing context
		if r := recover(); r != nil {
			err := fmt.Errorf("worker panicked: %v", r)
			processingCtx.Failure(err)
			ew.logger.Error("Worker panicked during message processing",
				zap.String("alert_id", msg.AlertID),
				zap.String("worker", ew.config.WorkerName),
				zap.Any("panic", r))
		}
	}()
	
	// Parse alert from message
	alert, err := ew.parseAlert(msg)
	if err != nil {
		processingCtx.Failure(err)
		return NewPermanentError(ew.config.Stage, msg.AlertID, "failed to parse alert", err)
	}
	
	// Validate alert
	if err := ew.processor.ValidateAlert(alert); err != nil {
		processingCtx.Failure(err)
		return NewPermanentError(ew.config.Stage, msg.AlertID, "alert validation failed", err)
	}
	
	processingCtx.AddAttribute("alert_version", fmt.Sprintf("%d", alert.Version))
	processingCtx.AddAttribute("processor_name", ew.processor.GetProcessorName())
	
	// Process with circuit breaker protection if enabled
	var processedAlert *Alert
	if ew.config.EnableCircuitBreaker && ew.circuitBreaker != nil {
		err = ew.circuitBreaker.Execute(ctx, func() error {
			var procErr error
			processedAlert, procErr = ew.processor.ProcessAlert(ctx, alert)
			return procErr
		})
	} else {
		processedAlert, err = ew.processor.ProcessAlert(ctx, alert)
	}
	
	if err != nil {
		// Determine if error is retryable
		if delphiErr, ok := err.(*DelphiError); ok {
			if delphiErr.IsRetryable() && alert.Attempt < ew.config.MaxRetries {
				processingCtx.Retry(alert.Attempt+1, err)
				return ew.scheduleRetry(ctx, alert, err)
			}
		}
		
		processingCtx.Failure(err)
		return err
	}
	
	// Publish processed alert to next stage
	if err := ew.publishToNextStage(ctx, processedAlert); err != nil {
		processingCtx.Failure(err)
		return NewTransientError(ew.config.Stage, alert.ID, "failed to publish to next stage", err)
	}
	
	processingCtx.Success()
	
	ew.logger.Info("Alert processed successfully",
		zap.String("alert_id", alert.ID),
		zap.String("worker", ew.config.WorkerName),
		zap.String("stage", ew.config.Stage),
		zap.Duration("processing_time", time.Since(processingCtx.StartTime)))
	
	return nil
}

// parseAlert converts a stream message to an Alert
func (ew *EnhancedWorker) parseAlert(msg *StreamMessage) (*Alert, error) {
	alertData, ok := msg.Data["alert"]
	if !ok {
		return nil, fmt.Errorf("message missing alert data")
	}
	
	alertBytes, err := json.Marshal(alertData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal alert data: %w", err)
	}
	
	var alert Alert
	if err := json.Unmarshal(alertBytes, &alert); err != nil {
		return nil, fmt.Errorf("failed to unmarshal alert: %w", err)
	}
	
	// Set processing metadata
	alert.Attempt = msg.Retry
	alert.ProcessedBy = ew.config.WorkerName
	
	return &alert, nil
}

// publishToNextStage publishes the processed alert to the next pipeline stage
func (ew *EnhancedWorker) publishToNextStage(ctx context.Context, alert *Alert) error {
	nextStage := ew.getNextStage(alert.Stage)
	if nextStage == "" {
		// This is the final stage
		ew.logger.Info("Alert processing pipeline completed",
			zap.String("alert_id", alert.ID),
			zap.String("final_stage", alert.Stage))
		return nil
	}
	
	// Create message for next stage
	msg := &StreamMessage{
		AlertID:   alert.ID,
		Stage:     nextStage,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"alert": alert,
		},
	}
	
	// Publish to appropriate channel
	channel := ew.getChannelForStage(nextStage)
	return ew.streamHandler.PublishMessage(ctx, channel, msg)
}

// getNextStage determines the next stage in the pipeline
func (ew *EnhancedWorker) getNextStage(currentStage string) string {
	stageMap := map[string]string{
		"new":         "enriching",
		"enriching":   "enriched",
		"enriched":    "analyzing",
		"analyzing":   "analyzed",
		"analyzed":    "formatting",
		"formatting":  "formatted",
		"formatted":   "sending",
		"sending":     "", // Final stage
	}
	
	return stageMap[currentStage]
}

// getChannelForStage maps pipeline stages to Redis Stream channels
func (ew *EnhancedWorker) getChannelForStage(stage string) string {
	channelMap := map[string]string{
		"enriching": "new_alert",
		"enriched":  "agent_enriched", 
		"analyzing": "new_response",
		"analyzed":  "alert_structured",
		"formatting":"alert_formatted",
		"sending":   "alert_formatted",
	}
	
	return channelMap[stage]
}

// scheduleRetry schedules an alert for retry processing
func (ew *EnhancedWorker) scheduleRetry(ctx context.Context, alert *Alert, processingErr error) error {
	alert.Attempt++
	
	// Calculate exponential backoff delay
	delay := time.Duration(alert.Attempt) * ew.config.RetryBackoff
	retryTime := time.Now().Add(delay)
	
	ew.logger.Warn("Scheduling alert for retry",
		zap.String("alert_id", alert.ID),
		zap.Int("attempt", alert.Attempt),
		zap.Duration("delay", delay),
		zap.Time("retry_time", retryTime),
		zap.Error(processingErr))
	
	// Create retry message
	retryMsg := &StreamMessage{
		AlertID:   alert.ID,
		Stage:     alert.Stage,
		Timestamp: retryTime,
		Retry:     alert.Attempt,
		Data: map[string]interface{}{
			"alert":      alert,
			"retry_reason": processingErr.Error(),
			"original_error": processingErr.Error(),
		},
	}
	
	// Publish to retry queue (could be a delayed queue implementation)
	return ew.publishRetryMessage(ctx, retryMsg, delay)
}

// publishRetryMessage publishes a message for delayed retry
func (ew *EnhancedWorker) publishRetryMessage(ctx context.Context, msg *StreamMessage, delay time.Duration) error {
	// For now, sleep and republish (in production, use Redis delayed queues)
	go func() {
		time.Sleep(delay)
		
		retryCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		
		channel := ew.getChannelForStage(msg.Stage)
		if err := ew.streamHandler.PublishMessage(retryCtx, channel, msg); err != nil {
			ew.logger.Error("Failed to publish retry message",
				zap.String("alert_id", msg.AlertID),
				zap.Error(err))
		}
	}()
	
	return nil
}

// GetStats returns current worker statistics
func (ew *EnhancedWorker) GetStats(ctx context.Context) WorkerStats {
	stats := WorkerStats{
		WorkerName:     ew.config.WorkerName,
		Stage:          ew.config.Stage,
		ProcessorName:  ew.processor.GetProcessorName(),
		StartTime:      time.Now(), // In practice, track actual start time
	}
	
	// Add circuit breaker stats if enabled
	if ew.circuitBreaker != nil {
		cbStats := ew.circuitBreaker.GetStats(ctx)
		stats.CircuitBreakerStats = &cbStats
	}
	
	return stats
}

// WorkerStats holds statistics about a worker
type WorkerStats struct {
	WorkerName          string                `json:"worker_name"`
	Stage               string                `json:"stage"`
	ProcessorName       string                `json:"processor_name"`
	StartTime           time.Time             `json:"start_time"`
	CircuitBreakerStats *CircuitBreakerStats  `json:"circuit_breaker_stats,omitempty"`
}

// Stop gracefully stops the worker
func (ew *EnhancedWorker) Stop(ctx context.Context) error {
	ew.logger.Info("Stopping enhanced worker",
		zap.String("worker_name", ew.config.WorkerName))
	
	// Close stream handler
	if err := ew.streamHandler.Close(); err != nil {
		ew.logger.Error("Error closing stream handler", zap.Error(err))
		return err
	}
	
	ew.logger.Info("Enhanced worker stopped",
		zap.String("worker_name", ew.config.WorkerName))
	
	return nil
}

// Helper functions for environment variable parsing
func getEnvBoolOrDefault(key string, defaultVal bool) bool {
	if val := os.Getenv(key); val != "" {
		return val == "true" || val == "1" || val == "yes"
	}
	return defaultVal
}