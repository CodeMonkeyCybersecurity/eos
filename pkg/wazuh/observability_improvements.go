// pkg/wazuh/observability/enhanced_monitoring.go
package wazuh

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// ObservabilityMetrics provides comprehensive observability for the Wazuh pipeline
type ObservabilityMetrics struct {
	// Counters
	alertsReceived  metric.Int64Counter
	alertsProcessed metric.Int64Counter
	alertsFailed    metric.Int64Counter
	alertsRetried   metric.Int64Counter

	// Histograms
	processingDuration metric.Float64Histogram
	queueDepth         metric.Int64Histogram
	llmTokens          metric.Int64Histogram

	// Gauges
	activeWorkers        metric.Int64UpDownCounter
	circuitBreakerStatus metric.Int64UpDownCounter

	tracer trace.Tracer
	logger *zap.Logger
}

func NewObservabilityMetrics(logger *zap.Logger) (*ObservabilityMetrics, error) {
	meter := otel.Meter("wazuh-pipeline")
	tracer := otel.Tracer("wazuh-pipeline")

	alertsReceived, err := meter.Int64Counter("wazuh_alerts_received_total",
		metric.WithDescription("Total number of alerts received"))
	if err != nil {
		return nil, fmt.Errorf("failed to create alerts_received counter: %w", err)
	}

	alertsProcessed, err := meter.Int64Counter("wazuh_alerts_processed_total",
		metric.WithDescription("Total number of alerts successfully processed"))
	if err != nil {
		return nil, fmt.Errorf("failed to create alerts_processed counter: %w", err)
	}

	alertsFailed, err := meter.Int64Counter("wazuh_alerts_failed_total",
		metric.WithDescription("Total number of alerts that failed processing"))
	if err != nil {
		return nil, fmt.Errorf("failed to create alerts_failed counter: %w", err)
	}

	alertsRetried, err := meter.Int64Counter("wazuh_alerts_retried_total",
		metric.WithDescription("Total number of alert processing retries"))
	if err != nil {
		return nil, fmt.Errorf("failed to create alerts_retried counter: %w", err)
	}

	processingDuration, err := meter.Float64Histogram("wazuh_processing_duration_seconds",
		metric.WithDescription("Time spent processing alerts by stage"))
	if err != nil {
		return nil, fmt.Errorf("failed to create processing_duration histogram: %w", err)
	}

	queueDepth, err := meter.Int64Histogram("wazuh_queue_depth",
		metric.WithDescription("Number of alerts waiting in queue"))
	if err != nil {
		return nil, fmt.Errorf("failed to create queue_depth histogram: %w", err)
	}

	llmTokens, err := meter.Int64Histogram("wazuh_llm_tokens_used",
		metric.WithDescription("Number of LLM tokens used per request"))
	if err != nil {
		return nil, fmt.Errorf("failed to create llm_tokens histogram: %w", err)
	}

	activeWorkers, err := meter.Int64UpDownCounter("wazuh_active_workers",
		metric.WithDescription("Number of active worker processes"))
	if err != nil {
		return nil, fmt.Errorf("failed to create active_workers gauge: %w", err)
	}

	circuitBreakerStatus, err := meter.Int64UpDownCounter("wazuh_circuit_breaker_status",
		metric.WithDescription("Circuit breaker status (0=closed, 1=open, 2=half-open)"))
	if err != nil {
		return nil, fmt.Errorf("failed to create circuit_breaker_status gauge: %w", err)
	}

	return &ObservabilityMetrics{
		alertsReceived:       alertsReceived,
		alertsProcessed:      alertsProcessed,
		alertsFailed:         alertsFailed,
		alertsRetried:        alertsRetried,
		processingDuration:   processingDuration,
		queueDepth:           queueDepth,
		llmTokens:            llmTokens,
		activeWorkers:        activeWorkers,
		circuitBreakerStatus: circuitBreakerStatus,
		tracer:               tracer,
		logger:               logger,
	}, nil
}

// ProcessingContext wraps alert processing with comprehensive observability
type ProcessingContext struct {
	AlertID    string
	Stage      string
	StartTime  time.Time
	Attributes []attribute.KeyValue
	span       trace.Span
	ctx        context.Context
	metrics    *ObservabilityMetrics
}

func (om *ObservabilityMetrics) StartProcessing(ctx context.Context, alertID, stage string) *ProcessingContext {
	ctx, span := om.tracer.Start(ctx, fmt.Sprintf("wazuh.%s", stage),
		trace.WithAttributes(
			attribute.String("alert.id", alertID),
			attribute.String("pipeline.stage", stage),
		))

	attrs := []attribute.KeyValue{
		attribute.String("stage", stage),
		attribute.String("alert_id", alertID),
	}

	om.logger.Info("Processing stage started",
		zap.String("alert_id", alertID),
		zap.String("stage", stage))

	return &ProcessingContext{
		AlertID:    alertID,
		Stage:      stage,
		StartTime:  time.Now(),
		Attributes: attrs,
		span:       span,
		ctx:        ctx,
		metrics:    om,
	}
}

func (pc *ProcessingContext) AddAttribute(key, value string) {
	attr := attribute.String(key, value)
	pc.Attributes = append(pc.Attributes, attr)
	pc.span.SetAttributes(attr)
}

func (pc *ProcessingContext) AddIntAttribute(key string, value int64) {
	attr := attribute.Int64(key, value)
	pc.Attributes = append(pc.Attributes, attr)
	pc.span.SetAttributes(attr)
}

func (pc *ProcessingContext) Success() {
	duration := time.Since(pc.StartTime).Seconds()

	pc.metrics.alertsProcessed.Add(pc.ctx, 1, metric.WithAttributes(pc.Attributes...))
	pc.metrics.processingDuration.Record(pc.ctx, duration, metric.WithAttributes(pc.Attributes...))

	pc.span.SetStatus(codes.Ok, "Processing completed successfully")
	pc.span.End()

	pc.metrics.logger.Info("Processing stage completed successfully",
		zap.String("alert_id", pc.AlertID),
		zap.String("stage", pc.Stage),
		zap.Duration("duration", time.Since(pc.StartTime)))
}

func (pc *ProcessingContext) Failure(err error) {
	duration := time.Since(pc.StartTime).Seconds()

	pc.metrics.alertsFailed.Add(pc.ctx, 1, metric.WithAttributes(pc.Attributes...))
	pc.metrics.processingDuration.Record(pc.ctx, duration, metric.WithAttributes(pc.Attributes...))

	pc.span.RecordError(err)
	pc.span.SetStatus(codes.Error, err.Error())
	pc.span.End()

	pc.metrics.logger.Error("Processing stage failed",
		zap.String("alert_id", pc.AlertID),
		zap.String("stage", pc.Stage),
		zap.Duration("duration", time.Since(pc.StartTime)),
		zap.Error(err))
}

func (pc *ProcessingContext) Retry(attempt int, err error) {
	pc.metrics.alertsRetried.Add(pc.ctx, 1, metric.WithAttributes(pc.Attributes...))

	pc.metrics.logger.Warn("Processing stage retry",
		zap.String("alert_id", pc.AlertID),
		zap.String("stage", pc.Stage),
		zap.Int("attempt", attempt),
		zap.Error(err))
}

func (pc *ProcessingContext) RecordLLMUsage(promptTokens, completionTokens int64) {
	totalTokens := promptTokens + completionTokens

	attrs := append(pc.Attributes,
		attribute.String("token_type", "total"),
	)

	pc.metrics.llmTokens.Record(pc.ctx, totalTokens, metric.WithAttributes(attrs...))

	pc.AddIntAttribute("llm.prompt_tokens", promptTokens)
	pc.AddIntAttribute("llm.completion_tokens", completionTokens)
	pc.AddIntAttribute("llm.total_tokens", totalTokens)
}

// Enhanced Error Types with Context
type WazuhError struct {
	Code      string
	Message   string
	Stage     string
	AlertID   string
	Cause     error
	Context   map[string]interface{}
	Retryable bool
	Timestamp time.Time
}

func (e *WazuhError) Error() string {
	return fmt.Sprintf("[%s:%s] %s (alert: %s): %v",
		e.Code, e.Stage, e.Message, e.AlertID, e.Cause)
}

func (e *WazuhError) IsRetryable() bool {
	return e.Retryable
}

func (e *WazuhError) WithContext(key string, value interface{}) *WazuhError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// Error constructors
func NewTransientError(stage, alertID, message string, cause error) *WazuhError {
	return &WazuhError{
		Code:      "TRANSIENT_ERROR",
		Message:   message,
		Stage:     stage,
		AlertID:   alertID,
		Cause:     cause,
		Retryable: true,
		Timestamp: time.Now(),
	}
}

func NewPermanentError(stage, alertID, message string, cause error) *WazuhError {
	return &WazuhError{
		Code:      "PERMANENT_ERROR",
		Message:   message,
		Stage:     stage,
		AlertID:   alertID,
		Cause:     cause,
		Retryable: false,
		Timestamp: time.Now(),
	}
}

// Health Check System
type HealthChecker struct {
	checks map[string]HealthCheck
	mutex  sync.RWMutex
	logger *zap.Logger
}

type HealthCheck interface {
	Name() string
	Check(ctx context.Context) error
}

type HealthResult struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	Error     string    `json:"error,omitempty"`
	Duration  string    `json:"duration"`
	Timestamp time.Time `json:"timestamp"`
}

func NewHealthChecker(logger *zap.Logger) *HealthChecker {
	return &HealthChecker{
		checks: make(map[string]HealthCheck),
		logger: logger,
	}
}

func (hc *HealthChecker) Register(check HealthCheck) {
	hc.mutex.Lock()
	defer hc.mutex.Unlock()
	hc.checks[check.Name()] = check
}

func (hc *HealthChecker) CheckAll(ctx context.Context) map[string]HealthResult {
	hc.mutex.RLock()
	checks := make(map[string]HealthCheck, len(hc.checks))
	for name, check := range hc.checks {
		checks[name] = check
	}
	hc.mutex.RUnlock()

	results := make(map[string]HealthResult)

	for name, check := range checks {
		start := time.Now()
		err := check.Check(ctx)
		duration := time.Since(start)

		result := HealthResult{
			Name:      name,
			Status:    "healthy",
			Duration:  duration.String(),
			Timestamp: time.Now(),
		}

		if err != nil {
			result.Status = "unhealthy"
			result.Error = err.Error()

			hc.logger.Error("Health check failed",
				zap.String("check", name),
				zap.Duration("duration", duration),
				zap.Error(err))
		} else {
			hc.logger.Debug("Health check passed",
				zap.String("check", name),
				zap.Duration("duration", duration))
		}

		results[name] = result
	}

	return results
}

// Database Health Check
type DatabaseHealthCheck struct {
	db     interface{ Ping() error }
	logger *zap.Logger
}

func NewDatabaseHealthCheck(db interface{ Ping() error }, logger *zap.Logger) *DatabaseHealthCheck {
	return &DatabaseHealthCheck{db: db, logger: logger}
}

func (dhc *DatabaseHealthCheck) Name() string {
	return "database"
}

func (dhc *DatabaseHealthCheck) Check(ctx context.Context) error {
	return dhc.db.Ping()
}

// Queue Health Check
type QueueHealthCheck struct {
	client interface{ Ping(context.Context) error }
	logger *zap.Logger
}

func NewQueueHealthCheck(client interface{ Ping(context.Context) error }, logger *zap.Logger) *QueueHealthCheck {
	return &QueueHealthCheck{client: client, logger: logger}
}

func (qhc *QueueHealthCheck) Name() string {
	return "queue"
}

func (qhc *QueueHealthCheck) Check(ctx context.Context) error {
	return qhc.client.Ping(ctx)
}
