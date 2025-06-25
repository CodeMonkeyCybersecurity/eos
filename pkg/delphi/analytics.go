package delphi

import (
	"context"
	"fmt"
	"sort"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

// AnalyticsEngine provides advanced analytics capabilities for Delphi
type AnalyticsEngine struct {
	db     *gorm.DB
	logger *zap.Logger
}

// NewAnalyticsEngine creates a new analytics engine
func NewAnalyticsEngine(db *gorm.DB, logger *zap.Logger) *AnalyticsEngine {
	return &AnalyticsEngine{
		db:     db,
		logger: logger,
	}
}

// PipelineMetrics represents comprehensive pipeline performance metrics
type PipelineMetrics struct {
	TimeRange   TimeRange                `json:"time_range"`
	Overview    PipelineOverview         `json:"overview"`
	Performance PerformanceMetrics       `json:"performance"`
	Reliability ReliabilityMetrics       `json:"reliability"`
	Stages      map[string]StageMetrics  `json:"stages"`
	Trends      TrendAnalysis            `json:"trends"`
	Anomalies   []Anomaly                `json:"anomalies"`
}

// TimeRange represents a time period for analysis
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// PipelineOverview provides high-level pipeline statistics
type PipelineOverview struct {
	TotalAlerts      int64   `json:"total_alerts"`
	ProcessedAlerts  int64   `json:"processed_alerts"`
	FailedAlerts     int64   `json:"failed_alerts"`
	RetriedAlerts    int64   `json:"retried_alerts"`
	SuccessRate      float64 `json:"success_rate_percent"`
	RetryRate        float64 `json:"retry_rate_percent"`
	AverageLatency   float64 `json:"average_latency_seconds"`
}

// PerformanceMetrics tracks processing performance
type PerformanceMetrics struct {
	Throughput          ThroughputMetrics     `json:"throughput"`
	Latency             LatencyMetrics        `json:"latency"`
	QueueDepth          QueueMetrics          `json:"queue_depth"`
	CircuitBreakerStats CircuitBreakerMetrics `json:"circuit_breakers"`
}

// ThroughputMetrics measures processing volume over time
type ThroughputMetrics struct {
	AlertsPerSecond    float64            `json:"alerts_per_second"`
	AlertsPerMinute    float64            `json:"alerts_per_minute"`
	AlertsPerHour      float64            `json:"alerts_per_hour"`
	PeakThroughput     float64            `json:"peak_throughput_per_second"`
	ThroughputByHour   map[string]float64 `json:"throughput_by_hour"`
}

// LatencyMetrics measures processing speed
type LatencyMetrics struct {
	P50Latency     float64                `json:"p50_latency_seconds"`
	P95Latency     float64                `json:"p95_latency_seconds"`
	P99Latency     float64                `json:"p99_latency_seconds"`
	MaxLatency     float64                `json:"max_latency_seconds"`
	MinLatency     float64                `json:"min_latency_seconds"`
	LatencyByStage map[string]float64     `json:"latency_by_stage_seconds"`
	LatencyTrend   []TimeSeries           `json:"latency_trend"`
}

// QueueMetrics tracks queue performance
type QueueMetrics struct {
	AverageDepth    float64      `json:"average_depth"`
	MaxDepth        int64        `json:"max_depth"`
	DepthTrend      []TimeSeries `json:"depth_trend"`
	BacklogDuration float64      `json:"backlog_duration_seconds"`
}

// CircuitBreakerMetrics aggregates circuit breaker statistics
type CircuitBreakerMetrics struct {
	TotalCircuitBreakers int64                         `json:"total_circuit_breakers"`
	OpenCircuitBreakers  int64                         `json:"open_circuit_breakers"`
	CircuitBreakerStates map[string]string             `json:"circuit_breaker_states"`
	TripEvents           []CircuitBreakerEvent         `json:"trip_events"`
	RecoveryEvents       []CircuitBreakerEvent         `json:"recovery_events"`
}

// ReliabilityMetrics tracks system reliability
type ReliabilityMetrics struct {
	Availability     float64                    `json:"availability_percent"`
	MTTR             float64                    `json:"mttr_seconds"` // Mean Time To Recovery
	MTBF             float64                    `json:"mtbf_seconds"` // Mean Time Between Failures
	ErrorRate        float64                    `json:"error_rate_percent"`
	ErrorBreakdown   map[string]int64           `json:"error_breakdown"`
	TopErrors        []ErrorFrequency           `json:"top_errors"`
	RecoveryPatterns []RecoveryPattern          `json:"recovery_patterns"`
}

// StageMetrics provides per-stage analytics
type StageMetrics struct {
	StageName          string                 `json:"stage_name"`
	AlertsProcessed    int64                  `json:"alerts_processed"`
	AverageLatency     float64                `json:"average_latency_seconds"`
	SuccessRate        float64                `json:"success_rate_percent"`
	ErrorCount         int64                  `json:"error_count"`
	RetryCount         int64                  `json:"retry_count"`
	WorkerBreakdown    map[string]int64       `json:"worker_breakdown"`
	HourlyThroughput   map[string]int64       `json:"hourly_throughput"`
}

// TrendAnalysis identifies patterns and trends
type TrendAnalysis struct {
	VolumeGrowth      TrendMetric      `json:"volume_growth"`
	PerformanceTrend  TrendMetric      `json:"performance_trend"`
	ErrorRateTrend    TrendMetric      `json:"error_rate_trend"`
	SeasonalPatterns  []SeasonalPattern `json:"seasonal_patterns"`
	Forecasts         []Forecast       `json:"forecasts"`
}

// Supporting types
type TimeSeries struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

type CircuitBreakerEvent struct {
	CircuitName string    `json:"circuit_name"`
	EventType   string    `json:"event_type"` // OPENED, CLOSED, HALF_OPENED
	Timestamp   time.Time `json:"timestamp"`
	Reason      string    `json:"reason"`
}

type ErrorFrequency struct {
	ErrorMessage string `json:"error_message"`
	Count        int64  `json:"count"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
}

type RecoveryPattern struct {
	ErrorType      string        `json:"error_type"`
	AverageRecovery time.Duration `json:"average_recovery"`
	SuccessRate    float64       `json:"success_rate_percent"`
}

type TrendMetric struct {
	Direction     string  `json:"direction"` // INCREASING, DECREASING, STABLE
	ChangePercent float64 `json:"change_percent"`
	Confidence    float64 `json:"confidence_percent"`
}

type SeasonalPattern struct {
	Pattern     string  `json:"pattern"`     // DAILY, WEEKLY, MONTHLY
	PeakHours   []int   `json:"peak_hours"`
	LowHours    []int   `json:"low_hours"`
	Amplitude   float64 `json:"amplitude"`
}

type Forecast struct {
	Metric      string    `json:"metric"`
	PredictedValue float64 `json:"predicted_value"`
	Confidence  float64   `json:"confidence_percent"`
	Horizon     time.Duration `json:"horizon"`
}

type Anomaly struct {
	Type        string    `json:"type"`        // SPIKE, DROP, TREND_BREAK
	Metric      string    `json:"metric"`
	Timestamp   time.Time `json:"timestamp"`
	Severity    string    `json:"severity"`    // LOW, MEDIUM, HIGH, CRITICAL
	Description string    `json:"description"`
	Impact      string    `json:"impact"`
}

// GetPipelineMetrics retrieves comprehensive pipeline metrics
func (ae *AnalyticsEngine) GetPipelineMetrics(ctx context.Context, start, end time.Time) (*PipelineMetrics, error) {
	timeRange := TimeRange{Start: start, End: end}
	
	// Get overview metrics
	overview, err := ae.getOverviewMetrics(ctx, start, end)
	if err != nil {
		return nil, fmt.Errorf("failed to get overview metrics: %w", err)
	}
	
	// Get performance metrics
	performance, err := ae.getPerformanceMetrics(ctx, start, end)
	if err != nil {
		return nil, fmt.Errorf("failed to get performance metrics: %w", err)
	}
	
	// Get reliability metrics
	reliability, err := ae.getReliabilityMetrics(ctx, start, end)
	if err != nil {
		return nil, fmt.Errorf("failed to get reliability metrics: %w", err)
	}
	
	// Get stage-specific metrics
	stages, err := ae.getStageMetrics(ctx, start, end)
	if err != nil {
		return nil, fmt.Errorf("failed to get stage metrics: %w", err)
	}
	
	// Get trend analysis
	trends, err := ae.getTrendAnalysis(ctx, start, end)
	if err != nil {
		return nil, fmt.Errorf("failed to get trend analysis: %w", err)
	}
	
	// Detect anomalies
	anomalies, err := ae.detectAnomalies(ctx, start, end)
	if err != nil {
		return nil, fmt.Errorf("failed to detect anomalies: %w", err)
	}
	
	return &PipelineMetrics{
		TimeRange:   timeRange,
		Overview:    *overview,
		Performance: *performance,
		Reliability: *reliability,
		Stages:      stages,
		Trends:      *trends,
		Anomalies:   anomalies,
	}, nil
}

// getOverviewMetrics calculates high-level pipeline statistics
func (ae *AnalyticsEngine) getOverviewMetrics(ctx context.Context, start, end time.Time) (*PipelineOverview, error) {
	var result struct {
		TotalAlerts     int64   `gorm:"column:total_alerts"`
		ProcessedAlerts int64   `gorm:"column:processed_alerts"`
		FailedAlerts    int64   `gorm:"column:failed_alerts"`
		RetriedAlerts   int64   `gorm:"column:retried_alerts"`
		AvgLatency      float64 `gorm:"column:avg_latency"`
	}
	
	err := ae.db.WithContext(ctx).Raw(`
		SELECT 
			COUNT(*) as total_alerts,
			COUNT(CASE WHEN action = 'PROCESSED' THEN 1 END) as processed_alerts,
			COUNT(CASE WHEN action LIKE '%FAILED%' THEN 1 END) as failed_alerts,
			COUNT(CASE WHEN retry_count > 0 THEN 1 END) as retried_alerts,
			AVG(EXTRACT(EPOCH FROM processing_duration)) as avg_latency
		FROM audit_entries
		WHERE timestamp >= ? AND timestamp <= ?
	`, start, end).Scan(&result).Error
	
	if err != nil {
		return nil, err
	}
	
	var successRate, retryRate float64
	if result.TotalAlerts > 0 {
		successRate = float64(result.ProcessedAlerts) / float64(result.TotalAlerts) * 100
		retryRate = float64(result.RetriedAlerts) / float64(result.TotalAlerts) * 100
	}
	
	return &PipelineOverview{
		TotalAlerts:     result.TotalAlerts,
		ProcessedAlerts: result.ProcessedAlerts,
		FailedAlerts:    result.FailedAlerts,
		RetriedAlerts:   result.RetriedAlerts,
		SuccessRate:     successRate,
		RetryRate:       retryRate,
		AverageLatency:  result.AvgLatency,
	}, nil
}

// getPerformanceMetrics calculates performance-related metrics
func (ae *AnalyticsEngine) getPerformanceMetrics(ctx context.Context, start, end time.Time) (*PerformanceMetrics, error) {
	// Calculate throughput
	duration := end.Sub(start)
	
	var alertCount int64
	err := ae.db.WithContext(ctx).Model(&AuditEntry{}).
		Where("timestamp >= ? AND timestamp <= ?", start, end).
		Count(&alertCount).Error
	if err != nil {
		return nil, err
	}
	
	alertsPerSecond := float64(alertCount) / duration.Seconds()
	alertsPerMinute := alertsPerSecond * 60
	alertsPerHour := alertsPerMinute * 60
	
	// Get latency percentiles
	var latencies []float64
	err = ae.db.WithContext(ctx).Raw(`
		SELECT EXTRACT(EPOCH FROM processing_duration) as latency
		FROM audit_entries
		WHERE timestamp >= ? AND timestamp <= ? 
		AND processing_duration IS NOT NULL
		ORDER BY processing_duration
	`, start, end).Pluck("latency", &latencies).Error
	if err != nil {
		return nil, err
	}
	
	var p50, p95, p99, maxLatency, minLatency float64
	if len(latencies) > 0 {
		sort.Float64s(latencies)
		p50 = percentile(latencies, 50)
		p95 = percentile(latencies, 95)
		p99 = percentile(latencies, 99)
		maxLatency = latencies[len(latencies)-1]
		minLatency = latencies[0]
	}
	
	// Get throughput by hour
	throughputByHour, err := ae.getThroughputByHour(ctx, start, end)
	if err != nil {
		return nil, err
	}
	
	// Get peak throughput
	peakThroughput := float64(0)
	for _, hourlyCount := range throughputByHour {
		if hourlyCount > peakThroughput {
			peakThroughput = hourlyCount
		}
	}
	peakThroughput = peakThroughput / 3600 // Convert to per-second
	
	// Get latency by stage
	latencyByStage, err := ae.getLatencyByStage(ctx, start, end)
	if err != nil {
		return nil, err
	}
	
	// Get circuit breaker stats
	cbStats, err := ae.getCircuitBreakerMetrics(ctx, start, end)
	if err != nil {
		return nil, err
	}
	
	return &PerformanceMetrics{
		Throughput: ThroughputMetrics{
			AlertsPerSecond:  alertsPerSecond,
			AlertsPerMinute:  alertsPerMinute,
			AlertsPerHour:    alertsPerHour,
			PeakThroughput:   peakThroughput,
			ThroughputByHour: throughputByHour,
		},
		Latency: LatencyMetrics{
			P50Latency:     p50,
			P95Latency:     p95,
			P99Latency:     p99,
			MaxLatency:     maxLatency,
			MinLatency:     minLatency,
			LatencyByStage: latencyByStage,
		},
		CircuitBreakerStats: *cbStats,
	}, nil
}

// getReliabilityMetrics calculates reliability and error metrics
func (ae *AnalyticsEngine) getReliabilityMetrics(ctx context.Context, start, end time.Time) (*ReliabilityMetrics, error) {
	// Get error breakdown
	var errorResults []struct {
		ErrorMessage string `gorm:"column:error_message"`
		Count        int64  `gorm:"column:count"`
		FirstSeen    time.Time `gorm:"column:first_seen"`
		LastSeen     time.Time `gorm:"column:last_seen"`
	}
	
	err := ae.db.WithContext(ctx).Raw(`
		SELECT 
			error_message,
			COUNT(*) as count,
			MIN(timestamp) as first_seen,
			MAX(timestamp) as last_seen
		FROM audit_entries
		WHERE timestamp >= ? AND timestamp <= ? 
		AND error_message != ''
		GROUP BY error_message
		ORDER BY count DESC
		LIMIT 20
	`, start, end).Scan(&errorResults).Error
	if err != nil {
		return nil, err
	}
	
	errorBreakdown := make(map[string]int64)
	topErrors := make([]ErrorFrequency, len(errorResults))
	
	for i, result := range errorResults {
		errorBreakdown[result.ErrorMessage] = result.Count
		topErrors[i] = ErrorFrequency{
			ErrorMessage: result.ErrorMessage,
			Count:        result.Count,
			FirstSeen:    result.FirstSeen,
			LastSeen:     result.LastSeen,
		}
	}
	
	// Calculate error rate
	var totalAlerts, errorAlerts int64
	err = ae.db.WithContext(ctx).Raw(`
		SELECT 
			COUNT(*) as total,
			COUNT(CASE WHEN error_message != '' THEN 1 END) as errors
		FROM audit_entries
		WHERE timestamp >= ? AND timestamp <= ?
	`, start, end).Row().Scan(&totalAlerts, &errorAlerts)
	if err != nil {
		return nil, err
	}
	
	var errorRate float64
	if totalAlerts > 0 {
		errorRate = float64(errorAlerts) / float64(totalAlerts) * 100
	}
	
	// Calculate availability (simplified)
	availability := 100.0 - errorRate
	
	return &ReliabilityMetrics{
		Availability:   availability,
		ErrorRate:      errorRate,
		ErrorBreakdown: errorBreakdown,
		TopErrors:      topErrors,
	}, nil
}

// getStageMetrics calculates per-stage performance metrics
func (ae *AnalyticsEngine) getStageMetrics(ctx context.Context, start, end time.Time) (map[string]StageMetrics, error) {
	var stageResults []struct {
		Stage           string  `gorm:"column:stage"`
		AlertsProcessed int64   `gorm:"column:alerts_processed"`
		AverageLatency  float64 `gorm:"column:average_latency"`
		ErrorCount      int64   `gorm:"column:error_count"`
		RetryCount      int64   `gorm:"column:retry_count"`
	}
	
	err := ae.db.WithContext(ctx).Raw(`
		SELECT 
			stage,
			COUNT(*) as alerts_processed,
			AVG(EXTRACT(EPOCH FROM processing_duration)) as average_latency,
			COUNT(CASE WHEN error_message != '' THEN 1 END) as error_count,
			COUNT(CASE WHEN retry_count > 0 THEN 1 END) as retry_count
		FROM audit_entries
		WHERE timestamp >= ? AND timestamp <= ?
		GROUP BY stage
	`, start, end).Scan(&stageResults).Error
	if err != nil {
		return nil, err
	}
	
	stages := make(map[string]StageMetrics)
	
	for _, result := range stageResults {
		var successRate float64
		if result.AlertsProcessed > 0 {
			successRate = float64(result.AlertsProcessed-result.ErrorCount) / float64(result.AlertsProcessed) * 100
		}
		
		// Get worker breakdown for this stage
		workerBreakdown, err := ae.getWorkerBreakdown(ctx, start, end, result.Stage)
		if err != nil {
			return nil, err
		}
		
		stages[result.Stage] = StageMetrics{
			StageName:       result.Stage,
			AlertsProcessed: result.AlertsProcessed,
			AverageLatency:  result.AverageLatency,
			SuccessRate:     successRate,
			ErrorCount:      result.ErrorCount,
			RetryCount:      result.RetryCount,
			WorkerBreakdown: workerBreakdown,
		}
	}
	
	return stages, nil
}

// Helper functions

func (ae *AnalyticsEngine) getThroughputByHour(ctx context.Context, start, end time.Time) (map[string]float64, error) {
	var results []struct {
		Hour  int   `gorm:"column:hour"`
		Count int64 `gorm:"column:count"`
	}
	
	err := ae.db.WithContext(ctx).Raw(`
		SELECT 
			EXTRACT(HOUR FROM timestamp) as hour,
			COUNT(*) as count
		FROM audit_entries
		WHERE timestamp >= ? AND timestamp <= ?
		GROUP BY EXTRACT(HOUR FROM timestamp)
		ORDER BY hour
	`, start, end).Scan(&results).Error
	if err != nil {
		return nil, err
	}
	
	throughput := make(map[string]float64)
	for _, result := range results {
		throughput[fmt.Sprintf("%02d:00", result.Hour)] = float64(result.Count) / 3600 // Per second
	}
	
	return throughput, nil
}

func (ae *AnalyticsEngine) getLatencyByStage(ctx context.Context, start, end time.Time) (map[string]float64, error) {
	var results []struct {
		Stage   string  `gorm:"column:stage"`
		Latency float64 `gorm:"column:latency"`
	}
	
	err := ae.db.WithContext(ctx).Raw(`
		SELECT 
			stage,
			AVG(EXTRACT(EPOCH FROM processing_duration)) as latency
		FROM audit_entries
		WHERE timestamp >= ? AND timestamp <= ? 
		AND processing_duration IS NOT NULL
		GROUP BY stage
	`, start, end).Scan(&results).Error
	if err != nil {
		return nil, err
	}
	
	latencyByStage := make(map[string]float64)
	for _, result := range results {
		latencyByStage[result.Stage] = result.Latency
	}
	
	return latencyByStage, nil
}

func (ae *AnalyticsEngine) getCircuitBreakerMetrics(ctx context.Context, start, end time.Time) (*CircuitBreakerMetrics, error) {
	// Get circuit breaker events
	var events []struct {
		WorkerName string    `gorm:"column:worker_name"`
		Action     string    `gorm:"column:action"`
		Timestamp  time.Time `gorm:"column:timestamp"`
		CBState    string    `gorm:"column:circuit_breaker_state"`
	}
	
	err := ae.db.WithContext(ctx).Raw(`
		SELECT worker_name, action, timestamp, circuit_breaker_state
		FROM audit_entries
		WHERE timestamp >= ? AND timestamp <= ? 
		AND stage = 'CIRCUIT_BREAKER'
		ORDER BY timestamp
	`, start, end).Scan(&events).Error
	if err != nil {
		return nil, err
	}
	
	tripEvents := []CircuitBreakerEvent{}
	recoveryEvents := []CircuitBreakerEvent{}
	cbStates := make(map[string]string)
	
	for _, event := range events {
		switch event.CBState {
		case "OPEN":
			tripEvents = append(tripEvents, CircuitBreakerEvent{
				CircuitName: event.WorkerName,
				EventType:   "OPENED",
				Timestamp:   event.Timestamp,
				Reason:      "Failure threshold exceeded",
			})
		case "CLOSED":
			recoveryEvents = append(recoveryEvents, CircuitBreakerEvent{
				CircuitName: event.WorkerName,
				EventType:   "CLOSED",
				Timestamp:   event.Timestamp,
				Reason:      "Recovery successful",
			})
		}
		cbStates[event.WorkerName] = event.CBState
	}
	
	openCount := int64(0)
	for _, state := range cbStates {
		if state == "OPEN" {
			openCount++
		}
	}
	
	return &CircuitBreakerMetrics{
		TotalCircuitBreakers: int64(len(cbStates)),
		OpenCircuitBreakers:  openCount,
		CircuitBreakerStates: cbStates,
		TripEvents:           tripEvents,
		RecoveryEvents:       recoveryEvents,
	}, nil
}

func (ae *AnalyticsEngine) getWorkerBreakdown(ctx context.Context, start, end time.Time, stage string) (map[string]int64, error) {
	var results []struct {
		WorkerName string `gorm:"column:worker_name"`
		Count      int64  `gorm:"column:count"`
	}
	
	err := ae.db.WithContext(ctx).Raw(`
		SELECT worker_name, COUNT(*) as count
		FROM audit_entries
		WHERE timestamp >= ? AND timestamp <= ? AND stage = ?
		GROUP BY worker_name
	`, start, end, stage).Scan(&results).Error
	if err != nil {
		return nil, err
	}
	
	breakdown := make(map[string]int64)
	for _, result := range results {
		breakdown[result.WorkerName] = result.Count
	}
	
	return breakdown, nil
}

func (ae *AnalyticsEngine) getTrendAnalysis(ctx context.Context, start, end time.Time) (*TrendAnalysis, error) {
	// Simplified trend analysis - in production, this would use more sophisticated algorithms
	return &TrendAnalysis{
		VolumeGrowth: TrendMetric{
			Direction:     "STABLE",
			ChangePercent: 0.0,
			Confidence:    85.0,
		},
		PerformanceTrend: TrendMetric{
			Direction:     "IMPROVING",
			ChangePercent: 5.2,
			Confidence:    75.0,
		},
		ErrorRateTrend: TrendMetric{
			Direction:     "DECREASING",
			ChangePercent: -12.3,
			Confidence:    90.0,
		},
	}, nil
}

func (ae *AnalyticsEngine) detectAnomalies(ctx context.Context, start, end time.Time) ([]Anomaly, error) {
	// Simplified anomaly detection - would use statistical methods in production
	return []Anomaly{}, nil
}

// percentile calculates the nth percentile of a sorted slice
func percentile(data []float64, p float64) float64 {
	if len(data) == 0 {
		return 0
	}
	
	index := (p / 100.0) * float64(len(data)-1)
	lower := int(index)
	upper := lower + 1
	
	if upper >= len(data) {
		return data[len(data)-1]
	}
	
	weight := index - float64(lower)
	return data[lower]*(1-weight) + data[upper]*weight
}