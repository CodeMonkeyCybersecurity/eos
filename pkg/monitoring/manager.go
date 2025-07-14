package monitoring

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewMonitoringManager creates a new monitoring manager
func NewMonitoringManager(config *MonitoringConfig) *MonitoringManager {
	return &MonitoringManager{
		config:           config,
		healthCheckers:   make(map[string]HealthChecker),
		statusProviders:  make(map[string]StatusProvider),
		metricCollectors: make(map[string]MetricCollector),
		alertManager:     NewAlertManager(config.Alerting),
	}
}

// RegisterHealthChecker registers a health checker
func (mm *MonitoringManager) RegisterHealthChecker(checker HealthChecker) {
	mm.healthCheckers[checker.Name()] = checker
}

// RegisterStatusProvider registers a status provider
func (mm *MonitoringManager) RegisterStatusProvider(provider StatusProvider) {
	mm.statusProviders[provider.Name()] = provider
}

// RegisterMetricCollector registers a metric collector
func (mm *MonitoringManager) RegisterMetricCollector(collector MetricCollector) {
	mm.metricCollectors[collector.Name()] = collector
}

// CheckHealth performs a health check on a target
func (mm *MonitoringManager) CheckHealth(rc *eos_io.RuntimeContext, target *MonitoringTarget) (*HealthResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Performing health check",
		zap.String("target", target.Name),
		zap.String("type", string(target.Type)))

	// Assessment: Find appropriate health checker
	checker, err := mm.findHealthChecker(target.Type)
	if err != nil {
		return nil, &MonitoringError{
			Type:      "health_check_error",
			Target:    target.Name,
			Operation: "find_checker",
			Message:   "no suitable health checker found",
			Cause:     err,
			Timestamp: time.Now(),
		}
	}

	// Intervention: Perform the health check
	targetAddress := mm.buildTargetAddress(target)
	result, err := checker.Check(targetAddress, target.Config)
	if err != nil {
		logger.Warn("Health check failed",
			zap.String("target", target.Name),
			zap.Error(err))

		return &HealthResult{
			Target:    target.Name,
			Healthy:   false,
			Status:    HealthStatusUnhealthy,
			Message:   err.Error(),
			Timestamp: time.Now(),
			CheckType: checker.Name(),
		}, nil
	}

	// Evaluation: Validate and enrich result
	if result.Target == "" {
		result.Target = target.Name
	}
	if result.CheckType == "" {
		result.CheckType = checker.Name()
	}
	if result.Metadata == nil {
		result.Metadata = make(map[string]string)
	}
	result.Metadata["environment"] = target.Environment

	logger.Debug("Health check completed",
		zap.String("target", target.Name),
		zap.Bool("healthy", result.Healthy),
		zap.String("status", string(result.Status)))

	return result, nil
}

// GetStatus gets the status of a target
func (mm *MonitoringManager) GetStatus(rc *eos_io.RuntimeContext, target *MonitoringTarget) (*StatusResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Getting status",
		zap.String("target", target.Name),
		zap.String("type", string(target.Type)))

	// Assessment: Find appropriate status provider
	provider, err := mm.findStatusProvider(target.Type)
	if err != nil {
		return nil, &MonitoringError{
			Type:      "status_error",
			Target:    target.Name,
			Operation: "find_provider",
			Message:   "no suitable status provider found",
			Cause:     err,
			Timestamp: time.Now(),
		}
	}

	// Intervention: Get the status
	targetAddress := mm.buildTargetAddress(target)
	result, err := provider.GetStatus(targetAddress, target.Config)
	if err != nil {
		logger.Warn("Status check failed",
			zap.String("target", target.Name),
			zap.Error(err))

		return &StatusResult{
			Target:    target.Name,
			Status:    ServiceStatusUnknown,
			Timestamp: time.Now(),
		}, err
	}

	// Evaluation: Validate and enrich result
	if result.Target == "" {
		result.Target = target.Name
	}
	if result.Metadata == nil {
		result.Metadata = make(map[string]string)
	}
	result.Metadata["environment"] = target.Environment

	logger.Debug("Status check completed",
		zap.String("target", target.Name),
		zap.String("status", string(result.Status)))

	return result, nil
}

// CollectMetrics collects metrics from a target
func (mm *MonitoringManager) CollectMetrics(rc *eos_io.RuntimeContext, target *MonitoringTarget) (*MetricResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Collecting metrics",
		zap.String("target", target.Name),
		zap.String("type", string(target.Type)))

	// Assessment: Find appropriate metric collector
	collector, err := mm.findMetricCollector(target.Type)
	if err != nil {
		return nil, &MonitoringError{
			Type:      "metric_collection_error",
			Target:    target.Name,
			Operation: "find_collector",
			Message:   "no suitable metric collector found",
			Cause:     err,
			Timestamp: time.Now(),
		}
	}

	// Intervention: Collect metrics
	targetAddress := mm.buildTargetAddress(target)
	result, err := collector.Collect(targetAddress, target.Config)
	if err != nil {
		logger.Warn("Metric collection failed",
			zap.String("target", target.Name),
			zap.Error(err))

		return nil, &MonitoringError{
			Type:      "metric_collection_error",
			Target:    target.Name,
			Operation: "collect",
			Message:   "metric collection failed",
			Cause:     err,
			Timestamp: time.Now(),
		}
	}

	// Evaluation: Validate and enrich result
	if result.Target == "" {
		result.Target = target.Name
	}
	if result.Labels == nil {
		result.Labels = make(map[string]string)
	}
	result.Labels["environment"] = target.Environment
	result.Labels["target_type"] = string(target.Type)

	logger.Debug("Metrics collected",
		zap.String("target", target.Name),
		zap.Int("metric_count", len(result.Metrics)))

	return result, nil
}

// MonitorTargets continuously monitors a list of targets
func (mm *MonitoringManager) MonitorTargets(ctx context.Context, targets []*MonitoringTarget) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("Starting continuous monitoring",
		zap.Int("target_count", len(targets)))

	// Create a runtime context for monitoring operations
	rc := &eos_io.RuntimeContext{
		Ctx:       ctx,
		Component: "monitoring",
	}

	// Create tickers for different monitoring intervals
	healthTicker := time.NewTicker(mm.config.CheckInterval)
	metricTicker := time.NewTicker(mm.config.MetricInterval)

	defer healthTicker.Stop()
	defer metricTicker.Stop()

	// Start monitoring loops
	var wg sync.WaitGroup

	// Health monitoring loop
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-healthTicker.C:
				mm.performHealthChecks(rc, targets)
			}
		}
	}()

	// Metric collection loop
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-metricTicker.C:
				mm.collectAllMetrics(rc, targets)
			}
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()
	logger.Info("Stopping monitoring")

	// Wait for all goroutines to finish
	wg.Wait()

	return nil
}

// PerformHealthChecks performs health checks on all targets
func (mm *MonitoringManager) performHealthChecks(rc *eos_io.RuntimeContext, targets []*MonitoringTarget) {
	logger := otelzap.Ctx(rc.Ctx)

	var wg sync.WaitGroup
	for _, target := range targets {
		if !target.Enabled {
			continue
		}

		wg.Add(1)
		go func(t *MonitoringTarget) {
			defer wg.Done()

			result, err := mm.CheckHealth(rc, t)
			if err != nil {
				logger.Error("Health check failed",
					zap.String("target", t.Name),
					zap.Error(err))
				return
			}

			// Process result for alerting
			mm.processHealthResult(rc, t, result)

		}(target)
	}

	wg.Wait()
}

// CollectAllMetrics collects metrics from all targets
func (mm *MonitoringManager) collectAllMetrics(rc *eos_io.RuntimeContext, targets []*MonitoringTarget) {
	logger := otelzap.Ctx(rc.Ctx)

	var wg sync.WaitGroup
	for _, target := range targets {
		if !target.Enabled {
			continue
		}

		wg.Add(1)
		go func(t *MonitoringTarget) {
			defer wg.Done()

			result, err := mm.CollectMetrics(rc, t)
			if err != nil {
				logger.Error("Metric collection failed",
					zap.String("target", t.Name),
					zap.Error(err))
				return
			}

			// Process metrics for alerting
			mm.processMetricResult(rc, t, result)

		}(target)
	}

	wg.Wait()
}

// GetOverallHealth gets the overall health status for an environment
func (mm *MonitoringManager) GetOverallHealth(rc *eos_io.RuntimeContext, environment string, targets []*MonitoringTarget) (*OverallHealthResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Getting overall health",
		zap.String("environment", environment),
		zap.Int("target_count", len(targets)))

	result := &OverallHealthResult{
		Environment: environment,
		Timestamp:   time.Now(),
		Targets:     make(map[string]*HealthResult),
		Summary:     HealthSummary{},
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Check health of all targets concurrently
	for _, target := range targets {
		if !target.Enabled || target.Environment != environment {
			continue
		}

		wg.Add(1)
		go func(t *MonitoringTarget) {
			defer wg.Done()

			healthResult, err := mm.CheckHealth(rc, t)
			if err != nil {
				logger.Error("Health check failed",
					zap.String("target", t.Name),
					zap.Error(err))
				
				// Create a failure result
				healthResult = &HealthResult{
					Target:    t.Name,
					Healthy:   false,
					Status:    HealthStatusUnknown,
					Message:   err.Error(),
					Timestamp: time.Now(),
				}
			}

			mu.Lock()
			result.Targets[t.Name] = healthResult
			
			// Update summary
			result.Summary.Total++
			switch healthResult.Status {
			case HealthStatusHealthy:
				result.Summary.Healthy++
			case HealthStatusUnhealthy:
				result.Summary.Unhealthy++
			case HealthStatusDegraded:
				result.Summary.Degraded++
			default:
				result.Summary.Unknown++
			}
			mu.Unlock()

		}(target)
	}

	wg.Wait()

	// Calculate overall status
	if result.Summary.Total == 0 {
		result.OverallStatus = HealthStatusUnknown
	} else if result.Summary.Unhealthy > 0 {
		result.OverallStatus = HealthStatusUnhealthy
	} else if result.Summary.Degraded > 0 {
		result.OverallStatus = HealthStatusDegraded
	} else if result.Summary.Unknown > 0 {
		result.OverallStatus = HealthStatusUnknown
	} else {
		result.OverallStatus = HealthStatusHealthy
	}

	logger.Info("Overall health assessment completed",
		zap.String("environment", environment),
		zap.String("overall_status", string(result.OverallStatus)),
		zap.Int("total", result.Summary.Total),
		zap.Int("healthy", result.Summary.Healthy),
		zap.Int("unhealthy", result.Summary.Unhealthy))

	return result, nil
}

// Helper methods

func (mm *MonitoringManager) findHealthChecker(targetType TargetType) (HealthChecker, error) {
	for _, checker := range mm.healthCheckers {
		for _, supportedType := range checker.SupportedTypes() {
			if supportedType == string(targetType) {
				return checker, nil
			}
		}
	}
	return nil, fmt.Errorf("no health checker found for target type: %s", targetType)
}

func (mm *MonitoringManager) findStatusProvider(targetType TargetType) (StatusProvider, error) {
	for _, provider := range mm.statusProviders {
		for _, supportedType := range provider.SupportedTypes() {
			if supportedType == string(targetType) {
				return provider, nil
			}
		}
	}
	return nil, fmt.Errorf("no status provider found for target type: %s", targetType)
}

func (mm *MonitoringManager) findMetricCollector(targetType TargetType) (MetricCollector, error) {
	for _, collector := range mm.metricCollectors {
		for _, supportedType := range collector.SupportedMetrics() {
			if supportedType == string(targetType) {
				return collector, nil
			}
		}
	}
	return nil, fmt.Errorf("no metric collector found for target type: %s", targetType)
}

func (mm *MonitoringManager) buildTargetAddress(target *MonitoringTarget) string {
	if target.Port > 0 {
		return fmt.Sprintf("%s:%d", target.Address, target.Port)
	}
	return target.Address
}

func (mm *MonitoringManager) processHealthResult(rc *eos_io.RuntimeContext, target *MonitoringTarget, result *HealthResult) {
	// Check if this health result should trigger an alert
	if mm.alertManager != nil && !result.Healthy {
		alert := &Alert{
			ID:       fmt.Sprintf("health-%s-%d", target.Name, time.Now().Unix()),
			Rule:     "health_check_failed",
			Target:   target.Name,
			Severity: AlertSeverityWarning,
			Status:   AlertStatusActive,
			Message:  fmt.Sprintf("Health check failed: %s", result.Message),
			Details: map[string]interface{}{
				"health_status": result.Status,
				"check_type":    result.CheckType,
				"duration":      result.Duration,
			},
			StartTime: time.Now(),
			Metadata: map[string]string{
				"environment": target.Environment,
				"target_type": string(target.Type),
			},
		}
		
		mm.alertManager.TriggerAlert(rc, alert)
	}
}

func (mm *MonitoringManager) processMetricResult(rc *eos_io.RuntimeContext, target *MonitoringTarget, result *MetricResult) {
	// Process metrics for alerting rules
	if mm.alertManager != nil {
		mm.alertManager.EvaluateMetrics(rc, target, result)
	}
}

// OverallHealthResult represents the overall health of an environment
type OverallHealthResult struct {
	Environment   string                     `json:"environment"`
	OverallStatus HealthStatus               `json:"overall_status"`
	Summary       HealthSummary              `json:"summary"`
	Targets       map[string]*HealthResult   `json:"targets"`
	Timestamp     time.Time                  `json:"timestamp"`
}

// HealthSummary provides a summary of health check results
type HealthSummary struct {
	Total     int `json:"total"`
	Healthy   int `json:"healthy"`
	Unhealthy int `json:"unhealthy"`
	Degraded  int `json:"degraded"`
	Unknown   int `json:"unknown"`
}