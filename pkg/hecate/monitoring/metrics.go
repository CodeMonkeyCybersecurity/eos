package monitoring

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// MetricsCollector collects and aggregates metrics from various sources
type MetricsCollector struct {
	rc           *eos_io.RuntimeContext
	caddyURL     string
	authentikURL string
}

// RouteMetrics represents metrics for a specific route
type RouteMetrics struct {
	Domain          string        `json:"domain"`
	RequestCount    int64         `json:"request_count"`
	ErrorCount      int64         `json:"error_count"`
	ResponseTime    time.Duration `json:"response_time"`
	BytesIn         int64         `json:"bytes_in"`
	BytesOut        int64         `json:"bytes_out"`
	ActiveRequests  int64         `json:"active_requests"`
	HealthStatus    string        `json:"health_status"`
	LastHealthCheck time.Time     `json:"last_health_check"`
	ErrorRate       float64       `json:"error_rate"`
}

// SystemMetrics represents system-wide metrics
type SystemMetrics struct {
	TotalRoutes         int           `json:"total_routes"`
	HealthyRoutes       int           `json:"healthy_routes"`
	UnhealthyRoutes     int           `json:"unhealthy_routes"`
	TotalRequests       int64         `json:"total_requests"`
	TotalErrors         int64         `json:"total_errors"`
	AverageResponseTime time.Duration `json:"average_response_time"`
	SystemLoad          float64       `json:"system_load"`
	MemoryUsage         float64       `json:"memory_usage"`
	CPUUsage            float64       `json:"cpu_usage"`
	DiskUsage           float64       `json:"disk_usage"`
	NetworkIn           int64         `json:"network_in"`
	NetworkOut          int64         `json:"network_out"`
	Uptime              time.Duration `json:"uptime"`
}

// MetricsSnapshot represents a point-in-time snapshot of all metrics
type MetricsSnapshot struct {
	Timestamp time.Time                `json:"timestamp"`
	Routes    map[string]RouteMetrics  `json:"routes"`
	System    SystemMetrics            `json:"system"`
	Services  map[string]ServiceHealth `json:"services"`
}

// ServiceHealth represents health status of a service
type ServiceHealth struct {
	Name         string        `json:"name"`
	Status       string        `json:"status"`
	ResponseTime time.Duration `json:"response_time"`
	LastCheck    time.Time     `json:"last_check"`
	ErrorMessage string        `json:"error_message,omitempty"`
	Version      string        `json:"version,omitempty"`
	Uptime       time.Duration `json:"uptime,omitempty"`
}

// AlertRule represents a monitoring alert rule
type AlertRule struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Condition   string            `json:"condition"`
	Threshold   float64           `json:"threshold"`
	Duration    time.Duration     `json:"duration"`
	Severity    string            `json:"severity"`
	Enabled     bool              `json:"enabled"`
	Labels      map[string]string `json:"labels"`
	Actions     []AlertAction     `json:"actions"`
}

// AlertAction represents an action to take when an alert fires
type AlertAction struct {
	Type   string                 `json:"type"` // email, webhook, slack, etc.
	Config map[string]interface{} `json:"config"`
}

// Alert represents a fired alert
type Alert struct {
	ID          string            `json:"id"`
	RuleID      string            `json:"rule_id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Severity    string            `json:"severity"`
	Status      string            `json:"status"` // firing, resolved
	FiredAt     time.Time         `json:"fired_at"`
	ResolvedAt  *time.Time        `json:"resolved_at,omitempty"`
	Labels      map[string]string `json:"labels"`
	Value       float64           `json:"value"`
	Threshold   float64           `json:"threshold"`
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(rc *eos_io.RuntimeContext, caddyURL, authentikURL string) *MetricsCollector {
	return &MetricsCollector{
		rc:           rc,
		caddyURL:     caddyURL,
		authentikURL: authentikURL,
	}
}

// CollectMetrics collects metrics from all sources
func (mc *MetricsCollector) CollectMetrics() (*MetricsSnapshot, error) {
	logger := otelzap.Ctx(mc.rc.Ctx)
	logger.Info("Collecting metrics from all sources")

	snapshot := &MetricsSnapshot{
		Timestamp: time.Now(),
		Routes:    make(map[string]RouteMetrics),
		Services:  make(map[string]ServiceHealth),
	}

	// Collect route metrics from Caddy
	routeMetrics, err := mc.collectRouteMetrics()
	if err != nil {
		logger.Warn("Failed to collect route metrics", zap.Error(err))
	} else {
		snapshot.Routes = routeMetrics
	}

	// Collect system metrics
	systemMetrics, err := mc.collectSystemMetrics()
	if err != nil {
		logger.Warn("Failed to collect system metrics", zap.Error(err))
	} else {
		snapshot.System = systemMetrics
	}

	// Collect service health
	serviceHealth, err := mc.collectServiceHealth()
	if err != nil {
		logger.Warn("Failed to collect service health", zap.Error(err))
	} else {
		snapshot.Services = serviceHealth
	}

	logger.Info("Metrics collection completed",
		zap.Int("routes", len(snapshot.Routes)),
		zap.Int("services", len(snapshot.Services)))

	return snapshot, nil
}

// collectRouteMetrics collects metrics for all routes from Caddy
func (mc *MetricsCollector) collectRouteMetrics() (map[string]RouteMetrics, error) {
	logger := otelzap.Ctx(mc.rc.Ctx)
	metrics := make(map[string]RouteMetrics)

	// Get metrics from Caddy admin API
	client := &http.Client{Timeout: 10 * time.Second}
	url := fmt.Sprintf("%s/metrics", mc.caddyURL)

	req, err := http.NewRequestWithContext(mc.rc.Ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get metrics from Caddy: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Caddy metrics API returned %d", resp.StatusCode)
	}

	// TODO: Parse Caddy metrics response
	// For now, create mock data
	mockRoutes := []string{"api.example.com", "app.example.com", "admin.example.com"}
	for _, domain := range mockRoutes {
		metrics[domain] = RouteMetrics{
			Domain:          domain,
			RequestCount:    1000,
			ErrorCount:      10,
			ResponseTime:    50 * time.Millisecond,
			BytesIn:         1024 * 1024,
			BytesOut:        2048 * 1024,
			ActiveRequests:  5,
			HealthStatus:    "healthy",
			LastHealthCheck: time.Now(),
			ErrorRate:       0.01,
		}
	}

	logger.Debug("Route metrics collected",
		zap.Int("route_count", len(metrics)))

	return metrics, nil
}

// collectSystemMetrics collects system-wide metrics
func (mc *MetricsCollector) collectSystemMetrics() (SystemMetrics, error) {
	logger := otelzap.Ctx(mc.rc.Ctx)

	// TODO: Implement actual system metrics collection
	// For now, return mock data
	metrics := SystemMetrics{
		TotalRoutes:         3,
		HealthyRoutes:       3,
		UnhealthyRoutes:     0,
		TotalRequests:       3000,
		TotalErrors:         30,
		AverageResponseTime: 50 * time.Millisecond,
		SystemLoad:          0.5,
		MemoryUsage:         0.7,
		CPUUsage:            0.3,
		DiskUsage:           0.6,
		NetworkIn:           1024 * 1024,
		NetworkOut:          2048 * 1024,
		Uptime:              24 * time.Hour,
	}

	logger.Debug("System metrics collected")
	return metrics, nil
}

// collectServiceHealth collects health status for all services
func (mc *MetricsCollector) collectServiceHealth() (map[string]ServiceHealth, error) {
	logger := otelzap.Ctx(mc.rc.Ctx)
	health := make(map[string]ServiceHealth)

	// Check Caddy health
	caddyHealth := mc.checkServiceHealth("caddy", mc.caddyURL+"/health")
	health["caddy"] = caddyHealth

	// Check Authentik health
	if mc.authentikURL != "" {
		authentikHealth := mc.checkServiceHealth("authentik", mc.authentikURL+"/api/v3/admin/version/")
		health["authentik"] = authentikHealth
	}

	// Check other services
	// TODO: Add more service health checks

	logger.Debug("Service health collected",
		zap.Int("service_count", len(health)))

	return health, nil
}

// checkServiceHealth checks the health of a specific service
func (mc *MetricsCollector) checkServiceHealth(name, url string) ServiceHealth {
	logger := otelzap.Ctx(mc.rc.Ctx)

	start := time.Now()
	client := &http.Client{Timeout: 5 * time.Second}

	req, err := http.NewRequestWithContext(mc.rc.Ctx, "GET", url, nil)
	if err != nil {
		return ServiceHealth{
			Name:         name,
			Status:       "unknown",
			ResponseTime: 0,
			LastCheck:    time.Now(),
			ErrorMessage: fmt.Sprintf("Failed to create request: %v", err),
		}
	}

	resp, err := client.Do(req)
	responseTime := time.Since(start)

	if err != nil {
		logger.Warn("Service health check failed",
			zap.String("service", name),
			zap.Error(err))

		return ServiceHealth{
			Name:         name,
			Status:       "unhealthy",
			ResponseTime: responseTime,
			LastCheck:    time.Now(),
			ErrorMessage: err.Error(),
		}
	}
	defer func() { _ = resp.Body.Close() }()

	status := "healthy"
	if resp.StatusCode >= 400 {
		status = "unhealthy"
	}

	return ServiceHealth{
		Name:         name,
		Status:       status,
		ResponseTime: responseTime,
		LastCheck:    time.Now(),
	}
}

// CheckRouteHealth checks the health of a specific route
func CheckRouteHealth(rc *eos_io.RuntimeContext, route *hecate.Route) (*hecate.RouteStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Build health check URL
	healthURL := fmt.Sprintf("https://%s", route.Domain)
	if route.HealthCheck != nil && route.HealthCheck.Path != "" {
		healthURL = fmt.Sprintf("%s%s", healthURL, route.HealthCheck.Path)
	}

	logger.Debug("Checking route health",
		zap.String("domain", route.Domain),
		zap.String("url", healthURL))

	start := time.Now()
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(rc.Ctx, "GET", healthURL, nil)
	if err != nil {
		return &hecate.RouteStatus{
			State:       hecate.RouteStateError,
			Health:      hecate.RouteHealthUnhealthy,
			LastChecked: time.Now(),
			ErrorCount:  1,
			Message:     fmt.Sprintf("Failed to create request: %v", err),
		}, nil
	}

	resp, err := client.Do(req)
	responseTime := time.Since(start)

	status := &hecate.RouteStatus{
		State:       hecate.RouteStateActive,
		Health:      hecate.RouteHealthHealthy,
		LastChecked: time.Now(),
		ErrorCount:  0,
		Message:     "",
	}

	if err != nil {
		status.State = hecate.RouteStateError
		status.Health = hecate.RouteHealthUnhealthy
		status.ErrorCount = 1
		status.Message = err.Error()
		logger.Warn("Route health check failed",
			zap.String("domain", route.Domain),
			zap.Error(err))
		return status, nil
	}
	defer func() { _ = resp.Body.Close() }()

	// Check response status
	if route.HealthCheck != nil && len(route.HealthCheck.ExpectedStatus) > 0 {
		statusOK := false
		for _, expectedStatus := range route.HealthCheck.ExpectedStatus {
			if resp.StatusCode == expectedStatus {
				statusOK = true
				break
			}
		}
		if statusOK {
			status.Health = hecate.RouteHealthHealthy
			status.State = hecate.RouteStateActive
			status.ErrorCount = 0
			status.Message = ""
		} else {
			status.Health = hecate.RouteHealthUnhealthy
			status.State = hecate.RouteStateError
			status.ErrorCount = 1
			status.Message = fmt.Sprintf("Unexpected status code: %d", resp.StatusCode)
		}
	} else {
		// Default: accept 2xx and 3xx
		isHealthy := resp.StatusCode < 400
		if isHealthy {
			status.Health = hecate.RouteHealthHealthy
			status.State = hecate.RouteStateActive
			status.ErrorCount = 0
			status.Message = ""
		} else {
			status.Health = hecate.RouteHealthUnhealthy
			status.State = hecate.RouteStateError
			status.ErrorCount = 1
			status.Message = fmt.Sprintf("HTTP error: %d", resp.StatusCode)
		}
	}

	logger.Debug("Route health check completed",
		zap.String("domain", route.Domain),
		zap.String("health", status.Health),
		zap.Duration("response_time", responseTime))

	return status, nil
}

// MonitorRoutes continuously monitors all routes
func MonitorRoutes(ctx context.Context, rc *eos_io.RuntimeContext, routes []*hecate.Route, interval time.Duration) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting route monitoring",
		zap.Int("route_count", len(routes)),
		zap.Duration("interval", interval))

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("Route monitoring stopped")
			return
		case <-ticker.C:
			for _, route := range routes {
				go func(r *hecate.Route) {
					status, err := CheckRouteHealth(rc, r)
					if err != nil {
						logger.Error("Failed to check route health",
							zap.String("domain", r.Domain),
							zap.Error(err))
						return
					}

					if status.Health != hecate.RouteHealthHealthy {
						logger.Warn("Route is unhealthy",
							zap.String("domain", r.Domain),
							zap.String("error", status.Message))

						// TODO: Trigger alerts
					}
				}(route)
			}
		}
	}
}

// CollectPrometheusMetrics exports metrics in Prometheus format
func CollectPrometheusMetrics(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Collecting Prometheus metrics")

	collector := NewMetricsCollector(rc, "http://localhost:2019", "")
	snapshot, err := collector.CollectMetrics()
	if err != nil {
		return "", fmt.Errorf("failed to collect metrics: %w", err)
	}

	// Convert to Prometheus format
	var prometheus strings.Builder

	// Write help and type information
	prometheus.WriteString("# HELP hecate_route_requests_total Total number of requests per route\n")
	prometheus.WriteString("# TYPE hecate_route_requests_total counter\n")

	for domain, metrics := range snapshot.Routes {
		prometheus.WriteString(fmt.Sprintf("hecate_route_requests_total{domain=\"%s\"} %d\n",
			domain, metrics.RequestCount))
	}

	prometheus.WriteString("# HELP hecate_route_errors_total Total number of errors per route\n")
	prometheus.WriteString("# TYPE hecate_route_errors_total counter\n")

	for domain, metrics := range snapshot.Routes {
		prometheus.WriteString(fmt.Sprintf("hecate_route_errors_total{domain=\"%s\"} %d\n",
			domain, metrics.ErrorCount))
	}

	prometheus.WriteString("# HELP hecate_route_response_time_seconds Route response time in seconds\n")
	prometheus.WriteString("# TYPE hecate_route_response_time_seconds gauge\n")

	for domain, metrics := range snapshot.Routes {
		prometheus.WriteString(fmt.Sprintf("hecate_route_response_time_seconds{domain=\"%s\"} %f\n",
			domain, metrics.ResponseTime.Seconds()))
	}

	// System metrics
	prometheus.WriteString("# HELP hecate_system_routes_total Total number of routes\n")
	prometheus.WriteString("# TYPE hecate_system_routes_total gauge\n")
	prometheus.WriteString(fmt.Sprintf("hecate_system_routes_total %d\n", snapshot.System.TotalRoutes))

	prometheus.WriteString("# HELP hecate_system_healthy_routes Total number of healthy routes\n")
	prometheus.WriteString("# TYPE hecate_system_healthy_routes gauge\n")
	prometheus.WriteString(fmt.Sprintf("hecate_system_healthy_routes %d\n", snapshot.System.HealthyRoutes))

	prometheus.WriteString("# HELP hecate_system_load System load average\n")
	prometheus.WriteString("# TYPE hecate_system_load gauge\n")
	prometheus.WriteString(fmt.Sprintf("hecate_system_load %f\n", snapshot.System.SystemLoad))

	prometheus.WriteString("# HELP hecate_system_memory_usage Memory usage percentage\n")
	prometheus.WriteString("# TYPE hecate_system_memory_usage gauge\n")
	prometheus.WriteString(fmt.Sprintf("hecate_system_memory_usage %f\n", snapshot.System.MemoryUsage))

	return prometheus.String(), nil
}
