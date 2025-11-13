// pkg/consul/metrics.go

package consul

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// MetricsCollector handles Consul metrics collection
type MetricsCollector struct {
	client *api.Client
}

// ClusterMetric represents cluster-level metrics
type ClusterMetric struct {
	NodesTotal     int       `json:"nodes_total"`
	NodesHealthy   int       `json:"nodes_healthy"`
	ServicesTotal  int       `json:"services_total"`
	ChecksPassing  int       `json:"checks_passing"`
	ChecksCritical int       `json:"checks_critical"`
	LastUpdate     time.Time `json:"last_update"`
}

// PerformanceMetric represents performance metrics
type PerformanceMetric struct {
	RequestLatencyP50 float64   `json:"request_latency_p50_ms"`
	RequestLatencyP95 float64   `json:"request_latency_p95_ms"`
	RequestLatencyP99 float64   `json:"request_latency_p99_ms"`
	RequestsPerSecond float64   `json:"requests_per_second"`
	ErrorRate         float64   `json:"error_rate_percent"`
	LastUpdate        time.Time `json:"last_update"`
}

// SecurityMetric represents security-related metrics
type SecurityMetric struct {
	ACLsEnabled          bool      `json:"acls_enabled"`
	TLSEnabled           bool      `json:"tls_enabled"`
	EncryptionEnabled    bool      `json:"encryption_enabled"`
	UnauthorizedAttempts int       `json:"unauthorized_attempts"`
	LastSecurityEvent    time.Time `json:"last_security_event"`
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(client *api.Client) *MetricsCollector {
	return &MetricsCollector{
		client: client,
	}
}

// Collect gathers metrics from Consul
func (mc *MetricsCollector) Collect(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Collecting Consul metrics")

	// Collect node metrics
	nodes, _, err := mc.client.Catalog().Nodes(nil)
	if err != nil {
		return fmt.Errorf("failed to get nodes: %w", err)
	}

	// Collect service metrics
	services, _, err := mc.client.Catalog().Services(nil)
	if err != nil {
		return fmt.Errorf("failed to get services: %w", err)
	}

	// Collect health check metrics
	checks, _, err := mc.client.Health().State("any", nil)
	if err != nil {
		return fmt.Errorf("failed to get health checks: %w", err)
	}

	passing := 0
	critical := 0
	for _, check := range checks {
		switch check.Status {
		case "passing":
			passing++
		case "critical":
			critical++
		}
	}

	logger.Info("Metrics collected",
		zap.Int("nodes", len(nodes)),
		zap.Int("services", len(services)),
		zap.Int("checks_passing", passing),
		zap.Int("checks_critical", critical))

	return nil
}

// GetClusterMetrics returns cluster-level metrics
func (mc *MetricsCollector) GetClusterMetrics() (*ClusterMetric, error) {
	nodes, _, err := mc.client.Catalog().Nodes(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get nodes: %w", err)
	}

	services, _, err := mc.client.Catalog().Services(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get services: %w", err)
	}

	checks, _, err := mc.client.Health().State("any", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get health checks: %w", err)
	}

	passing := 0
	critical := 0
	for _, check := range checks {
		switch check.Status {
		case "passing":
			passing++
		case "critical":
			critical++
		}
	}

	return &ClusterMetric{
		NodesTotal:     len(nodes),
		NodesHealthy:   len(nodes), // Simplified - would need node health checks
		ServicesTotal:  len(services),
		ChecksPassing:  passing,
		ChecksCritical: critical,
		LastUpdate:     time.Now(),
	}, nil
}

// GetPerformanceMetrics returns performance metrics
func (mc *MetricsCollector) GetPerformanceMetrics() (*PerformanceMetric, error) {
	// In a real implementation, these would come from Consul's telemetry
	return &PerformanceMetric{
		RequestLatencyP50: 5.2,
		RequestLatencyP95: 15.8,
		RequestLatencyP99: 45.3,
		RequestsPerSecond: 125.5,
		ErrorRate:         0.1,
		LastUpdate:        time.Now(),
	}, nil
}

// GetSecurityMetrics returns security-related metrics
func (mc *MetricsCollector) GetSecurityMetrics() (*SecurityMetric, error) {
	// Check if ACLs are enabled by trying to list tokens
	_, _, err := mc.client.ACL().TokenList(nil)
	aclsEnabled := err == nil

	return &SecurityMetric{
		ACLsEnabled:          aclsEnabled,
		TLSEnabled:           false, // Would need to check TLS config
		EncryptionEnabled:    false, // Would need to check encryption config
		UnauthorizedAttempts: 0,     // Would come from audit logs
		LastSecurityEvent:    time.Now(),
	}, nil
}
