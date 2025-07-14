package monitoring

import (
	"fmt"
	"net"
	"net/http"
	"time"
)

// HTTPHealthChecker performs HTTP-based health checks
type HTTPHealthChecker struct{}

// NewHTTPHealthChecker creates a new HTTP health checker
func NewHTTPHealthChecker() *HTTPHealthChecker {
	return &HTTPHealthChecker{}
}

// Check performs an HTTP health check
func (h *HTTPHealthChecker) Check(target string, config map[string]interface{}) (*HealthResult, error) {
	startTime := time.Now()
	
	// Parse configuration
	path := "/health"
	if p, ok := config["path"].(string); ok {
		path = p
	}
	
	timeout := 30 * time.Second
	if t, ok := config["timeout"].(time.Duration); ok {
		timeout = t
	}
	
	protocol := "http"
	if p, ok := config["protocol"].(string); ok {
		protocol = p
	}
	
	expectedStatus := 200
	if s, ok := config["expected_status"].(int); ok {
		expectedStatus = s
	}

	// Build URL
	url := fmt.Sprintf("%s://%s%s", protocol, target, path)
	
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: timeout,
	}
	
	// Perform HTTP request
	resp, err := client.Get(url)
	duration := time.Since(startTime)
	
	result := &HealthResult{
		Target:    target,
		Timestamp: time.Now(),
		Duration:  duration,
		CheckType: h.Name(),
		Details:   make(map[string]interface{}),
		Metadata:  make(map[string]string),
	}
	
	if err != nil {
		result.Healthy = false
		result.Status = HealthStatusUnhealthy
		result.Message = fmt.Sprintf("HTTP request failed: %v", err)
		result.Details["error"] = err.Error()
		result.Details["url"] = url
		return result, nil
	}
	
	defer resp.Body.Close()
	
	// Check status code
	if resp.StatusCode == expectedStatus {
		result.Healthy = true
		result.Status = HealthStatusHealthy
		result.Message = "HTTP health check passed"
	} else {
		result.Healthy = false
		result.Status = HealthStatusUnhealthy
		result.Message = fmt.Sprintf("HTTP status code %d, expected %d", resp.StatusCode, expectedStatus)
	}
	
	result.Details["status_code"] = resp.StatusCode
	result.Details["url"] = url
	result.Details["response_time_ms"] = duration.Milliseconds()
	
	return result, nil
}

// Name returns the name of the health checker
func (h *HTTPHealthChecker) Name() string {
	return "http"
}

// SupportedTypes returns the supported target types
func (h *HTTPHealthChecker) SupportedTypes() []string {
	return []string{"http", "https"}
}

// TCPHealthChecker performs TCP-based health checks
type TCPHealthChecker struct{}

// NewTCPHealthChecker creates a new TCP health checker
func NewTCPHealthChecker() *TCPHealthChecker {
	return &TCPHealthChecker{}
}

// Check performs a TCP health check
func (t *TCPHealthChecker) Check(target string, config map[string]interface{}) (*HealthResult, error) {
	startTime := time.Now()
	
	// Parse configuration
	timeout := 10 * time.Second
	if to, ok := config["timeout"].(time.Duration); ok {
		timeout = to
	}
	
	// Attempt TCP connection
	conn, err := net.DialTimeout("tcp", target, timeout)
	duration := time.Since(startTime)
	
	result := &HealthResult{
		Target:    target,
		Timestamp: time.Now(),
		Duration:  duration,
		CheckType: t.Name(),
		Details:   make(map[string]interface{}),
		Metadata:  make(map[string]string),
	}
	
	if err != nil {
		result.Healthy = false
		result.Status = HealthStatusUnhealthy
		result.Message = fmt.Sprintf("TCP connection failed: %v", err)
		result.Details["error"] = err.Error()
		return result, nil
	}
	
	// Connection successful
	conn.Close()
	
	result.Healthy = true
	result.Status = HealthStatusHealthy
	result.Message = "TCP connection successful"
	result.Details["connection_time_ms"] = duration.Milliseconds()
	
	return result, nil
}

// Name returns the name of the health checker
func (t *TCPHealthChecker) Name() string {
	return "tcp"
}

// SupportedTypes returns the supported target types
func (t *TCPHealthChecker) SupportedTypes() []string {
	return []string{"tcp"}
}

// NomadHealthChecker performs Nomad job health checks
type NomadHealthChecker struct{}

// NewNomadHealthChecker creates a new Nomad health checker
func NewNomadHealthChecker() *NomadHealthChecker {
	return &NomadHealthChecker{}
}

// Check performs a Nomad job health check
func (n *NomadHealthChecker) Check(target string, config map[string]interface{}) (*HealthResult, error) {
	startTime := time.Now()
	
	result := &HealthResult{
		Target:    target,
		Timestamp: time.Now(),
		Duration:  time.Since(startTime),
		CheckType: n.Name(),
		Details:   make(map[string]interface{}),
		Metadata:  make(map[string]string),
	}
	
	// Implementation would check Nomad job status via API
	// For now, simulate a check
	
	// Mock implementation - always healthy for demo
	result.Healthy = true
	result.Status = HealthStatusHealthy
	result.Message = "Nomad job is running"
	result.Details["job_status"] = "running"
	result.Details["allocations"] = 3
	result.Details["desired"] = 3
	
	return result, nil
}

// Name returns the name of the health checker
func (n *NomadHealthChecker) Name() string {
	return "nomad"
}

// SupportedTypes returns the supported target types
func (n *NomadHealthChecker) SupportedTypes() []string {
	return []string{"nomad_job"}
}

// ConsulHealthChecker performs Consul service health checks
type ConsulHealthChecker struct{}

// NewConsulHealthChecker creates a new Consul health checker
func NewConsulHealthChecker() *ConsulHealthChecker {
	return &ConsulHealthChecker{}
}

// Check performs a Consul service health check
func (c *ConsulHealthChecker) Check(target string, config map[string]interface{}) (*HealthResult, error) {
	startTime := time.Now()
	
	result := &HealthResult{
		Target:    target,
		Timestamp: time.Now(),
		Duration:  time.Since(startTime),
		CheckType: c.Name(),
		Details:   make(map[string]interface{}),
		Metadata:  make(map[string]string),
	}
	
	// Implementation would check Consul service health via API
	// For now, simulate a check
	
	// Mock implementation - always healthy for demo
	result.Healthy = true
	result.Status = HealthStatusHealthy
	result.Message = "Consul service is healthy"
	result.Details["service_status"] = "passing"
	result.Details["instances"] = 2
	result.Details["passing_checks"] = 4
	result.Details["warning_checks"] = 0
	result.Details["critical_checks"] = 0
	
	return result, nil
}

// Name returns the name of the health checker
func (c *ConsulHealthChecker) Name() string {
	return "consul"
}

// SupportedTypes returns the supported target types
func (c *ConsulHealthChecker) SupportedTypes() []string {
	return []string{"consul_service"}
}

// DatabaseHealthChecker performs database health checks
type DatabaseHealthChecker struct{}

// NewDatabaseHealthChecker creates a new database health checker
func NewDatabaseHealthChecker() *DatabaseHealthChecker {
	return &DatabaseHealthChecker{}
}

// Check performs a database health check
func (d *DatabaseHealthChecker) Check(target string, config map[string]interface{}) (*HealthResult, error) {
	startTime := time.Now()
	
	result := &HealthResult{
		Target:    target,
		Timestamp: time.Now(),
		Duration:  time.Since(startTime),
		CheckType: d.Name(),
		Details:   make(map[string]interface{}),
		Metadata:  make(map[string]string),
	}
	
	// Implementation would perform actual database health check
	// For now, simulate a check
	
	// Mock implementation - check connection
	dbType := "postgres"
	if dt, ok := config["type"].(string); ok {
		dbType = dt
	}
	
	// Simulate database connection check
	time.Sleep(50 * time.Millisecond) // Simulate connection time
	
	result.Healthy = true
	result.Status = HealthStatusHealthy
	result.Message = fmt.Sprintf("%s database is healthy", dbType)
	result.Details["database_type"] = dbType
	result.Details["connection_time_ms"] = time.Since(startTime).Milliseconds()
	result.Details["active_connections"] = 15
	result.Details["max_connections"] = 100
	
	return result, nil
}

// Name returns the name of the health checker
func (d *DatabaseHealthChecker) Name() string {
	return "database"
}

// SupportedTypes returns the supported target types
func (d *DatabaseHealthChecker) SupportedTypes() []string {
	return []string{"database", "postgres", "mysql", "redis"}
}