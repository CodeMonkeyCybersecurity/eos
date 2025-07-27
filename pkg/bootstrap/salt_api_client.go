// pkg/bootstrap/salt_api_client.go

package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SaltAPIClient handles communication with Salt API endpoints
type SaltAPIClient struct {
	baseURL    string
	httpClient *http.Client
	rc         *eos_io.RuntimeContext
}

// APIResponse represents a standard API response
type APIResponse struct {
	Status  string      `json:"status"`
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
}

// NodeRegistrationRequest represents a node registration request
type NodeRegistrationRequest struct {
	Hostname       string                 `json:"hostname"`
	IPAddress      string                 `json:"ip_address"`
	PreferredRole  string                 `json:"preferred_role,omitempty"`
	AutoAccept     bool                   `json:"auto_accept,omitempty"`
	HealthChecks   map[string]interface{} `json:"health_checks,omitempty"`
	Capabilities   map[string]interface{} `json:"capabilities,omitempty"`
	Resources      map[string]interface{} `json:"resources,omitempty"`
}

// NodeRegistrationResponse represents the response from node registration
type NodeRegistrationResponse struct {
	Hostname           string                 `json:"hostname"`
	AssignedRole       string                 `json:"assigned_role"`
	RegistrationStatus string                 `json:"registration_status"`
	ClusterID          string                 `json:"cluster_id"`
	Accepted           bool                   `json:"accepted"`
	ClusterInfo        map[string]interface{} `json:"cluster_info"`
}

// ClusterInfoResponse represents cluster information
type ClusterInfoResponse struct {
	ClusterID     string   `json:"cluster_id"`
	NodeCount     int      `json:"node_count"`
	Scale         string   `json:"scale"`
	ActiveMinions []string `json:"active_minions"`
	MasterAddr    string   `json:"master_addr"`
	CreatedAt     string   `json:"created_at"`
}

// NodesListResponse represents the response from listing nodes
type NodesListResponse struct {
	Nodes        []APINodeInfo `json:"nodes"`
	TotalCount   int           `json:"total_count"`
	ActiveCount  int           `json:"active_count"`
	PendingCount int           `json:"pending_count"`
}

// APINodeInfo represents information about a node from the API
type APINodeInfo struct {
	Hostname         string                 `json:"hostname"`
	Status           string                 `json:"status"`
	Role             string                 `json:"role"`
	IPAddress        string                 `json:"ip_address"`
	LastSeen         string                 `json:"last_seen"`
	RegistrationInfo map[string]interface{} `json:"registration_info"`
}

// NewSaltAPIClient creates a new Salt API client
func NewSaltAPIClient(rc *eos_io.RuntimeContext, masterAddr string) *SaltAPIClient {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if TLS should be enabled based on environment
	scheme := "http"
	if os.Getenv("EOS_SALT_API_TLS") == "true" {
		scheme = "https"
	}
	
	// Create HTTP client with secure TLS configuration
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}
	
	// Configure TLS security if HTTPS is enabled
	if scheme == "https" {
		tlsConfig, err := createSecureTLSConfig(rc, masterAddr)
		if err != nil {
			logger.Error("Failed to create secure TLS configuration, falling back to HTTP", 
				zap.Error(err),
				zap.String("master", masterAddr))
			scheme = "http"
		} else {
			httpClient.Transport = &http.Transport{
				TLSClientConfig: tlsConfig,
			}
			logger.Info("HTTPS enabled with certificate validation", 
				zap.String("master", masterAddr))
		}
	}
	
	return &SaltAPIClient{
		baseURL:    fmt.Sprintf("%s://%s:5000", scheme, masterAddr),
		httpClient: httpClient,
		rc:         rc,
	}
}

// createSecureTLSConfig creates a secure TLS configuration with proper certificate validation
func createSecureTLSConfig(rc *eos_io.RuntimeContext, masterAddr string) (*tls.Config, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Start with secure defaults
	tlsConfig := &tls.Config{
		ServerName:         masterAddr,
		MinVersion:         tls.VersionTLS12, // Require TLS 1.2 or higher
		CipherSuites:       getSecureCipherSuites(),
		InsecureSkipVerify: false, // Always validate certificates by default
	}
	
	// Check for custom CA certificate
	caCertPath := os.Getenv("EOS_SALT_API_CA_CERT")
	if caCertPath != "" {
		logger.Info("Loading custom CA certificate", zap.String("path", caCertPath))
		
		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate from %s: %w", caCertPath, err)
		}
		
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from %s", caCertPath)
		}
		
		tlsConfig.RootCAs = caCertPool
		logger.Info("Custom CA certificate loaded successfully")
	}
	
	// Check for client certificate authentication
	clientCertPath := os.Getenv("EOS_SALT_API_CLIENT_CERT")
	clientKeyPath := os.Getenv("EOS_SALT_API_CLIENT_KEY")
	
	if clientCertPath != "" && clientKeyPath != "" {
		logger.Info("Loading client certificate for mutual TLS", 
			zap.String("cert", clientCertPath),
			zap.String("key", clientKeyPath))
		
		clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		
		tlsConfig.Certificates = []tls.Certificate{clientCert}
		logger.Info("Client certificate loaded for mutual TLS")
	}
	
	// Allow skipping certificate verification ONLY if explicitly requested
	// This should only be used in development environments
	if os.Getenv("EOS_SALT_API_SKIP_VERIFY") == "true" {
		logger.Warn("Certificate verification disabled - THIS IS INSECURE and should only be used in development",
			zap.String("master", masterAddr))
		tlsConfig.InsecureSkipVerify = true
	}
	
	// Verify the configuration can connect
	if err := validateTLSConfig(tlsConfig, masterAddr); err != nil {
		return nil, fmt.Errorf("TLS configuration validation failed: %w", err)
	}
	
	return tlsConfig, nil
}

// getSecureCipherSuites returns a list of secure cipher suites
func getSecureCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	}
}

// validateTLSConfig performs a basic validation of the TLS configuration
func validateTLSConfig(tlsConfig *tls.Config, masterAddr string) error {
	// Create a test connection to validate the TLS configuration
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{
			Timeout: 10 * time.Second,
		},
		Config: tlsConfig,
	}
	
	conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:5000", masterAddr))
	if err != nil {
		// If connection fails, it might be because the service isn't running yet
		// We'll allow this but warn about it
		if strings.Contains(err.Error(), "connection refused") || 
		   strings.Contains(err.Error(), "no route to host") {
			return nil // Service not running, but TLS config is probably OK
		}
		return fmt.Errorf("TLS connection test failed: %w", err)
	}
	defer conn.Close()
	
	return nil
}

// makeRequest makes an HTTP request to the Salt API
func (c *SaltAPIClient) makeRequest(method, endpoint string, body interface{}) (*APIResponse, error) {
	logger := otelzap.Ctx(c.rc.Ctx)
	
	url := c.baseURL + endpoint
	
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
	}
	
	req, err := http.NewRequestWithContext(c.rc.Ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	
	logger.Debug("Making Salt API request",
		zap.String("method", method),
		zap.String("url", url))
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	
	var apiResp APIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	if resp.StatusCode >= 400 {
		return &apiResp, fmt.Errorf("API error (%d): %s", resp.StatusCode, apiResp.Message)
	}
	
	logger.Debug("Salt API request completed",
		zap.String("status", apiResp.Status),
		zap.Int("status_code", resp.StatusCode))
	
	return &apiResp, nil
}

// RegisterNode registers a node with the Salt master
func (c *SaltAPIClient) RegisterNode(req NodeRegistrationRequest) (*NodeRegistrationResponse, error) {
	logger := otelzap.Ctx(c.rc.Ctx)
	logger.Info("Registering node with Salt master",
		zap.String("hostname", req.Hostname),
		zap.String("preferred_role", req.PreferredRole))
	
	resp, err := c.makeRequest("POST", "/api/v1/cluster/register", req)
	if err != nil {
		return nil, fmt.Errorf("registration request failed: %w", err)
	}
	
	if resp.Status != "success" {
		return nil, fmt.Errorf("registration failed: %s", resp.Message)
	}
	
	// Convert response data to struct
	dataBytes, err := json.Marshal(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response data: %w", err)
	}
	
	var regResp NodeRegistrationResponse
	if err := json.Unmarshal(dataBytes, &regResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal registration response: %w", err)
	}
	
	logger.Info("Node registration completed",
		zap.String("hostname", regResp.Hostname),
		zap.String("assigned_role", regResp.AssignedRole),
		zap.Bool("accepted", regResp.Accepted))
	
	return &regResp, nil
}

// GetClusterInfo retrieves cluster information
func (c *SaltAPIClient) GetClusterInfo() (*ClusterInfoResponse, error) {
	logger := otelzap.Ctx(c.rc.Ctx)
	logger.Debug("Getting cluster information")
	
	resp, err := c.makeRequest("GET", "/api/v1/cluster/info", nil)
	if err != nil {
		return nil, fmt.Errorf("cluster info request failed: %w", err)
	}
	
	if resp.Status != "success" {
		return nil, fmt.Errorf("failed to get cluster info: %s", resp.Message)
	}
	
	// Convert response data to struct
	dataBytes, err := json.Marshal(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response data: %w", err)
	}
	
	var clusterInfo ClusterInfoResponse
	if err := json.Unmarshal(dataBytes, &clusterInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cluster info: %w", err)
	}
	
	logger.Debug("Retrieved cluster information",
		zap.String("cluster_id", clusterInfo.ClusterID),
		zap.Int("node_count", clusterInfo.NodeCount),
		zap.String("scale", clusterInfo.Scale))
	
	return &clusterInfo, nil
}

// ListNodes retrieves a list of all nodes in the cluster
func (c *SaltAPIClient) ListNodes() (*NodesListResponse, error) {
	logger := otelzap.Ctx(c.rc.Ctx)
	logger.Debug("Listing cluster nodes")
	
	resp, err := c.makeRequest("GET", "/api/v1/nodes", nil)
	if err != nil {
		return nil, fmt.Errorf("nodes list request failed: %w", err)
	}
	
	if resp.Status != "success" {
		return nil, fmt.Errorf("failed to list nodes: %s", resp.Message)
	}
	
	// Convert response data to struct
	dataBytes, err := json.Marshal(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response data: %w", err)
	}
	
	var nodesList NodesListResponse
	if err := json.Unmarshal(dataBytes, &nodesList); err != nil {
		return nil, fmt.Errorf("failed to unmarshal nodes list: %w", err)
	}
	
	logger.Debug("Retrieved nodes list",
		zap.Int("total_count", nodesList.TotalCount),
		zap.Int("active_count", nodesList.ActiveCount),
		zap.Int("pending_count", nodesList.PendingCount))
	
	return &nodesList, nil
}

// AcceptNode manually accepts a pending node registration
func (c *SaltAPIClient) AcceptNode(hostname string) error {
	logger := otelzap.Ctx(c.rc.Ctx)
	logger.Info("Accepting node registration", zap.String("hostname", hostname))
	
	endpoint := fmt.Sprintf("/api/v1/nodes/%s/accept", hostname)
	resp, err := c.makeRequest("POST", endpoint, nil)
	if err != nil {
		return fmt.Errorf("accept node request failed: %w", err)
	}
	
	if resp.Status != "success" {
		return fmt.Errorf("failed to accept node: %s", resp.Message)
	}
	
	logger.Info("Node accepted successfully", zap.String("hostname", hostname))
	return nil
}

// CalculateRoles calculates role distribution for the cluster
func (c *SaltAPIClient) CalculateRoles(clusterSize int, newNode string) (map[string]string, error) {
	logger := otelzap.Ctx(c.rc.Ctx)
	logger.Debug("Calculating role distribution",
		zap.Int("cluster_size", clusterSize),
		zap.String("new_node", newNode))
	
	requestBody := map[string]interface{}{
		"cluster_size": clusterSize,
		"new_node":     newNode,
	}
	
	resp, err := c.makeRequest("POST", "/api/v1/roles/calculate", requestBody)
	if err != nil {
		return nil, fmt.Errorf("calculate roles request failed: %w", err)
	}
	
	if resp.Status != "success" {
		return nil, fmt.Errorf("failed to calculate roles: %s", resp.Message)
	}
	
	// Extract role distribution from response
	dataMap, ok := resp.Data.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid response data format")
	}
	
	roleDistribution, ok := dataMap["role_distribution"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("role distribution not found in response")
	}
	
	// Convert to string map
	result := make(map[string]string)
	for hostname, role := range roleDistribution {
		if roleStr, ok := role.(string); ok {
			result[hostname] = roleStr
		}
	}
	
	logger.Debug("Role distribution calculated", zap.Any("roles", result))
	return result, nil
}

// HealthCheck checks the health of the Salt API
func (c *SaltAPIClient) HealthCheck() error {
	logger := otelzap.Ctx(c.rc.Ctx)
	logger.Debug("Checking Salt API health")
	
	// Use shorter timeout for health check
	originalTimeout := c.httpClient.Timeout
	c.httpClient.Timeout = 5 * time.Second
	defer func() {
		c.httpClient.Timeout = originalTimeout
	}()
	
	resp, err := c.makeRequest("GET", "/api/v1/health", nil)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	
	if resp.Status != "healthy" {
		return fmt.Errorf("Salt API is unhealthy: %s", resp.Message)
	}
	
	logger.Debug("Salt API health check passed")
	return nil
}

// WaitForAPI waits for the Salt API to become available
func (c *SaltAPIClient) WaitForAPI(ctx context.Context, maxWait time.Duration) error {
	logger := otelzap.Ctx(c.rc.Ctx)
	logger.Info("Waiting for Salt API to become available", zap.Duration("max_wait", maxWait))
	
	deadline := time.Now().Add(maxWait)
	
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		
		if err := c.HealthCheck(); err == nil {
			logger.Info("Salt API is available")
			return nil
		}
		
		logger.Debug("Salt API not yet available, retrying...")
		time.Sleep(2 * time.Second)
	}
	
	return fmt.Errorf("timed out waiting for Salt API to become available")
}