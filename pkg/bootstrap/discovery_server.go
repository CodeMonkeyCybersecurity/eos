// pkg/bootstrap/discovery_server.go

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DiscoveryServer handles multicast discovery for Salt masters
type DiscoveryServer struct {
	rc         *eos_io.RuntimeContext
	conn       *net.UDPConn
	clusterID  string
	masterAddr string
}

// DiscoveryResponse is sent in response to discovery requests
type DiscoveryResponse struct {
	ClusterID  string `json:"cluster_id"`
	MasterAddr string `json:"master_addr"`
	NodeCount  int    `json:"node_count"`
	Version    string `json:"version"`
}

// NewDiscoveryServer creates a new discovery server
func NewDiscoveryServer(rc *eos_io.RuntimeContext, clusterID, masterAddr string) *DiscoveryServer {
	return &DiscoveryServer{
		rc:         rc,
		clusterID:  clusterID,
		masterAddr: masterAddr,
	}
}

// Start begins listening for discovery requests
func (d *DiscoveryServer) Start(ctx context.Context) error {
	logger := otelzap.Ctx(d.rc.Ctx)
	logger.Info("Starting discovery server",
		zap.String("cluster_id", d.clusterID),
		zap.String("master_addr", d.masterAddr))

	// Setup multicast listener
	addr, err := net.ResolveUDPAddr("udp", "224.0.0.1:4505")
	if err != nil {
		return fmt.Errorf("failed to resolve multicast address: %w", err)
	}

	conn, err := net.ListenMulticastUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("failed to listen on multicast: %w", err)
	}
	d.conn = conn
	defer conn.Close()

	// Set read buffer
	conn.SetReadBuffer(1024)

	// Listen for discovery requests
	buffer := make([]byte, 1024)
	for {
		select {
		case <-ctx.Done():
			logger.Info("Discovery server stopping")
			return ctx.Err()
		default:
			// Set read deadline to allow checking context
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			
			n, clientAddr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				// Timeout is expected, continue
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				logger.Warn("Error reading discovery request", zap.Error(err))
				continue
			}

			// Check if this is a valid discovery request
			if string(buffer[:n]) == "EOS_CLUSTER_DISCOVERY_v1" {
				logger.Info("Received discovery request",
					zap.String("from", clientAddr.String()))
				
				// Send response
				if err := d.sendResponse(clientAddr); err != nil {
					logger.Error("Failed to send discovery response",
						zap.String("to", clientAddr.String()),
						zap.Error(err))
				}
			}
		}
	}
}

// sendResponse sends a discovery response to the client
func (d *DiscoveryServer) sendResponse(clientAddr *net.UDPAddr) error {
	logger := otelzap.Ctx(d.rc.Ctx)
	
	// Get current node count
	nodeCount := d.getNodeCount()
	
	response := DiscoveryResponse{
		ClusterID:  d.clusterID,
		MasterAddr: d.masterAddr,
		NodeCount:  nodeCount,
		Version:    "1.0",
	}

	data, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	// Send response directly to client
	conn, err := net.DialUDP("udp", nil, clientAddr)
	if err != nil {
		return fmt.Errorf("failed to create response connection: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write(data)
	if err != nil {
		return fmt.Errorf("failed to send response: %w", err)
	}

	logger.Debug("Sent discovery response",
		zap.String("to", clientAddr.String()),
		zap.Int("node_count", nodeCount))

	return nil
}

// getNodeCount returns the current number of nodes in the cluster
func (d *DiscoveryServer) getNodeCount() int {
	logger := otelzap.Ctx(d.rc.Ctx)
	
	// Query Salt for accepted minions
	output, err := execute.Run(d.rc.Ctx, execute.Options{
		Command: "salt",
		Args:    []string{"--out=json", "'*'", "test.ping"},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	
	if err != nil {
		logger.Warn("Failed to get node count", zap.Error(err))
		return 1 // Assume at least this node
	}

	// Parse JSON output to count responding nodes
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		logger.Warn("Failed to parse Salt output", zap.Error(err))
		return 1
	}

	return len(result)
}

// StartDiscoveryService starts the discovery service as a background service
func StartDiscoveryService(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Get cluster configuration
	clusterID := "eos-cluster-001" // Default, would be from config
	
	// Get master address
	masterAddr, err := getLocalIP()
	if err != nil {
		logger.Warn("Failed to get local IP, using localhost", zap.Error(err))
		masterAddr = "localhost"
	}

	// Create systemd service for discovery
	serviceContent := fmt.Sprintf(`[Unit]
Description=EOS Cluster Discovery Service
After=network.target salt-master.service

[Service]
Type=simple
ExecStart=/usr/local/bin/eos-discovery-server --cluster-id=%s --master=%s
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
`, clusterID, masterAddr)

	servicePath := "/etc/systemd/system/eos-discovery.service"
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}

	// Reload systemd
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"daemon-reload"},
		Capture: false,
	}); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	// Enable and start service
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"enable", "--now", "eos-discovery.service"},
		Capture: false,
	}); err != nil {
		logger.Warn("Failed to start discovery service", zap.Error(err))
	}

	logger.Info("Discovery service configured")
	return nil
}

// getLocalIP returns the primary local IP address
func getLocalIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}