// pkg/bootstrap/registration.go

package bootstrap

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NodeRegistration contains information for registering a node
type NodeRegistration struct {
	Hostname      string       `json:"hostname"`
	IP            string       `json:"ip"`
	Resources     ResourceInfo `json:"resources"`
	PreferredRole string       `json:"preferred_role,omitempty"`
	Timestamp     time.Time    `json:"timestamp"`
}

// ResourceInfo contains node resource information
type ResourceInfo struct {
	CPUCores     int    `json:"cpu_cores"`
	MemoryGB     int    `json:"memory_gb"`
	StorageGB    int    `json:"storage_gb"`
	StorageType  string `json:"storage_type"` // ssd, hdd, nvme
	NetworkSpeed string `json:"network_speed"` // 1G, 10G, etc
}

// RegistrationResult contains the result of node registration
type RegistrationResult struct {
	Accepted     bool             `json:"accepted"`
	AssignedRole environment.Role `json:"assigned_role"`
	ClusterID    string           `json:"cluster_id"`
	MasterKey    string           `json:"master_key,omitempty"`
	Config       map[string]interface{} `json:"config,omitempty"`
}

// RegisterNode registers this node with the Salt master
func RegisterNode(rc *eos_io.RuntimeContext, masterAddr string, reg NodeRegistration) (*RegistrationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting node registration",
		zap.String("master", masterAddr),
		zap.String("hostname", reg.Hostname))

	// ASSESS - Gather node information if not provided
	if reg.Hostname == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("failed to get hostname: %w", err)
		}
		reg.Hostname = hostname
	}

	if reg.IP == "" {
		ip, err := getNodeIP()
		if err != nil {
			return nil, fmt.Errorf("failed to get node IP: %w", err)
		}
		reg.IP = ip
	}

	if reg.Resources.CPUCores == 0 {
		resources, err := gatherResources(rc)
		if err != nil {
			logger.Warn("Failed to gather resources, using defaults", zap.Error(err))
			reg.Resources = ResourceInfo{
				CPUCores:  4,
				MemoryGB:  8,
				StorageGB: 100,
			}
		} else {
			reg.Resources = *resources
		}
	}

	reg.Timestamp = time.Now()

	// INTERVENE - Register with master
	// First, configure Salt minion to point to master
	logger.Info("Configuring Salt minion for master",
		zap.String("master", masterAddr))

	if err := configureSaltMinion(rc, masterAddr); err != nil {
		return nil, fmt.Errorf("failed to configure Salt minion: %w", err)
	}

	// Start Salt minion
	if err := startSaltMinion(rc); err != nil {
		return nil, fmt.Errorf("failed to start Salt minion: %w", err)
	}

	// Submit registration request
	logger.Info("Submitting registration request")
	if err := submitRegistration(rc, masterAddr, reg); err != nil {
		return nil, fmt.Errorf("failed to submit registration: %w", err)
	}

	// EVALUATE - Wait for acceptance
	logger.Info("Waiting for master to accept registration")
	result, err := waitForAcceptance(rc, masterAddr, reg.Hostname)
	if err != nil {
		return nil, fmt.Errorf("registration not accepted: %w", err)
	}

	logger.Info("Node registration successful",
		zap.String("role", string(result.AssignedRole)),
		zap.String("cluster_id", result.ClusterID))

	return result, nil
}

// gatherResources collects system resource information
func gatherResources(rc *eos_io.RuntimeContext) (*ResourceInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Gathering system resources")

	resources := &ResourceInfo{}

	// Get CPU cores
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "nproc",
		Capture: true,
	})
	if err == nil {
		fmt.Sscanf(output, "%d", &resources.CPUCores)
	}

	// Get memory in GB
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "free",
		Args:    []string{"-g"},
		Capture: true,
	})
	if err == nil {
		// Parse free output to get total memory
		fmt.Sscanf(output, "Mem: %d", &resources.MemoryGB)
	}

	// Get storage capacity
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "df",
		Args:    []string{"-BG", "/"},
		Capture: true,
	})
	if err == nil {
		// Parse df output
		var total int
		fmt.Sscanf(output, "%*s %dG", &total)
		resources.StorageGB = total
	}

	// Detect storage type (simplified)
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "lsblk",
		Args:    []string{"-d", "-o", "name,rota"},
		Capture: true,
	})
	if err == nil {
		if strings.Contains(output, " 0") {
			resources.StorageType = "ssd"
		} else {
			resources.StorageType = "hdd"
		}
	}

	// Detect network speed (simplified)
	resources.NetworkSpeed = "1G" // Default, would need ethtool for actual speed

	logger.Debug("Resources gathered",
		zap.Int("cpu_cores", resources.CPUCores),
		zap.Int("memory_gb", resources.MemoryGB),
		zap.Int("storage_gb", resources.StorageGB))

	return resources, nil
}

// getNodeIP gets the primary IP address of the node
func getNodeIP() (string, error) {
	// Get the IP that would be used to connect to 8.8.8.8
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

// configureSaltMinion configures the Salt minion to connect to master
func configureSaltMinion(rc *eos_io.RuntimeContext, masterAddr string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	minionConfig := fmt.Sprintf(`master: %s
id: %s
startup_states: highstate
`, masterAddr, hostname)

	configPath := "/etc/salt/minion"
	if err := os.WriteFile(configPath, []byte(minionConfig), 0644); err != nil {
		return fmt.Errorf("failed to write minion config: %w", err)
	}

	logger.Debug("Salt minion configured", zap.String("master", masterAddr))
	return nil
}

// startSaltMinion starts the Salt minion service
func startSaltMinion(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Stop if already running
	execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"stop", "salt-minion"},
		Capture: false,
	})

	// Start minion
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"start", "salt-minion"},
		Capture: false,
	}); err != nil {
		return fmt.Errorf("failed to start salt-minion: %w", err)
	}

	// Enable for auto-start
	execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"enable", "salt-minion"},
		Capture: false,
	})

	logger.Info("Salt minion started")
	return nil
}

// submitRegistration submits the registration to the master via Salt API
func submitRegistration(rc *eos_io.RuntimeContext, masterAddr string, reg NodeRegistration) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Create Salt API client
	apiClient := NewSaltAPIClient(rc, masterAddr)
	
	// Convert resources to capabilities map
	capabilities := map[string]interface{}{
		"cpu_cores":     reg.Resources.CPUCores,
		"memory_gb":     reg.Resources.MemoryGB,
		"storage_gb":    reg.Resources.StorageGB,
		"storage_type":  reg.Resources.StorageType,
		"network_speed": reg.Resources.NetworkSpeed,
	}
	
	// Build registration request
	apiReq := NodeRegistrationRequest{
		Hostname:      reg.Hostname,
		IPAddress:     reg.IP,
		PreferredRole: reg.PreferredRole,
		AutoAccept:    false, // Manual acceptance for security
		Capabilities:  capabilities,
		Resources:     capabilities, // Same data for now
	}
	
	// Submit registration
	resp, err := apiClient.RegisterNode(apiReq)
	if err != nil {
		return fmt.Errorf("API registration failed: %w", err)
	}
	
	logger.Debug("Registration submitted via API",
		zap.String("assigned_role", resp.AssignedRole),
		zap.Bool("accepted", resp.Accepted))
	return nil
}

// waitForAcceptance waits for the master to accept the registration
func waitForAcceptance(rc *eos_io.RuntimeContext, masterAddr string, hostname string) (*RegistrationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Create Salt API client for checking status
	apiClient := NewSaltAPIClient(rc, masterAddr)
	
	// Wait for acceptance
	maxAttempts := 30
	for i := 0; i < maxAttempts; i++ {
		// Check registration status via API
		nodesList, err := apiClient.ListNodes()
		if err != nil {
			logger.Warn("Failed to check registration status via API", zap.Error(err))
			// Fall back to local Salt check
			return waitForAcceptanceLocal(rc, hostname)
		}
		
		// Find our node in the list
		for _, apiNode := range nodesList.Nodes {
			if apiNode.Hostname == hostname {
				if apiNode.Status == "active" {
					logger.Info("Node registration accepted",
						zap.String("hostname", hostname),
						zap.String("role", apiNode.Role))
					
					// Get cluster info
					clusterInfo, err := apiClient.GetClusterInfo()
					clusterID := "eos-cluster-001" // Default
					if err == nil {
						clusterID = clusterInfo.ClusterID
					}
					
					return &RegistrationResult{
						Accepted:     true,
						AssignedRole: environment.Role(apiNode.Role),
						ClusterID:    clusterID,
					}, nil
				} else if apiNode.Status == "pending" {
					logger.Debug("Registration pending approval",
						zap.String("hostname", hostname))
					break
				}
			}
		}
		
		logger.Debug("Waiting for registration acceptance",
			zap.Int("attempt", i+1),
			zap.Int("max_attempts", maxAttempts))
		
		time.Sleep(2 * time.Second)
	}
	
	return nil, fmt.Errorf("registration timeout - not accepted within %d attempts", maxAttempts)
}

// waitForAcceptanceLocal is a fallback method using local Salt commands
func waitForAcceptanceLocal(rc *eos_io.RuntimeContext, hostname string) (*RegistrationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Using local Salt check as fallback")
	
	maxAttempts := 30
	for i := 0; i < maxAttempts; i++ {
		// Check if our key has been accepted
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "salt-call",
			Args:    []string{"--local", "test.ping"},
			Capture: true,
		})
		
		if err == nil && strings.Contains(output, "True") {
			logger.Info("Salt key accepted, node is registered")
			
			// Get assigned role from grains
			output, err = execute.Run(rc.Ctx, execute.Options{
				Command: "salt-call",
				Args:    []string{"--local", "grains.get", "role"},
				Capture: true,
			})
			
			role := environment.RoleApp // Default
			if err == nil && strings.Contains(output, ":") {
				// Parse role from output
				parts := strings.Split(output, ":")
				if len(parts) > 1 {
					roleName := strings.TrimSpace(parts[1])
					role = environment.Role(roleName)
				}
			}
			
			return &RegistrationResult{
				Accepted:     true,
				AssignedRole: role,
				ClusterID:    "eos-cluster-001", // Default
			}, nil
		}
		
		logger.Debug("Waiting for key acceptance (local check)",
			zap.Int("attempt", i+1),
			zap.Int("max_attempts", maxAttempts))
		
		time.Sleep(2 * time.Second)
	}
	
	return nil, fmt.Errorf("registration timeout - key not accepted")
}

// hostname is used for minion ID
var hostname string

func init() {
	h, _ := os.Hostname()
	hostname = h
}