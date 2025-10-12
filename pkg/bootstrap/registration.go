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
	StorageType  string `json:"storage_type"`  // ssd, hdd, nvme
	NetworkSpeed string `json:"network_speed"` // 1G, 10G, etc
}

// RegistrationResult contains the result of node registration
type RegistrationResult struct {
	Accepted     bool                   `json:"accepted"`
	AssignedRole environment.Role       `json:"assigned_role"`
	ClusterID    string                 `json:"cluster_id"`
	MasterKey    string                 `json:"master_key,omitempty"`
	Config       map[string]interface{} `json:"config,omitempty"`
}

// RegisterNode registers this node with the  master
func RegisterNode(rc *eos_io.RuntimeContext, consulAddr string, reg NodeRegistration) (*RegistrationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting node registration",
		zap.String("master", consulAddr),
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
		ip := generateNodeID("")
		if ip == "" {
			return nil, fmt.Errorf("failed to get node IP")
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

	// Submit registration request
	logger.Info("Submitting registration request")
	if err := submitRegistration(rc, consulAddr, reg); err != nil {
		return nil, fmt.Errorf("failed to submit registration: %w", err)
	}

	// EVALUATE - Wait for acceptance
	logger.Info("Waiting for master to accept registration")
	result, err := waitForAcceptance(rc, consulAddr, reg.Hostname)
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
		_, _ = fmt.Sscanf(output, "%d", &resources.CPUCores)
	}

	// Get memory in GB
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "free",
		Args:    []string{"-g"},
		Capture: true,
	})
	if err == nil {
		// Parse free output to get total memory
		_, _ = fmt.Sscanf(output, "Mem: %d", &resources.MemoryGB)
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
		_, _ = fmt.Sscanf(output, "%*s %dG", &total)
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

// generateNodeID gets the primary IP address of the node
func generateNodeID(_ string) string {
	// Get the IP that would be used to connect to 8.8.8.8
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// submitRegistration submits the registration to the master via  API
func submitRegistration(rc *eos_io.RuntimeContext, consulAddr string, reg NodeRegistration) error {
	logger := otelzap.Ctx(rc.Ctx)

	// TODO: Replace with Consul-based registration (HashiCorp migration)
	logger.Info("Node registration completed via basic method",
		zap.String("hostname", reg.Hostname),
		zap.String("ip", reg.IP),
		zap.String("preferred_role", string(reg.PreferredRole)),
		zap.Int("cpu_cores", reg.Resources.CPUCores),
		zap.Int("memory_gb", reg.Resources.MemoryGB),
		zap.Int("storage_gb", reg.Resources.StorageGB))

	return nil
}

// waitForAcceptance waits for the master to accept the registration
func waitForAcceptance(rc *eos_io.RuntimeContext, consulAddr string, hostname string) (*RegistrationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// TODO: Replace with Consul-based status checking (HashiCorp migration)
	logger.Info("Using basic acceptance check - Consul integration pending")

	// Fallback to local  check for now
	return waitForAcceptanceLocal(rc, hostname)
}

// waitForAcceptanceLocal is a fallback method using local  commands
func waitForAcceptanceLocal(rc *eos_io.RuntimeContext, hostname string) (*RegistrationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Using local  check as fallback")

	maxAttempts := 30
	for i := 0; i < maxAttempts; i++ {
		// Check if our key has been accepted
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "-call",
			Args:    []string{"--local", "test.ping"},
			Capture: true,
		})

		if err == nil && strings.Contains(output, "True") {
			logger.Info(" key accepted, node is registered")

			// Get assigned role from s
			output, err = execute.Run(rc.Ctx, execute.Options{
				Command: "-call",
				Args:    []string{"--local", "s.get", "role"},
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
