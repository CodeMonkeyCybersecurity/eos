// pkg/environment/detector.go

package environment

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Environment represents the detected infrastructure environment
type Environment struct {
	MachineCount int
	Machines     []Machine
	MyRole       Role
	MyHostname   string
}

// Machine represents a single machine in the infrastructure
type Machine struct {
	Hostname string
	IP       string
	Role     Role
}

// Role represents the functional role of a machine
type Role string

const (
	RoleMonolith Role = "monolith"
	RoleEdge     Role = "edge"
	RoleCore     Role = "core"
	RoleApp      Role = "app"
	RoleData     Role = "data"
	RoleMessage  Role = "message"
	RoleObserve  Role = "observe"
	RoleCompute  Role = "compute"
)

// Detect discovers the environment configuration using Salt
func Detect(rc *eos_io.RuntimeContext) (*Environment, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Detecting environment configuration")

	// ASSESS - Check if Salt is available
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"salt-call"},
		Capture: true,
	}); err != nil {
		logger.Warn("Salt not available, falling back to single machine mode")
		return detectSingleMachine()
	}

	// INTERVENE - Use Salt to detect environment
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"--local", "publish.publish", "*", "test.ping", "--out=json"},
		Capture: true,
	})
	if err != nil {
		logger.Warn("Failed to use Salt for detection, falling back to single machine mode",
			zap.Error(err))
		return detectSingleMachine()
	}

	// Parse Salt output
	machines, err := parseSaltOutput(output)
	if err != nil {
		logger.Warn("Failed to parse Salt output, falling back to single machine mode",
			zap.Error(err))
		return detectSingleMachine()
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname: %w", err)
	}

	env := &Environment{
		MachineCount: len(machines),
		Machines:     machines,
		MyHostname:   hostname,
	}

	// EVALUATE - Determine roles based on machine count and hostname
	if err := env.assignRoles(); err != nil {
		return nil, fmt.Errorf("failed to assign roles: %w", err)
	}

	logger.Info("Environment detection completed",
		zap.Int("machine_count", env.MachineCount),
		zap.String("my_role", string(env.MyRole)),
		zap.String("hostname", env.MyHostname))

	return env, nil
}

// detectSingleMachine returns environment for a single machine setup
func detectSingleMachine() (*Environment, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname: %w", err)
	}

	return &Environment{
		MachineCount: 1,
		Machines: []Machine{
			{
				Hostname: hostname,
				IP:       "127.0.0.1",
				Role:     RoleMonolith,
			},
		},
		MyRole:     RoleMonolith,
		MyHostname: hostname,
	}, nil
}

// parseSaltOutput parses the JSON output from Salt
func parseSaltOutput(output string) ([]Machine, error) {
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Extract machines from Salt response
	var machines []Machine
	if local, ok := result["local"].(map[string]interface{}); ok {
		for hostname := range local {
			if hostname != "_stamp" { // Skip metadata fields
				machines = append(machines, Machine{
					Hostname: hostname,
					// IP and Role will be determined later
				})
			}
		}
	}

	return machines, nil
}

// assignRoles determines the role of each machine based on count and naming
func (e *Environment) assignRoles() error {
	switch e.MachineCount {
	case 1:
		// Single machine - everything runs here
		e.MyRole = RoleMonolith
		if len(e.Machines) > 0 {
			e.Machines[0].Role = RoleMonolith
		}

	case 2:
		// Two machines - edge and core
		for i := range e.Machines {
			if strings.HasSuffix(e.Machines[i].Hostname, "1") ||
				strings.Contains(e.Machines[i].Hostname, "edge") {
				e.Machines[i].Role = RoleEdge
			} else {
				e.Machines[i].Role = RoleCore
			}
			
			if e.Machines[i].Hostname == e.MyHostname {
				e.MyRole = e.Machines[i].Role
			}
		}

	case 3:
		// Three machines - edge, core, and data
		for i := range e.Machines {
			hostname := e.Machines[i].Hostname
			if strings.HasSuffix(hostname, "1") || strings.Contains(hostname, "edge") {
				e.Machines[i].Role = RoleEdge
			} else if strings.HasSuffix(hostname, "2") || strings.Contains(hostname, "core") {
				e.Machines[i].Role = RoleCore
			} else {
				e.Machines[i].Role = RoleData
			}
			
			if hostname == e.MyHostname {
				e.MyRole = e.Machines[i].Role
			}
		}

	default:
		// 4+ machines - more complex role assignment
		// This would typically be read from configuration or determined
		// by more sophisticated logic
		return e.assignComplexRoles()
	}

	return nil
}

// assignComplexRoles handles role assignment for larger deployments
func (e *Environment) assignComplexRoles() error {
	// For now, use a simple naming convention
	// In production, this would read from Salt grains or configuration
	for i := range e.Machines {
		hostname := e.Machines[i].Hostname
		
		switch {
		case strings.Contains(hostname, "edge"):
			e.Machines[i].Role = RoleEdge
		case strings.Contains(hostname, "core"):
			e.Machines[i].Role = RoleCore
		case strings.Contains(hostname, "data"):
			e.Machines[i].Role = RoleData
		case strings.Contains(hostname, "msg") || strings.Contains(hostname, "message"):
			e.Machines[i].Role = RoleMessage
		case strings.Contains(hostname, "observe") || strings.Contains(hostname, "monitor"):
			e.Machines[i].Role = RoleObserve
		case strings.Contains(hostname, "compute"):
			e.Machines[i].Role = RoleCompute
		case strings.Contains(hostname, "app"):
			e.Machines[i].Role = RoleApp
		default:
			// Default to app role for unmatched machines
			e.Machines[i].Role = RoleApp
		}
		
		if hostname == e.MyHostname {
			e.MyRole = e.Machines[i].Role
		}
	}

	return nil
}

// GetRoleDescription returns a human-readable description of a role
func GetRoleDescription(role Role) string {
	descriptions := map[Role]string{
		RoleMonolith: "All-in-one server (monolithic deployment)",
		RoleEdge:     "Edge server (ingress, load balancing, caching)",
		RoleCore:     "Core services (API, business logic)",
		RoleApp:      "Application server (web apps, microservices)",
		RoleData:     "Data server (databases, storage)",
		RoleMessage:  "Message broker (queues, events)",
		RoleObserve:  "Observability (monitoring, logging, metrics)",
		RoleCompute:  "Compute node (batch processing, workers)",
	}
	
	if desc, ok := descriptions[role]; ok {
		return desc
	}
	return "Unknown role"
}