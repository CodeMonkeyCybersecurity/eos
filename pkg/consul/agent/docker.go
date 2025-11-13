// pkg/consul/agent/docker.go
//
// Docker Compose sidecar generation for Consul agents.
//
// Last Updated: 2025-01-24

package agent

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GenerateDockerComposeSidecar creates a Docker Compose service definition for Consul agent.
//
// This generates a sidecar container that can be added to an existing docker-compose.yml.
// The sidecar runs alongside the main service and provides Consul agent functionality.
//
// Network mode is set to "host" to allow Consul's gossip protocol to function correctly.
//
// Parameters:
//   - rc: RuntimeContext for logging
//   - config: Agent configuration
//
// Returns:
//   - map[string]interface{}: Docker Compose service definition
//   - error: Any generation error
//
// Example output:
//
//	{
//	  "image": "hashicorp/consul:1.19.2",
//	  "container_name": "my-service-consul-agent",
//	  "network_mode": "host",
//	  "restart": "unless-stopped",
//	  "volumes": [
//	    "/etc/consul.d/agent.hcl:/consul/config/agent.hcl:ro",
//	    "consul-agent-data:/consul/data"
//	  ],
//	  "command": "agent -config-file=/consul/config/agent.hcl",
//	  "healthcheck": {
//	    "test": ["CMD", "consul", "members"],
//	    "interval": "10s",
//	    "timeout": "5s",
//	    "retries": 3
//	  }
//	}
func GenerateDockerComposeSidecar(rc *eos_io.RuntimeContext, config AgentConfig) (map[string]interface{}, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Generating Docker Compose sidecar for Consul agent",
		zap.String("node_name", config.NodeName))

	// Validate required fields
	if config.NodeName == "" {
		return nil, fmt.Errorf("node_name is required")
	}

	// Determine container name
	containerName := fmt.Sprintf("%s-consul-agent", config.NodeName)

	// Determine image
	image := fmt.Sprintf("hashicorp/consul:%s", consul.ConsulDefaultVersion)

	// Build service definition
	service := map[string]interface{}{
		"image":          image,
		"container_name": containerName,
		"network_mode":   "host", // Required for Consul gossip protocol
		"restart":        "unless-stopped",
		"volumes": []string{
			fmt.Sprintf("%s:/consul/config/agent.hcl:ro", consul.ConsulConfigFile),
			"consul-agent-data:/consul/data",
		},
		"command": "agent -config-file=/consul/config/agent.hcl",
		"healthcheck": map[string]interface{}{
			"test":     []string{"CMD", "consul", "members"},
			"interval": "10s",
			"timeout":  "5s",
			"retries":  3,
		},
		"environment": []string{
			"CONSUL_HTTP_ADDR=http://localhost:8500",
		},
	}

	logger.Info("Docker Compose sidecar generated",
		zap.String("container_name", containerName),
		zap.String("image", image))

	return service, nil
}

// AddConsulSidecarToCompose adds a Consul agent sidecar to an existing docker-compose.yml.
//
// This function:
//  1. Reads the existing docker-compose.yml
//  2. Generates the Consul agent sidecar service
//  3. Merges it into the services section
//  4. Writes the updated compose file back to disk
//
// Parameters:
//   - rc: RuntimeContext
//   - composeFilePath: Path to docker-compose.yml
//   - config: Agent configuration
//
// Returns:
//   - error: Any file I/O or generation error
//
// Example:
//
//	config := agent.AgentConfig{
//	    NodeName:   "hecate",
//	    Datacenter: "dc1",
//	    RetryJoin:  []string{"10.0.1.10:8301"},
//	}
//	err := agent.AddConsulSidecarToCompose(rc, "/opt/hecate/docker-compose.yml", config)
func AddConsulSidecarToCompose(rc *eos_io.RuntimeContext, composeFilePath string, config AgentConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Adding Consul sidecar to docker-compose.yml",
		zap.String("compose_file", composeFilePath),
		zap.String("node_name", config.NodeName))

	// TODO: Implement compose file modification
	// 1. Read existing compose file (YAML)
	// 2. Generate sidecar service
	// 3. Add to services section
	// 4. Add volume definition
	// 5. Write back to disk

	return fmt.Errorf("not yet implemented - will be completed in next iteration")
}
