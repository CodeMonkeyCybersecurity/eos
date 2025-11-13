//go:build linux

// pkg/consul/service_definitions.go
//
// Service definition file generation for Docker containers.
//
// This implements HashiCorp's recommended pattern for Docker + Consul:
// - Host-based Consul client agent
// - Service definition files in /etc/consul.d/
// - Health checks using docker exec pattern
//
// Last Updated: 2025-01-24

package consul

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	dockercontainer "github.com/docker/docker/api/types/container"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ServiceInfo holds extracted service metadata from a container.
type ServiceInfo struct {
	ID             string            // Service ID (e.g., "hecate-caddy")
	Name           string            // Service name (e.g., "caddy")
	Port           int               // Primary service port
	Address        string            // Service address (default: localhost)
	Tags           []string          // Service tags
	HealthEndpoint string            // Health check endpoint
	HealthType     string            // Health check type (http, tcp, script)
	HealthInterval string            // Health check interval (default: 10s)
	HealthTimeout  string            // Health check timeout (default: 2s)
	Meta           map[string]string // Service metadata
	ContainerID    string            // Docker container ID
	ContainerName  string            // Docker container name
	DockerNetwork  string            // Docker network name
}

// ServiceOverrides allows manual override of auto-detected service info.
type ServiceOverrides struct {
	ServiceID      string            // Override service ID
	ServiceName    string            // Override service name
	Port           int               // Override port
	Tags           []string          // Override tags
	HealthEndpoint string            // Override health endpoint
	Meta           map[string]string // Override metadata
}

// GenerateDockerServiceDefinition creates a Consul service definition for a Docker container.
//
// This is the main entry point for service definition generation. It:
//  1. Inspects the Docker container
//  2. Extracts service metadata (name, port, tags, health)
//  3. Generates HCL service definition file
//  4. Writes to /etc/consul.d/{service-id}.hcl
//  5. Reloads Consul agent to pick up new service
//
// Parameters:
//   - rc: RuntimeContext
//   - containerNameOrID: Container name or ID
//   - overrides: Optional overrides for auto-detected values
//
// Returns:
//   - string: Path to generated service definition file
//   - error: Generation error or nil
//
// Example:
//
//	path, err := consul.GenerateDockerServiceDefinition(rc, "hecate-caddy", nil)
//	// File written to /etc/consul.d/hecate-caddy.hcl
func GenerateDockerServiceDefinition(
	rc *eos_io.RuntimeContext,
	containerNameOrID string,
	overrides *ServiceOverrides,
) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Generating Consul service definition for Docker container",
		zap.String("container", containerNameOrID))

	// ASSESS - Inspect container
	containerManager, err := container.NewManager(rc)
	if err != nil {
		return "", fmt.Errorf("failed to create container manager: %w", err)
	}
	defer func() { _ = containerManager.Close() }()

	containerInfo, err := containerManager.InspectRaw(rc.Ctx, containerNameOrID)
	if err != nil {
		return "", fmt.Errorf("failed to inspect container %s: %w", containerNameOrID, err)
	}

	logger.Debug("Container inspected",
		zap.String("id", containerInfo.ID[:12]),
		zap.String("name", containerInfo.Name),
		zap.String("state", containerInfo.State.Status))

	// ASSESS - Extract service information
	serviceInfo := extractServiceInfo(containerInfo, overrides)

	logger.Info("Service metadata extracted",
		zap.String("service_id", serviceInfo.ID),
		zap.String("service_name", serviceInfo.Name),
		zap.Int("port", serviceInfo.Port),
		zap.Strings("tags", serviceInfo.Tags))

	// INTERVENE - Generate HCL content
	hclContent := generateServiceHCL(serviceInfo)

	// INTERVENE - Write service definition file
	serviceFilePath := filepath.Join(ConsulConfigDir, fmt.Sprintf("%s.hcl", serviceInfo.ID))

	if err := os.WriteFile(serviceFilePath, []byte(hclContent), shared.FilePermStandard); err != nil {
		return "", fmt.Errorf("failed to write service definition %s: %w", serviceFilePath, err)
	}

	logger.Info("Service definition file written",
		zap.String("path", serviceFilePath))

	// INTERVENE - Reload Consul agent
	logger.Info("Reloading Consul agent to register service")
	if err := ReloadConsulAgent(rc); err != nil {
		logger.Warn("Failed to reload Consul agent (service will be picked up on next restart)",
			zap.Error(err))
		// Non-fatal - agent will pick up on restart
	}

	// EVALUATE - Verify file exists
	if _, err := os.Stat(serviceFilePath); err != nil {
		return "", fmt.Errorf("service definition file not found after write: %w", err)
	}

	logger.Info("Consul service definition generated successfully",
		zap.String("service_id", serviceInfo.ID),
		zap.String("file", serviceFilePath))

	return serviceFilePath, nil
}

// extractServiceInfo extracts service metadata from container inspection data.
//
// Extraction priority:
//  1. Manual overrides (if provided)
//  2. Container labels (consul.service.*)
//  3. Auto-detection from container config
//  4. Smart defaults
//
// Supported labels:
//   - consul.service.name: Service name
//   - consul.service.port: Service port
//   - consul.service.tags: Comma-separated tags
//   - consul.service.health: Health check endpoint
//   - consul.service.meta.*: Service metadata
//
// Parameters:
//   - containerInfo: Docker container inspection data
//   - overrides: Optional manual overrides
//
// Returns:
//   - ServiceInfo: Extracted service information
func extractServiceInfo(
	containerInfo *dockercontainer.InspectResponse,
	overrides *ServiceOverrides,
) ServiceInfo {
	labels := containerInfo.Config.Labels
	if labels == nil {
		labels = make(map[string]string)
	}

	service := ServiceInfo{
		ContainerID:    containerInfo.ID,
		ContainerName:  strings.TrimPrefix(containerInfo.Name, "/"),
		Address:        "localhost", // Default to localhost
		HealthInterval: "10s",
		HealthTimeout:  "2s",
		Meta:           make(map[string]string),
	}

	// Extract service name
	if overrides != nil && overrides.ServiceName != "" {
		service.Name = overrides.ServiceName
	} else if labelName, ok := labels["consul.service.name"]; ok {
		service.Name = labelName
	} else {
		// Auto-detect from container name
		service.Name = service.ContainerName
		// Strip common prefixes (hecate-, project_)
		service.Name = strings.TrimPrefix(service.Name, "hecate-")
		if idx := strings.Index(service.Name, "_"); idx != -1 {
			service.Name = service.Name[:idx]
		}
	}

	// Generate service ID
	if overrides != nil && overrides.ServiceID != "" {
		service.ID = overrides.ServiceID
	} else if labelID, ok := labels["consul.service.id"]; ok {
		service.ID = labelID
	} else {
		// Auto-generate: {container-name}
		service.ID = service.ContainerName
	}

	// Extract port
	if overrides != nil && overrides.Port > 0 {
		service.Port = overrides.Port
	} else if labelPort, ok := labels["consul.service.port"]; ok {
		_, _ = fmt.Sscanf(labelPort, "%d", &service.Port)
	} else {
		// Auto-detect from first exposed port
		for portProto := range containerInfo.Config.ExposedPorts {
			port := portProto.Int()
			if port > 0 {
				service.Port = port
				break
			}
		}
	}

	// Extract tags
	if overrides != nil && len(overrides.Tags) > 0 {
		service.Tags = overrides.Tags
	} else if labelTags, ok := labels["consul.service.tags"]; ok {
		service.Tags = strings.Split(labelTags, ",")
		for i := range service.Tags {
			service.Tags[i] = strings.TrimSpace(service.Tags[i])
		}
	} else {
		// Auto-generate tags based on service type
		service.Tags = generateDefaultTags(service.Name, service.Port)
	}

	// Extract health endpoint
	if overrides != nil && overrides.HealthEndpoint != "" {
		service.HealthEndpoint = overrides.HealthEndpoint
	} else if labelHealth, ok := labels["consul.service.health"]; ok {
		service.HealthEndpoint = labelHealth
	} else {
		// Generate default health check
		service.HealthEndpoint, service.HealthType = generateDefaultHealthCheck(service.Name, service.Port)
	}

	// Extract metadata
	if overrides != nil && len(overrides.Meta) > 0 {
		service.Meta = overrides.Meta
	} else {
		// Extract consul.service.meta.* labels
		for key, value := range labels {
			if strings.HasPrefix(key, "consul.service.meta.") {
				metaKey := strings.TrimPrefix(key, "consul.service.meta.")
				service.Meta[metaKey] = value
			}
		}
	}

	// Add default metadata
	if _, ok := service.Meta["container_name"]; !ok {
		service.Meta["container_name"] = service.ContainerName
	}
	if _, ok := service.Meta["container_id"]; !ok {
		service.Meta["container_id"] = service.ContainerID[:12]
	}

	// Detect Docker network
	for networkName := range containerInfo.NetworkSettings.Networks {
		service.DockerNetwork = networkName
		break
	}

	return service
}

// generateDefaultTags generates sensible default tags based on service name and port.
func generateDefaultTags(serviceName string, port int) []string {
	tags := []string{}

	// Service type tags
	switch {
	case strings.Contains(serviceName, "caddy") || strings.Contains(serviceName, "nginx"):
		tags = append(tags, "reverse-proxy", "http")
	case strings.Contains(serviceName, "authentik"):
		tags = append(tags, "sso", "authentication", "oidc")
	case strings.Contains(serviceName, "postgres"):
		tags = append(tags, "database", "postgresql")
	case strings.Contains(serviceName, "redis"):
		tags = append(tags, "cache", "redis")
	case strings.Contains(serviceName, "vault"):
		tags = append(tags, "secrets", "vault")
	case strings.Contains(serviceName, "consul"):
		tags = append(tags, "service-discovery", "consul")
	case strings.Contains(serviceName, "nomad"):
		tags = append(tags, "orchestration", "nomad")
	}

	// Port-based tags
	switch port {
	case 80:
		tags = append(tags, "http")
	case 443:
		tags = append(tags, "https", "tls")
	case 5432:
		tags = append(tags, "postgresql")
	case 6379:
		tags = append(tags, "redis")
	case 8200:
		tags = append(tags, "vault")
	case 8500:
		tags = append(tags, "consul")
	case 4646:
		tags = append(tags, "nomad")
	}

	return tags
}

// generateDefaultHealthCheck generates a default health check based on service type.
//
// Returns:
//   - string: Health check endpoint/command
//   - string: Health check type (http, tcp, script)
func generateDefaultHealthCheck(serviceName string, port int) (string, string) {
	// HTTP-based health checks
	switch {
	case strings.Contains(serviceName, "caddy"), strings.Contains(serviceName, "nginx"):
		return fmt.Sprintf("http://localhost:%d/", port), "http"
	case strings.Contains(serviceName, "authentik"):
		return "http://localhost:9000/-/health/ready/", "http"
	case strings.Contains(serviceName, "vault"):
		return "https://localhost:8200/v1/sys/health", "http"
	case strings.Contains(serviceName, "consul"):
		return "http://localhost:8500/v1/status/leader", "http"
	case strings.Contains(serviceName, "nomad"):
		return "http://localhost:4646/v1/status/leader", "http"
	}

	// Script-based health checks (requires docker exec)
	switch {
	case strings.Contains(serviceName, "postgres"):
		return "pg_isready -U postgres", "script"
	case strings.Contains(serviceName, "redis"):
		return "redis-cli ping", "script"
	}

	// Fallback: TCP check on primary port
	if port > 0 {
		return fmt.Sprintf("localhost:%d", port), "tcp"
	}

	// Last resort: nc -z
	return fmt.Sprintf("nc -z localhost %d", port), "script"
}

// generateServiceHCL creates HCL service definition content.
//
// Generates HashiCorp Configuration Language (HCL) for Consul service definition.
//
// Parameters:
//   - service: Service information
//
// Returns:
//   - string: HCL content for service definition file
//
// Example output:
//
//	service {
//	  id   = "hecate-caddy"
//	  name = "caddy"
//	  port = 80
//	  tags = ["reverse-proxy", "http"]
//
//	  check {
//	    id                  = "caddy-health"
//	    name                = "Caddy HTTP Health"
//	    docker_container_id = "a1b2c3d4e5f6"
//	    shell               = "/bin/sh"
//	    args                = ["-c", "curl -f http://localhost:80/ || exit 1"]
//	    interval            = "10s"
//	    timeout             = "2s"
//	  }
//	}
func generateServiceHCL(service ServiceInfo) string {
	var hcl strings.Builder

	hcl.WriteString("# Consul Service Definition\n")
	hcl.WriteString(fmt.Sprintf("# Generated by Eos for container: %s\n", service.ContainerName))
	hcl.WriteString(fmt.Sprintf("# Container ID: %s\n\n", service.ContainerID[:12]))

	hcl.WriteString("service {\n")
	hcl.WriteString(fmt.Sprintf("  id      = \"%s\"\n", service.ID))
	hcl.WriteString(fmt.Sprintf("  name    = \"%s\"\n", service.Name))
	if service.Port > 0 {
		hcl.WriteString(fmt.Sprintf("  port    = %d\n", service.Port))
	}
	hcl.WriteString(fmt.Sprintf("  address = \"%s\"\n", service.Address))

	// Tags
	if len(service.Tags) > 0 {
		hcl.WriteString("  tags    = [")
		for i, tag := range service.Tags {
			if i > 0 {
				hcl.WriteString(", ")
			}
			hcl.WriteString(fmt.Sprintf("\"%s\"", tag))
		}
		hcl.WriteString("]\n")
	}

	// Metadata
	if len(service.Meta) > 0 {
		hcl.WriteString("\n  meta = {\n")
		for key, value := range service.Meta {
			hcl.WriteString(fmt.Sprintf("    %s = \"%s\"\n", key, value))
		}
		hcl.WriteString("  }\n")
	}

	// Health check
	hcl.WriteString("\n  check {\n")
	hcl.WriteString(fmt.Sprintf("    id       = \"%s-health\"\n", service.ID))
	hcl.WriteString(fmt.Sprintf("    name     = \"%s Health Check\"\n", strings.Title(service.Name)))
	hcl.WriteString(fmt.Sprintf("    interval = \"%s\"\n", service.HealthInterval))
	hcl.WriteString(fmt.Sprintf("    timeout  = \"%s\"\n", service.HealthTimeout))

	switch service.HealthType {
	case "http":
		hcl.WriteString(fmt.Sprintf("    http     = \"%s\"\n", service.HealthEndpoint))
	case "tcp":
		hcl.WriteString(fmt.Sprintf("    tcp      = \"%s\"\n", service.HealthEndpoint))
	case "script", "":
		// Docker exec health check (HashiCorp pattern)
		hcl.WriteString(fmt.Sprintf("    docker_container_id = \"%s\"\n", service.ContainerID))
		hcl.WriteString("    shell               = \"/bin/sh\"\n")
		hcl.WriteString(fmt.Sprintf("    args                = [\"-c\", \"%s\"]\n", service.HealthEndpoint))
	}

	hcl.WriteString("  }\n")
	hcl.WriteString("}\n")

	return hcl.String()
}

// GetContainersFromComposeFile extracts container names from a docker-compose.yml file.
//
// This function parses a Docker Compose file to discover services that should be
// registered with Consul.
//
// Parameters:
//   - rc: RuntimeContext
//   - composeFilePath: Path to docker-compose.yml
//
// Returns:
//   - []string: List of container names
//   - error: Parse error or nil
//
// Example:
//
//	containers, err := consul.GetContainersFromComposeFile(rc, "/opt/hecate/docker-compose.yml")
//	// Returns: ["hecate-caddy", "hecate-authentik", "hecate-redis", "hecate-postgresql"]
func GetContainersFromComposeFile(rc *eos_io.RuntimeContext, composeFilePath string) ([]string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Discovering containers from docker-compose.yml",
		zap.String("compose_file", composeFilePath))

	// ASSESS - Check if compose file exists
	if _, err := os.Stat(composeFilePath); err != nil {
		return nil, fmt.Errorf("compose file not found: %w", err)
	}

	// ASSESS - Use docker compose ps to list containers
	containerManager, err := container.NewManager(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to create container manager: %w", err)
	}
	defer func() { _ = containerManager.Close() }()

	// List all containers (including stopped ones)
	containers, err := containerManager.ListAll(rc.Ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	// Extract directory name from compose file path
	composeDir := filepath.Dir(composeFilePath)
	projectName := filepath.Base(composeDir)

	logger.Debug("Filtering containers by project",
		zap.String("project_name", projectName),
		zap.Int("total_containers", len(containers)))

	// Filter containers by compose project label
	var composeContainers []string
	for _, c := range containers {
		// Docker Compose adds com.docker.compose.project label
		if c.Labels["com.docker.compose.project"] == projectName {
			// Use container name
			if c.Name != "" {
				composeContainers = append(composeContainers, c.Name)
			}
		}
	}

	logger.Info("Containers discovered from compose project",
		zap.String("project", projectName),
		zap.Int("count", len(composeContainers)),
		zap.Strings("containers", composeContainers))

	return composeContainers, nil
}
