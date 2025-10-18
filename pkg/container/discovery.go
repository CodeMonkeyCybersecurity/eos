// pkg/container/discovery.go
// Version-agnostic container discovery using Docker Compose labels

package container

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ComposeMetadata holds Docker Compose specific metadata
type ComposeMetadata struct {
	Project string
	Service string
	Number  string
}

// FindByService finds containers by Docker Compose service name
// Works with both Compose v1 and v2, regardless of project naming
func (m *Manager) FindByService(ctx context.Context, serviceName string) ([]Container, error) {
	logger := otelzap.Ctx(ctx)

	filterArgs := filters.NewArgs()
	filterArgs.Add("label", fmt.Sprintf("com.docker.compose.service=%s", serviceName))

	logger.Debug("Searching for containers by service",
		zap.String("service_name", serviceName),
		zap.String("label_filter", fmt.Sprintf("com.docker.compose.service=%s", serviceName)))

	m.mu.RLock()
	containers, err := m.client.ContainerList(ctx, container.ListOptions{
		All:     true,
		Filters: filterArgs,
	})
	m.mu.RUnlock()

	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	result := make([]Container, 0, len(containers))
	for _, c := range containers {
		result = append(result, m.toContainer(c))
	}

	logger.Debug("Containers found by service",
		zap.String("service_name", serviceName),
		zap.Int("count", len(result)))

	return result, nil
}

// FindByProject finds all containers in a Docker Compose project
func (m *Manager) FindByProject(ctx context.Context, projectName string) ([]Container, error) {
	logger := otelzap.Ctx(ctx)

	filterArgs := filters.NewArgs()
	filterArgs.Add("label", fmt.Sprintf("com.docker.compose.project=%s", projectName))

	logger.Debug("Searching for containers by project",
		zap.String("project_name", projectName))

	m.mu.RLock()
	containers, err := m.client.ContainerList(ctx, container.ListOptions{
		All:     true,
		Filters: filterArgs,
	})
	m.mu.RUnlock()

	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	result := make([]Container, 0, len(containers))
	for _, c := range containers {
		result = append(result, m.toContainer(c))
	}

	logger.Debug("Containers found by project",
		zap.String("project_name", projectName),
		zap.Int("count", len(result)))

	return result, nil
}

// FindByLabels finds containers matching label filters
func (m *Manager) FindByLabels(ctx context.Context, labels map[string]string) ([]Container, error) {
	logger := otelzap.Ctx(ctx)

	filterArgs := filters.NewArgs()
	for key, value := range labels {
		filterArgs.Add("label", fmt.Sprintf("%s=%s", key, value))
	}

	logger.Debug("Searching for containers by labels",
		zap.Any("labels", labels))

	m.mu.RLock()
	containers, err := m.client.ContainerList(ctx, container.ListOptions{
		All:     true,
		Filters: filterArgs,
	})
	m.mu.RUnlock()

	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	result := make([]Container, 0, len(containers))
	for _, c := range containers {
		result = append(result, m.toContainer(c))
	}

	logger.Debug("Containers found by labels",
		zap.Int("count", len(result)))

	return result, nil
}

// FindByName finds a container by exact name match
// Falls back to name-based search for non-Compose containers
func (m *Manager) FindByName(ctx context.Context, name string) (*Container, error) {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Searching for container by name",
		zap.String("name", name))

	m.mu.RLock()
	containers, err := m.client.ContainerList(ctx, container.ListOptions{
		All: true,
	})
	m.mu.RUnlock()

	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	// Try exact name matches (with and without leading slash)
	for _, c := range containers {
		for _, containerName := range c.Names {
			cleanName := strings.TrimPrefix(containerName, "/")
			if cleanName == name || containerName == name {
				result := m.toContainer(c)
				logger.Debug("Container found by name",
					zap.String("name", name),
					zap.String("id", result.ID[:12]))
				return &result, nil
			}
		}
	}

	return nil, fmt.Errorf("container not found: %s", name)
}

// ListAll lists all containers (running and stopped)
func (m *Manager) ListAll(ctx context.Context) ([]Container, error) {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Listing all containers")

	m.mu.RLock()
	containers, err := m.client.ContainerList(ctx, container.ListOptions{
		All: true,
	})
	m.mu.RUnlock()

	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	result := make([]Container, 0, len(containers))
	for _, c := range containers {
		result = append(result, m.toContainer(c))
	}

	logger.Debug("Containers listed",
		zap.Int("count", len(result)))

	return result, nil
}

// ListRunning lists only running containers
func (m *Manager) ListRunning(ctx context.Context) ([]Container, error) {
	logger := otelzap.Ctx(ctx)

	logger.Debug("Listing running containers")

	m.mu.RLock()
	containers, err := m.client.ContainerList(ctx, container.ListOptions{
		All: false, // Only running
	})
	m.mu.RUnlock()

	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	result := make([]Container, 0, len(containers))
	for _, c := range containers {
		result = append(result, m.toContainer(c))
	}

	logger.Debug("Running containers listed",
		zap.Int("count", len(result)))

	return result, nil
}

// toContainer converts Docker API container to our Container type
func (m *Manager) toContainer(c container.Summary) Container {
	// Extract name (remove leading slash)
	name := ""
	if len(c.Names) > 0 {
		name = strings.TrimPrefix(c.Names[0], "/")
	}

	// Convert status string to ContainerStatus
	status := ContainerStatus(c.State)

	// Convert Created timestamp to time.Time
	created := time.Unix(c.Created, 0)

	// Labels already include Compose metadata if present
	// com.docker.compose.project, com.docker.compose.service, etc.

	return Container{
		ID:      c.ID,
		Name:    name,
		Image:   c.Image,
		Status:  status,
		Labels:  c.Labels,
		Created: created,
	}
}

// IsRunning checks if a container is running
func (c *Container) IsRunning() bool {
	return c.Status == StatusRunning
}

// IsCompose checks if a container is managed by Docker Compose
func (c *Container) IsCompose() bool {
	_, hasProject := c.Labels["com.docker.compose.project"]
	_, hasService := c.Labels["com.docker.compose.service"]
	return hasProject && hasService
}

// GetComposeProject returns the Docker Compose project name if available
func (c *Container) GetComposeProject() string {
	return c.Labels["com.docker.compose.project"]
}

// GetComposeService returns the Docker Compose service name if available
func (c *Container) GetComposeService() string {
	return c.Labels["com.docker.compose.service"]
}

// ShortID returns the short container ID (first 12 characters)
func (c *Container) ShortID() string {
	if len(c.ID) >= 12 {
		return c.ID[:12]
	}
	return c.ID
}
