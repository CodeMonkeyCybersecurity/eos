// pkg/docker/compose_precipitate.go
// Generic docker-compose.yml precipitation from running containers using Docker SDK

package docker

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PrecipitatedService represents a Docker service extracted from a running container
type PrecipitatedService struct {
	Name          string
	Image         string
	ContainerName string
	Command       []string
	Environment   map[string]string
	Volumes       []string
	Ports         []string
	Networks      []string
	Restart       string
	DependsOn     []string
	HealthCheck   *PrecipitatedHealthCheck
	Labels        map[string]string
}

// PrecipitatedHealthCheck represents extracted health check configuration
type PrecipitatedHealthCheck struct {
	Test        []string
	Interval    string
	Timeout     string
	Retries     int
	StartPeriod string
}

// PrecipitatedCompose represents the full extracted docker-compose structure
type PrecipitatedCompose struct {
	Services map[string]*PrecipitatedService
	Networks map[string]*PrecipitatedNetwork
	Volumes  map[string]*PrecipitatedVolume
}

// PrecipitatedNetwork represents extracted network configuration
type PrecipitatedNetwork struct {
	Driver string
	Labels map[string]string
}

// PrecipitatedVolume represents extracted volume configuration
type PrecipitatedVolume struct {
	Driver string
	Labels map[string]string
}

// PrecipitateComposeOptions configures how compose precipitation works
type PrecipitateComposeOptions struct {
	// ProjectName filters containers by compose project (e.g., "hecate")
	ProjectName string
	// LabelFilters allows custom label-based filtering
	LabelFilters map[string]string
	// IncludeStopped includes stopped containers in output
	IncludeStopped bool
	// FilterEnvVars removes environment variables matching these prefixes
	FilterEnvVars []string
}

// DefaultPrecipitateOptions returns sensible defaults
func DefaultPrecipitateOptions() *PrecipitateComposeOptions {
	return &PrecipitateComposeOptions{
		IncludeStopped: true,
		FilterEnvVars: []string{
			"DOCKER_",
			"PATH",
			"HOSTNAME",
			"HOME",
			"TERM",
		},
	}
}

// PrecipitateCompose extracts docker-compose.yml from running containers
func PrecipitateCompose(rc *eos_io.RuntimeContext, opts *PrecipitateComposeOptions) (*PrecipitatedCompose, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Precipitating docker-compose configuration from running containers")

	if opts == nil {
		opts = DefaultPrecipitateOptions()
	}

	// ASSESS - Connect to Docker daemon
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}
	defer func() {
		if closeErr := cli.Close(); closeErr != nil {
			logger.Warn("Failed to close Docker client", zap.Error(closeErr))
		}
	}()

	// INTERVENE - Build container filters
	containerFilters := filters.NewArgs()

	if opts.ProjectName != "" {
		containerFilters.Add("label", fmt.Sprintf("com.docker.compose.project=%s", opts.ProjectName))
	}

	for key, value := range opts.LabelFilters {
		if value == "" {
			containerFilters.Add("label", key)
		} else {
			containerFilters.Add("label", fmt.Sprintf("%s=%s", key, value))
		}
	}

	containers, err := cli.ContainerList(rc.Ctx, container.ListOptions{
		All:     opts.IncludeStopped,
		Filters: containerFilters,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	if len(containers) == 0 {
		logger.Warn("No containers found matching filters")
		return nil, fmt.Errorf("no containers found - check your filters")
	}

	logger.Info("Found containers", zap.Int("count", len(containers)))

	// INTERVENE - Extract configuration from each container
	precipitated := &PrecipitatedCompose{
		Services: make(map[string]*PrecipitatedService),
		Networks: make(map[string]*PrecipitatedNetwork),
		Volumes:  make(map[string]*PrecipitatedVolume),
	}

	for _, ctr := range containers {
		service, err := extractServiceFromContainer(rc.Ctx, cli, ctr, opts)
		if err != nil {
			logger.Warn("Failed to extract service from container",
				zap.String("container", ctr.Names[0]),
				zap.Error(err))
			continue
		}

		precipitated.Services[service.Name] = service

		// Extract networks
		for _, network := range service.Networks {
			if _, exists := precipitated.Networks[network]; !exists {
				precipitated.Networks[network] = &PrecipitatedNetwork{
					Driver: "bridge", // Default, can be enhanced
				}
			}
		}
	}

	// INTERVENE - Extract volumes from Docker
	if err := extractVolumes(rc.Ctx, cli, precipitated); err != nil {
		logger.Warn("Failed to extract volumes", zap.Error(err))
		// Not fatal - continue without volumes
	}

	// EVALUATE - Verify we extracted services
	logger.Info("Successfully precipitated compose configuration",
		zap.Int("services", len(precipitated.Services)),
		zap.Int("networks", len(precipitated.Networks)),
		zap.Int("volumes", len(precipitated.Volumes)))

	return precipitated, nil
}

// extractServiceFromContainer extracts service configuration from a single container
func extractServiceFromContainer(ctx context.Context, cli *client.Client, ctr container.Summary, opts *PrecipitateComposeOptions) (*PrecipitatedService, error) {
	// Get detailed container info
	inspect, err := cli.ContainerInspect(ctx, ctr.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}

	// Extract service name from compose label
	serviceName := ctr.Labels["com.docker.compose.service"]
	if serviceName == "" {
		serviceName = strings.TrimPrefix(ctr.Names[0], "/")
	}

	service := &PrecipitatedService{
		Name:          serviceName,
		Image:         ctr.Image,
		ContainerName: strings.TrimPrefix(ctr.Names[0], "/"),
		Environment:   make(map[string]string),
		Volumes:       []string{},
		Ports:         []string{},
		Networks:      []string{},
		Labels:        make(map[string]string),
	}

	// Extract command
	if len(inspect.Config.Cmd) > 0 {
		service.Command = inspect.Config.Cmd
	}

	// Extract environment variables
	for _, env := range inspect.Config.Env {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			// Filter out unwanted env vars
			shouldFilter := false
			for _, prefix := range opts.FilterEnvVars {
				if strings.HasPrefix(parts[0], prefix) {
					shouldFilter = true
					break
				}
			}
			if !shouldFilter {
				service.Environment[parts[0]] = parts[1]
			}
		}
	}

	// Extract volumes/mounts
	for _, mount := range inspect.Mounts {
		var volumeStr string
		if mount.Type == "bind" {
			volumeStr = fmt.Sprintf("%s:%s", mount.Source, mount.Destination)
		} else {
			volumeStr = fmt.Sprintf("%s:%s", mount.Name, mount.Destination)
		}
		if mount.RW {
			volumeStr += ":rw"
		} else {
			volumeStr += ":ro"
		}
		service.Volumes = append(service.Volumes, volumeStr)
	}

	// Extract port mappings
	for _, port := range ctr.Ports {
		portStr := ""
		if port.IP != "" {
			portStr = fmt.Sprintf("%s:%d:%d", port.IP, port.PublicPort, port.PrivatePort)
		} else {
			portStr = fmt.Sprintf("%d:%d", port.PublicPort, port.PrivatePort)
		}
		if port.Type == "udp" {
			portStr += "/udp"
		}
		service.Ports = append(service.Ports, portStr)
	}

	// Extract networks
	for network := range inspect.NetworkSettings.Networks {
		if network != "bridge" && network != "host" && network != "none" {
			service.Networks = append(service.Networks, network)
		}
	}

	// Extract restart policy
	switch inspect.HostConfig.RestartPolicy.Name {
	case "always":
		service.Restart = "always"
	case "unless-stopped":
		service.Restart = "unless-stopped"
	case "on-failure":
		service.Restart = "on-failure"
	default:
		service.Restart = "no"
	}

	// Extract health check
	if inspect.Config.Healthcheck != nil {
		service.HealthCheck = &PrecipitatedHealthCheck{
			Test:     inspect.Config.Healthcheck.Test,
			Interval: inspect.Config.Healthcheck.Interval.String(),
			Timeout:  inspect.Config.Healthcheck.Timeout.String(),
			Retries:  inspect.Config.Healthcheck.Retries,
		}
		if inspect.Config.Healthcheck.StartPeriod > 0 {
			service.HealthCheck.StartPeriod = inspect.Config.Healthcheck.StartPeriod.String()
		}
	}

	// Extract compose-specific labels
	for key, value := range ctr.Labels {
		if strings.HasPrefix(key, "com.docker.compose.") {
			continue // Skip compose metadata
		}
		service.Labels[key] = value
	}

	return service, nil
}

// extractVolumes discovers named volumes used by services
func extractVolumes(ctx context.Context, cli *client.Client, precipitated *PrecipitatedCompose) error {
	// List all volumes
	volumesResp, err := cli.VolumeList(ctx, volume.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list volumes: %w", err)
	}

	// Find volumes used by our services
	usedVolumes := make(map[string]bool)
	for _, service := range precipitated.Services {
		for _, vol := range service.Volumes {
			parts := strings.Split(vol, ":")
			if len(parts) >= 2 && !strings.HasPrefix(parts[0], "/") && !strings.HasPrefix(parts[0], ".") {
				// This is a named volume, not a bind mount
				usedVolumes[parts[0]] = true
			}
		}
	}

	// Add used volumes to precipitated config
	for _, vol := range volumesResp.Volumes {
		if usedVolumes[vol.Name] {
			precipitated.Volumes[vol.Name] = &PrecipitatedVolume{
				Driver: vol.Driver,
				Labels: vol.Labels,
			}
		}
	}

	return nil
}

// RenderCompose generates docker-compose.yml content from precipitated config
func RenderCompose(precipitated *PrecipitatedCompose) string {
	var sb strings.Builder

	// Header
	sb.WriteString("# Precipitated docker-compose.yml\n")
	sb.WriteString("# Auto-generated from running containers\n")
	sb.WriteString("# Generated by Eos\n\n")

	// Services section
	sb.WriteString("services:\n")

	// Sort services for consistent output
	serviceNames := make([]string, 0, len(precipitated.Services))
	for name := range precipitated.Services {
		serviceNames = append(serviceNames, name)
	}
	sort.Strings(serviceNames)

	for _, name := range serviceNames {
		service := precipitated.Services[name]
		sb.WriteString(fmt.Sprintf("\n  %s:\n", name))
		sb.WriteString(fmt.Sprintf("    image: %s\n", service.Image))

		if service.ContainerName != "" {
			sb.WriteString(fmt.Sprintf("    container_name: %s\n", service.ContainerName))
		}

		if service.Restart != "no" {
			sb.WriteString(fmt.Sprintf("    restart: %s\n", service.Restart))
		}

		if len(service.Command) > 0 {
			sb.WriteString(fmt.Sprintf("    command: %s\n", strings.Join(service.Command, " ")))
		}

		// Environment variables
		if len(service.Environment) > 0 {
			sb.WriteString("    environment:\n")
			envKeys := make([]string, 0, len(service.Environment))
			for key := range service.Environment {
				envKeys = append(envKeys, key)
			}
			sort.Strings(envKeys)
			for _, key := range envKeys {
				value := service.Environment[key]
				// Quote values that might contain special chars
				if strings.Contains(value, " ") || strings.Contains(value, "$") {
					value = fmt.Sprintf("\"%s\"", value)
				}
				sb.WriteString(fmt.Sprintf("      %s: %s\n", key, value))
			}
		}

		// Volumes
		if len(service.Volumes) > 0 {
			sb.WriteString("    volumes:\n")
			for _, vol := range service.Volumes {
				sb.WriteString(fmt.Sprintf("      - %s\n", vol))
			}
		}

		// Ports
		if len(service.Ports) > 0 {
			sb.WriteString("    ports:\n")
			for _, port := range service.Ports {
				sb.WriteString(fmt.Sprintf("      - \"%s\"\n", port))
			}
		}

		// Networks
		if len(service.Networks) > 0 {
			sb.WriteString("    networks:\n")
			for _, network := range service.Networks {
				sb.WriteString(fmt.Sprintf("      - %s\n", network))
			}
		}

		// Health check
		if service.HealthCheck != nil {
			sb.WriteString("    healthcheck:\n")
			if len(service.HealthCheck.Test) > 0 {
				sb.WriteString(fmt.Sprintf("      test: %v\n", service.HealthCheck.Test))
			}
			if service.HealthCheck.StartPeriod != "" && service.HealthCheck.StartPeriod != "0s" {
				sb.WriteString(fmt.Sprintf("      start_period: %s\n", service.HealthCheck.StartPeriod))
			}
			if service.HealthCheck.Interval != "" && service.HealthCheck.Interval != "0s" {
				sb.WriteString(fmt.Sprintf("      interval: %s\n", service.HealthCheck.Interval))
			}
			if service.HealthCheck.Retries > 0 {
				sb.WriteString(fmt.Sprintf("      retries: %d\n", service.HealthCheck.Retries))
			}
			if service.HealthCheck.Timeout != "" && service.HealthCheck.Timeout != "0s" {
				sb.WriteString(fmt.Sprintf("      timeout: %s\n", service.HealthCheck.Timeout))
			}
		}
	}

	// Networks section
	if len(precipitated.Networks) > 0 {
		sb.WriteString("\nnetworks:\n")
		networkNames := make([]string, 0, len(precipitated.Networks))
		for name := range precipitated.Networks {
			networkNames = append(networkNames, name)
		}
		sort.Strings(networkNames)

		for _, name := range networkNames {
			network := precipitated.Networks[name]
			sb.WriteString(fmt.Sprintf("  %s:\n", name))
			if network.Driver != "" && network.Driver != "bridge" {
				sb.WriteString(fmt.Sprintf("    driver: %s\n", network.Driver))
			}
		}
	}

	// Volumes section
	if len(precipitated.Volumes) > 0 {
		sb.WriteString("\nvolumes:\n")
		volumeNames := make([]string, 0, len(precipitated.Volumes))
		for name := range precipitated.Volumes {
			volumeNames = append(volumeNames, name)
		}
		sort.Strings(volumeNames)

		for _, name := range volumeNames {
			volume := precipitated.Volumes[name]
			sb.WriteString(fmt.Sprintf("  %s:\n", name))
			if volume.Driver != "" && volume.Driver != "local" {
				sb.WriteString(fmt.Sprintf("    driver: %s\n", volume.Driver))
			}
		}
	}

	return sb.String()
}

// PrecipitateAndSave extracts compose from running containers and saves to file
func PrecipitateAndSave(rc *eos_io.RuntimeContext, opts *PrecipitateComposeOptions, outputPath string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Precipitating and saving docker-compose configuration",
		zap.String("output", outputPath))

	// ASSESS - Extract configuration from running containers
	precipitated, err := PrecipitateCompose(rc, opts)
	if err != nil {
		return fmt.Errorf("failed to precipitate compose: %w", err)
	}

	// INTERVENE - Render to YAML format
	composeContent := RenderCompose(precipitated)

	// INTERVENE - Write to file
	if err := os.WriteFile(outputPath, []byte(composeContent), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write compose file: %w", err)
	}

	// EVALUATE - Verify file was written
	fileInfo, err := os.Stat(outputPath)
	if err != nil {
		return fmt.Errorf("failed to verify output file: %w", err)
	}

	logger.Info("Successfully saved precipitated compose file",
		zap.String("path", outputPath),
		zap.Int64("size_bytes", fileInfo.Size()),
		zap.Int("services", len(precipitated.Services)))

	return nil
}
