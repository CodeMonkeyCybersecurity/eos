// Package inspect provides infrastructure discovery and audit capabilities
// for Docker, KVM, Hetzner Cloud, and system services.
package inspect

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// Constants for Docker inspection configuration.
const (
	// MaxComposeFileSize is the maximum size of a compose file we will read (10 MB).
	// RATIONALE: Prevents OOM from accidentally discovered multi-GB files.
	// SECURITY: Mitigates DoS via malicious symlinks to large files.
	MaxComposeFileSize = 10 * 1024 * 1024

	// ContainerStateRunning is the canonical "running" state string.
	ContainerStateRunning = "running"

	// ContainerStateStopped is the canonical "stopped" state string.
	ContainerStateStopped = "stopped"

	// SensitiveValueRedacted is the placeholder for redacted env vars.
	SensitiveValueRedacted = "***"
)

// ComposeSearchPaths are the directories searched for docker compose files.
// These cover standard Linux deployment locations for containerised services.
var ComposeSearchPaths = []string{
	"/home",
	"/root",
	"/opt",
	"/srv",
	"/var",
}

// ComposeFileNames are the file names recognised as Docker Compose files.
var ComposeFileNames = []string{
	"docker-compose.yml",
	"docker-compose.yaml",
	"compose.yml",
	"compose.yaml",
}

// sensitiveEnvKeywords are substrings that indicate an environment variable
// holds a sensitive value and should be redacted.
var sensitiveEnvKeywords = []string{
	"password",
	"secret",
	"token",
	"key",
	"credential",
	"private",
}

// DiscoverDocker gathers Docker infrastructure information.
func (i *Inspector) DiscoverDocker() (*DockerInfo, error) {
	logger := otelzap.Ctx(i.rc.Ctx)
	logger.Info("Starting Docker discovery")

	if !i.commandExists("docker") {
		return nil, fmt.Errorf("docker command not found: install Docker or ensure it is in PATH")
	}

	info := &DockerInfo{}

	// Get Docker version
	if output, err := i.runCommand("docker", "version", "--format", "{{.Server.Version}}"); err == nil {
		info.Version = output
		logger.Info("Docker version detected", zap.String("version", info.Version))
	}

	// Discover containers (batched inspect for performance)
	if containers, err := i.discoverContainers(); err != nil {
		logger.Warn("Failed to discover containers", zap.Error(err))
	} else {
		info.Containers = containers
		logger.Info("Discovered containers", zap.Int("count", len(containers)))
	}

	// Discover images
	if images, err := i.discoverImages(); err != nil {
		logger.Warn("Failed to discover images", zap.Error(err))
	} else {
		info.Images = images
		logger.Info("Discovered images", zap.Int("count", len(images)))
	}

	// Discover networks
	if networks, err := i.discoverNetworks(); err != nil {
		logger.Warn("Failed to discover networks", zap.Error(err))
	} else {
		info.Networks = networks
		logger.Info("Discovered networks", zap.Int("count", len(networks)))
	}

	// Discover volumes
	if volumes, err := i.discoverVolumes(); err != nil {
		logger.Warn("Failed to discover volumes", zap.Error(err))
	} else {
		info.Volumes = volumes
		logger.Info("Discovered volumes", zap.Int("count", len(volumes)))
	}

	// Discover compose files
	if composeFiles, err := i.discoverComposeFiles(); err != nil {
		logger.Warn("Failed to discover compose files", zap.Error(err))
	} else {
		info.ComposeFiles = composeFiles
		logger.Info("Discovered compose files", zap.Int("count", len(composeFiles)))
	}

	logger.Info("Docker discovery completed")
	return info, nil
}

// containerInspectData is the struct for unmarshalling docker inspect JSON output.
// Extracted as a package-level type for testability and reuse.
type containerInspectData struct {
	ID      string `json:"Id"`
	Name    string `json:"Name"`
	Created string `json:"Created"`
	State   struct {
		Status  string `json:"Status"`
		Running bool   `json:"Running"`
	} `json:"State"`
	Config struct {
		Image  string            `json:"Image"`
		Env    []string          `json:"Env"`
		Labels map[string]string `json:"Labels"`
		Cmd    []string          `json:"Cmd"`
	} `json:"Config"`
	NetworkSettings struct {
		Networks map[string]any `json:"Networks"`
		Ports    map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
	Mounts []struct {
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		Mode        string `json:"Mode"`
	} `json:"Mounts"`
	HostConfig struct {
		RestartPolicy struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
}

// discoverContainers discovers all Docker containers using batched inspect.
// This runs exactly 2 commands (ps + inspect) instead of N+1.
func (i *Inspector) discoverContainers() ([]DockerContainer, error) {
	logger := otelzap.Ctx(i.rc.Ctx)

	// Get all container IDs in a single call
	output, err := i.runCommand("docker", "ps", "-aq")
	if err != nil {
		return nil, fmt.Errorf("failed to list container IDs: %w", err)
	}

	if output == "" {
		return nil, nil
	}

	// Collect IDs, filtering empties
	var ids []string
	for _, id := range strings.Split(output, "\n") {
		if trimmed := strings.TrimSpace(id); trimmed != "" {
			ids = append(ids, trimmed)
		}
	}

	if len(ids) == 0 {
		return nil, nil
	}

	// Batch inspect: "docker inspect id1 id2 id3 ..." in one exec
	args := append([]string{"inspect"}, ids...)
	inspectOutput, err := i.runCommand("docker", args...)
	if err != nil {
		logger.Warn("Failed to batch inspect containers, falling back to individual inspect",
			zap.Int("container_count", len(ids)),
			zap.Error(err))
		return i.discoverContainersFallback(ids)
	}

	containers, parseErr := parseContainerInspectJSON(inspectOutput)
	if parseErr != nil {
		logger.Warn("Failed to parse batched container inspect data",
			zap.Error(parseErr))
		return i.discoverContainersFallback(ids)
	}

	return containers, nil
}

// discoverContainersFallback inspects containers one by one when batched inspect fails.
func (i *Inspector) discoverContainersFallback(ids []string) ([]DockerContainer, error) {
	logger := otelzap.Ctx(i.rc.Ctx)
	var containers []DockerContainer

	for _, id := range ids {
		inspectOutput, err := i.runCommand("docker", "inspect", id)
		if err != nil {
			logger.Warn("Failed to inspect container",
				zap.String("id", id),
				zap.Error(err))
			continue
		}

		parsed, parseErr := parseContainerInspectJSON(inspectOutput)
		if parseErr != nil {
			logger.Warn("Failed to parse container inspect data",
				zap.String("id", id),
				zap.Error(parseErr))
			continue
		}
		containers = append(containers, parsed...)
	}

	return containers, nil
}

// parseContainerInspectJSON parses the JSON output from docker inspect into
// DockerContainer structs. This is a pure function for testability.
func parseContainerInspectJSON(jsonData string) ([]DockerContainer, error) {
	var inspectData []containerInspectData
	if err := json.Unmarshal([]byte(jsonData), &inspectData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal container inspect JSON: %w", err)
	}

	containers := make([]DockerContainer, 0, len(inspectData))
	for _, data := range inspectData {
		state := ContainerStateStopped
		if data.State.Running {
			state = ContainerStateRunning
		}

		container := DockerContainer{
			ID:      data.ID,
			Name:    strings.TrimPrefix(data.Name, "/"),
			Image:   data.Config.Image,
			Status:  data.State.Status,
			State:   state,
			Labels:  data.Config.Labels,
			Restart: data.HostConfig.RestartPolicy.Name,
		}

		// Parse created time
		if t, err := time.Parse(time.RFC3339Nano, data.Created); err == nil {
			container.Created = t
		}

		// Parse environment variables with secret redaction
		container.Environment = parseEnvVars(data.Config.Env)

		// Parse command
		if len(data.Config.Cmd) > 0 {
			container.Command = strings.Join(data.Config.Cmd, " ")
		}

		// Parse networks (sorted for deterministic output)
		for network := range data.NetworkSettings.Networks {
			container.Networks = append(container.Networks, network)
		}
		sort.Strings(container.Networks)

		// Parse ports (sorted for deterministic output)
		for port, bindings := range data.NetworkSettings.Ports {
			for _, binding := range bindings {
				portStr := fmt.Sprintf("%s:%s->%s", binding.HostIP, binding.HostPort, port)
				container.Ports = append(container.Ports, portStr)
			}
		}
		sort.Strings(container.Ports)

		// Parse volumes (sorted for deterministic output)
		for _, mount := range data.Mounts {
			volStr := fmt.Sprintf("%s:%s:%s", mount.Source, mount.Destination, mount.Mode)
			container.Volumes = append(container.Volumes, volStr)
		}
		sort.Strings(container.Volumes)

		containers = append(containers, container)
	}

	return containers, nil
}

// parseEnvVars converts a slice of KEY=VALUE strings to a map, redacting
// sensitive values. This is a pure function for testability.
func parseEnvVars(envSlice []string) map[string]string {
	result := make(map[string]string, len(envSlice))
	for _, env := range envSlice {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		if isSensitiveEnvVar(parts[0]) {
			result[parts[0]] = SensitiveValueRedacted
		} else {
			result[parts[0]] = parts[1]
		}
	}
	return result
}

// isSensitiveEnvVar returns true if the variable name suggests a secret.
func isSensitiveEnvVar(name string) bool {
	lower := strings.ToLower(name)
	for _, keyword := range sensitiveEnvKeywords {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	return false
}

// discoverImages discovers Docker images.
func (i *Inspector) discoverImages() ([]DockerImage, error) {
	logger := otelzap.Ctx(i.rc.Ctx)

	output, err := i.runCommand("docker", "images", "--format", "{{json .}}")
	if err != nil {
		return nil, fmt.Errorf("failed to list Docker images: %w", err)
	}

	var images []DockerImage
	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}

		var imageData struct {
			ID         string `json:"ID"`
			Repository string `json:"Repository"`
			Tag        string `json:"Tag"`
			Size       string `json:"Size"`
			CreatedAt  string `json:"CreatedAt"`
		}

		if err := json.Unmarshal([]byte(line), &imageData); err != nil {
			logger.Warn("Failed to parse image data",
				zap.String("line", line),
				zap.Error(err))
			continue
		}

		image := DockerImage{
			ID: imageData.ID,
		}

		// Build repo tags
		if imageData.Repository != "<none>" {
			tag := imageData.Tag
			if tag == "<none>" {
				tag = "latest"
			}
			image.RepoTags = []string{fmt.Sprintf("%s:%s", imageData.Repository, tag)}
		}

		// Parse size (Docker uses SI/decimal units)
		if sizeBytes, err := ParseDockerSize(imageData.Size); err == nil {
			image.Size = sizeBytes
		}

		// Parse created time
		if t, err := time.Parse("2006-01-02 15:04:05 -0700 MST", imageData.CreatedAt); err == nil {
			image.Created = t
		}

		images = append(images, image)
	}

	return images, nil
}

// discoverNetworks discovers Docker networks.
func (i *Inspector) discoverNetworks() ([]DockerNetwork, error) {
	logger := otelzap.Ctx(i.rc.Ctx)

	output, err := i.runCommand("docker", "network", "ls", "--format", "{{json .}}")
	if err != nil {
		return nil, fmt.Errorf("failed to list Docker networks: %w", err)
	}

	var networks []DockerNetwork
	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}

		var netData struct {
			ID     string `json:"ID"`
			Name   string `json:"Name"`
			Driver string `json:"Driver"`
			Scope  string `json:"Scope"`
		}

		if err := json.Unmarshal([]byte(line), &netData); err != nil {
			logger.Warn("Failed to parse network data",
				zap.String("line", line),
				zap.Error(err))
			continue
		}

		network := DockerNetwork{
			ID:     netData.ID,
			Name:   netData.Name,
			Driver: netData.Driver,
			Scope:  netData.Scope,
		}

		// Get detailed network info for labels
		inspectOutput, err := i.runCommand("docker", "network", "inspect", netData.ID, "--format", "{{json .Labels}}")
		if err == nil && inspectOutput != "null" {
			var labels map[string]string
			if err := json.Unmarshal([]byte(inspectOutput), &labels); err == nil {
				network.Labels = labels
			}
		}

		networks = append(networks, network)
	}

	return networks, nil
}

// discoverVolumes discovers Docker volumes.
func (i *Inspector) discoverVolumes() ([]DockerVolume, error) {
	logger := otelzap.Ctx(i.rc.Ctx)

	output, err := i.runCommand("docker", "volume", "ls", "--format", "{{json .}}")
	if err != nil {
		return nil, fmt.Errorf("failed to list Docker volumes: %w", err)
	}

	var volumes []DockerVolume
	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}

		var volData struct {
			Name       string `json:"Name"`
			Driver     string `json:"Driver"`
			Mountpoint string `json:"Mountpoint"`
		}

		if err := json.Unmarshal([]byte(line), &volData); err != nil {
			logger.Warn("Failed to parse volume data",
				zap.String("line", line),
				zap.Error(err))
			continue
		}

		volume := DockerVolume{
			Name:   volData.Name,
			Driver: volData.Driver,
		}

		// Get detailed volume info
		inspectOutput, err := i.runCommand("docker", "volume", "inspect", volData.Name)
		if err == nil {
			var inspectData []struct {
				Mountpoint string            `json:"Mountpoint"`
				Labels     map[string]string `json:"Labels"`
			}
			if err := json.Unmarshal([]byte(inspectOutput), &inspectData); err == nil && len(inspectData) > 0 {
				volume.MountPoint = inspectData[0].Mountpoint
				volume.Labels = inspectData[0].Labels
			}
		}

		volumes = append(volumes, volume)
	}

	return volumes, nil
}

// discoverComposeFiles finds docker compose files in standard locations.
// Uses properly grouped find arguments and guards against oversized files.
//
//nolint:unparam // error return maintains consistent interface with other discover* methods
func (i *Inspector) discoverComposeFiles() ([]ComposeFile, error) {
	logger := otelzap.Ctx(i.rc.Ctx)
	var composeFiles []ComposeFile

	for _, basePath := range ComposeSearchPaths {
		// Check the search path exists before running find
		if _, err := os.Stat(basePath); os.IsNotExist(err) {
			continue
		}

		// Build find arguments with proper grouping:
		//   find /path -type f \( -name "X" -o -name "Y" \)
		// The -type f BEFORE the group ensures only files are matched.
		// Shell redirection (2>/dev/null) is NOT passed as an argument.
		args := []string{basePath, "-type", "f", "("}
		for idx, name := range ComposeFileNames {
			if idx > 0 {
				args = append(args, "-o")
			}
			args = append(args, "-name", name)
		}
		args = append(args, ")")

		output, err := i.runCommand("find", args...)
		if err != nil {
			logger.Debug("Compose file search failed for path",
				zap.String("path", basePath),
				zap.Error(err))
			continue
		}

		for _, path := range strings.Split(output, "\n") {
			if path == "" {
				continue
			}

			cf, err := i.readComposeFile(path)
			if err != nil {
				logger.Warn("Failed to read compose file",
					zap.String("path", path),
					zap.Error(err))
				continue
			}
			composeFiles = append(composeFiles, *cf)
		}
	}

	return composeFiles, nil
}

// readComposeFile reads and parses a single compose file with size guard.
func (i *Inspector) readComposeFile(path string) (*ComposeFile, error) {
	// Guard: check file size before reading to prevent OOM
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat compose file %s: %w", path, err)
	}
	if info.Size() > MaxComposeFileSize {
		return nil, fmt.Errorf("compose file %s exceeds maximum size (%d bytes > %d bytes)",
			path, info.Size(), MaxComposeFileSize)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read compose file %s: %w", path, err)
	}

	composeFile := &ComposeFile{
		Path: path,
	}

	var composeData map[string]any
	if err := yaml.Unmarshal(content, &composeData); err != nil {
		return nil, fmt.Errorf("failed to parse compose file %s: %w", path, err)
	}

	if services, ok := composeData["services"].(map[string]any); ok {
		composeFile.Services = services
	}

	return composeFile, nil
}

// ParseDockerSize converts Docker's human-readable sizes to bytes.
// Docker uses SI/decimal units (1 kB = 1000 B, 1 MB = 1000 kB, etc.)
// per the Docker source: github.com/docker/go-units.
// This is a pure function exported for testability.
func ParseDockerSize(size string) (int64, error) {
	size = strings.TrimSpace(size)
	if size == "" {
		return 0, nil
	}

	// Remove spaces between number and unit
	size = strings.ReplaceAll(size, " ", "")

	// Docker uses SI (decimal) units, not binary (IEC).
	// Reference: https://pkg.go.dev/github.com/docker/go-units#FromHumanSize
	type unitDef struct {
		suffix     string
		multiplier float64
	}

	// Order matters: check longer suffixes first to avoid prefix collisions
	// (e.g., "GB" before "B").
	units := []unitDef{
		{"TB", 1e12},
		{"GB", 1e9},
		{"MB", 1e6},
		{"kB", 1e3},
		{"KB", 1e3}, // Accept uppercase K as alias
		{"B", 1},
	}

	for _, u := range units {
		if strings.HasSuffix(size, u.suffix) {
			numStr := strings.TrimSuffix(size, u.suffix)
			var num float64
			if _, err := fmt.Sscanf(numStr, "%f", &num); err != nil {
				return 0, fmt.Errorf("failed to parse numeric part of size %q: %w", size, err)
			}
			if num < 0 {
				return 0, fmt.Errorf("negative size not allowed: %q", size)
			}
			return int64(num * u.multiplier), nil
		}
	}

	// No recognised unit suffix — assume raw bytes, but require
	// the entire string to be a valid number (reject trailing garbage).
	num, err := strconv.ParseFloat(size, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse size %q: %w", size, err)
	}
	if num < 0 {
		return 0, fmt.Errorf("negative size not allowed: %q", size)
	}
	return int64(num), nil
}
