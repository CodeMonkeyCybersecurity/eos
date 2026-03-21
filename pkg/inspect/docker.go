// Package inspect provides infrastructure discovery and audit capabilities
// for Docker, KVM, Hetzner Cloud, and system services.
package inspect

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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

	// ComposeSearchMaxDepth limits how deep filepath.WalkDir recurses.
	// RATIONALE: Prevents traversal of deeply nested directories (e.g. node_modules).
	ComposeSearchMaxDepth = 5

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

// composeFileNameSet is a pre-computed lookup set for O(1) compose file matching.
var composeFileNameSet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(ComposeFileNames))
	for _, name := range ComposeFileNames {
		m[name] = struct{}{}
	}
	return m
}()

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

	// Discover networks (batched inspect for performance)
	if networks, err := i.discoverNetworks(); err != nil {
		logger.Warn("Failed to discover networks", zap.Error(err))
	} else {
		info.Networks = networks
		logger.Info("Discovered networks", zap.Int("count", len(networks)))
	}

	// Discover volumes (batched inspect for performance)
	if volumes, err := i.discoverVolumes(); err != nil {
		logger.Warn("Failed to discover volumes", zap.Error(err))
	} else {
		info.Volumes = volumes
		logger.Info("Discovered volumes", zap.Int("count", len(volumes)))
	}

	// Discover compose files (uses filepath.WalkDir, no shell dependency)
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
// Runs exactly 2 commands (ps + inspect) instead of N+1.
func (i *Inspector) discoverContainers() ([]DockerContainer, error) {
	logger := otelzap.Ctx(i.rc.Ctx)

	output, err := i.runCommand("docker", "ps", "-aq", "--no-trunc")
	if err != nil {
		return nil, fmt.Errorf("failed to list container IDs: %w", err)
	}
	if output == "" {
		return nil, nil
	}

	ids := splitNonEmpty(output)
	if len(ids) == 0 {
		return nil, nil
	}

	// Batch inspect: "docker inspect id1 id2 id3 ..." in one exec
	args := make([]string, 0, 1+len(ids))
	args = append(args, "inspect")
	args = append(args, ids...)

	inspectOutput, err := i.runCommand("docker", args...)
	if err != nil {
		logger.Warn("Batched container inspect failed, falling back to individual inspect",
			zap.Int("container_count", len(ids)),
			zap.Error(err))
		return i.discoverContainersFallback(ids)
	}

	containers, parseErr := parseContainerInspectJSON(inspectOutput)
	if parseErr != nil {
		logger.Warn("Failed to parse batched container inspect data", zap.Error(parseErr))
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
				zap.String("id", id), zap.Error(err))
			continue
		}
		parsed, parseErr := parseContainerInspectJSON(inspectOutput)
		if parseErr != nil {
			logger.Warn("Failed to parse container inspect data",
				zap.String("id", id), zap.Error(parseErr))
			continue
		}
		containers = append(containers, parsed...)
	}

	return containers, nil
}

// parseContainerInspectJSON parses the JSON output from docker inspect into
// DockerContainer structs. Pure function for testability.
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

		if t, err := time.Parse(time.RFC3339Nano, data.Created); err == nil {
			container.Created = t
		}

		container.Environment = parseEnvVars(data.Config.Env)

		if len(data.Config.Cmd) > 0 {
			container.Command = strings.Join(data.Config.Cmd, " ")
		}

		for network := range data.NetworkSettings.Networks {
			container.Networks = append(container.Networks, network)
		}
		sort.Strings(container.Networks)

		for port, bindings := range data.NetworkSettings.Ports {
			for _, binding := range bindings {
				portStr := fmt.Sprintf("%s:%s->%s", binding.HostIP, binding.HostPort, port)
				container.Ports = append(container.Ports, portStr)
			}
		}
		sort.Strings(container.Ports)

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
// sensitive values. Pure function for testability.
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
				zap.String("line", line), zap.Error(err))
			continue
		}

		image := DockerImage{ID: imageData.ID}

		if imageData.Repository != "<none>" {
			tag := imageData.Tag
			if tag == "<none>" {
				tag = "latest"
			}
			image.RepoTags = []string{fmt.Sprintf("%s:%s", imageData.Repository, tag)}
		}

		if sizeBytes, err := ParseDockerSize(imageData.Size); err == nil {
			image.Size = sizeBytes
		}

		if t, err := time.Parse("2006-01-02 15:04:05 -0700 MST", imageData.CreatedAt); err == nil {
			image.Created = t
		}

		images = append(images, image)
	}

	return images, nil
}

// networkInspectData is the struct for unmarshalling docker network inspect JSON.
type networkInspectData struct {
	ID     string            `json:"Id"`
	Name   string            `json:"Name"`
	Driver string            `json:"Driver"`
	Scope  string            `json:"Scope"`
	Labels map[string]string `json:"Labels"`
}

// discoverNetworks discovers Docker networks using batched inspect.
// Runs exactly 2 commands (ls + inspect) instead of N+1.
func (i *Inspector) discoverNetworks() ([]DockerNetwork, error) {
	logger := otelzap.Ctx(i.rc.Ctx)

	output, err := i.runCommand("docker", "network", "ls", "--format", "{{.ID}}")
	if err != nil {
		return nil, fmt.Errorf("failed to list Docker networks: %w", err)
	}

	ids := splitNonEmpty(output)
	if len(ids) == 0 {
		return nil, nil
	}

	args := make([]string, 0, 2+len(ids))
	args = append(args, "network", "inspect")
	args = append(args, ids...)

	inspectOutput, err := i.runCommand("docker", args...)
	if err != nil {
		logger.Warn("Batched network inspect failed", zap.Error(err))
		return nil, fmt.Errorf("failed to inspect networks: %w", err)
	}

	var inspectData []networkInspectData
	if err := json.Unmarshal([]byte(inspectOutput), &inspectData); err != nil {
		return nil, fmt.Errorf("failed to parse network inspect JSON: %w", err)
	}

	networks := make([]DockerNetwork, 0, len(inspectData))
	for _, data := range inspectData {
		networks = append(networks, DockerNetwork(data))
	}
	return networks, nil
}

// volumeInspectData is the struct for unmarshalling docker volume inspect JSON.
type volumeInspectData struct {
	Name       string            `json:"Name"`
	Driver     string            `json:"Driver"`
	Mountpoint string            `json:"Mountpoint"`
	Labels     map[string]string `json:"Labels"`
}

// discoverVolumes discovers Docker volumes using batched inspect.
// Runs exactly 2 commands (ls + inspect) instead of N+1.
func (i *Inspector) discoverVolumes() ([]DockerVolume, error) {
	logger := otelzap.Ctx(i.rc.Ctx)

	output, err := i.runCommand("docker", "volume", "ls", "--format", "{{.Name}}")
	if err != nil {
		return nil, fmt.Errorf("failed to list Docker volumes: %w", err)
	}

	names := splitNonEmpty(output)
	if len(names) == 0 {
		return nil, nil
	}

	args := make([]string, 0, 2+len(names))
	args = append(args, "volume", "inspect")
	args = append(args, names...)

	inspectOutput, err := i.runCommand("docker", args...)
	if err != nil {
		logger.Warn("Batched volume inspect failed", zap.Error(err))
		return nil, fmt.Errorf("failed to inspect volumes: %w", err)
	}

	var inspectData []volumeInspectData
	if err := json.Unmarshal([]byte(inspectOutput), &inspectData); err != nil {
		return nil, fmt.Errorf("failed to parse volume inspect JSON: %w", err)
	}

	volumes := make([]DockerVolume, 0, len(inspectData))
	for _, data := range inspectData {
		volumes = append(volumes, DockerVolume{
			Name:       data.Name,
			Driver:     data.Driver,
			MountPoint: data.Mountpoint,
			Labels:     data.Labels,
		})
	}
	return volumes, nil
}

// discoverComposeFiles finds docker compose files using filepath.WalkDir.
// This replaces the previous shell `find` approach for portability and testability.
// Depth is limited to ComposeSearchMaxDepth to avoid traversing node_modules etc.
//
//nolint:unparam // error return maintains consistent interface with other discover* methods
func (i *Inspector) discoverComposeFiles() ([]ComposeFile, error) {
	logger := otelzap.Ctx(i.rc.Ctx)
	var composeFiles []ComposeFile

	for _, basePath := range ComposeSearchPaths {
		if _, err := os.Stat(basePath); os.IsNotExist(err) {
			continue
		}

		baseDepth := strings.Count(filepath.Clean(basePath), string(os.PathSeparator))

		err := filepath.WalkDir(basePath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				// Permission denied or similar — skip this subtree
				return filepath.SkipDir
			}

			// Enforce max depth
			currentDepth := strings.Count(filepath.Clean(path), string(os.PathSeparator))
			if d.IsDir() && (currentDepth-baseDepth) >= ComposeSearchMaxDepth {
				return filepath.SkipDir
			}

			if d.IsDir() {
				return nil
			}

			// Skip symlinks to avoid traversal into unexpected locations
			if d.Type()&fs.ModeSymlink != 0 {
				return nil
			}

			if _, ok := composeFileNameSet[d.Name()]; !ok {
				return nil
			}

			cf, readErr := readComposeFile(path)
			if readErr != nil {
				logger.Warn("Failed to read compose file",
					zap.String("path", path), zap.Error(readErr))
				return nil
			}
			composeFiles = append(composeFiles, *cf)
			return nil
		})

		if err != nil {
			logger.Debug("Compose file search failed for path",
				zap.String("path", basePath), zap.Error(err))
		}
	}

	return composeFiles, nil
}

// readComposeFile reads and parses a single compose file with size guard.
// Pure function (no Inspector receiver) for testability.
func readComposeFile(path string) (*ComposeFile, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat compose file %s: %w", path, err)
	}
	// Reject symlinks at read time as an additional safety measure
	if info.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("compose file %s is a symlink (rejected for security)", path)
	}
	if info.Size() > MaxComposeFileSize {
		return nil, fmt.Errorf("compose file %s exceeds maximum size (%d bytes > %d bytes)",
			path, info.Size(), MaxComposeFileSize)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read compose file %s: %w", path, err)
	}

	composeFile := &ComposeFile{Path: path}

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
// Pure function exported for testability.
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

	// No recognised unit suffix — assume raw bytes
	num, err := strconv.ParseFloat(size, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse size %q: %w", size, err)
	}
	if num < 0 {
		return 0, fmt.Errorf("negative size not allowed: %q", size)
	}
	return int64(num), nil
}

// splitNonEmpty splits output by newlines and returns non-empty trimmed lines.
// DRY helper used by container, network, and volume discovery.
func splitNonEmpty(output string) []string {
	var result []string
	for _, line := range strings.Split(output, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
