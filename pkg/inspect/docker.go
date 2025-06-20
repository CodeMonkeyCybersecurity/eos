package inspect

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"gopkg.in/yaml.v3"
)

// DiscoverDocker gathers Docker infrastructure information
func (i *Inspector) DiscoverDocker() (*DockerInfo, error) {
	logger := otelzap.Ctx(i.rc.Ctx)
	logger.Debug("🐳 Starting Docker discovery")

	// Check if Docker is installed
	if !i.commandExists("docker") {
		return nil, fmt.Errorf("docker command not found")
	}

	info := &DockerInfo{}

	// Get Docker version
	if output, err := i.runCommand("docker", "version", "--format", "{{.Server.Version}}"); err == nil {
		info.Version = output
		logger.Debug("📊 Docker version detected", zap.String("version", info.Version))
	}

	// Discover containers
	if containers, err := i.discoverContainers(); err != nil {
		logger.Warn("⚠️ Failed to discover containers", zap.Error(err))
	} else {
		info.Containers = containers
		logger.Debug("📦 Discovered containers", zap.Int("count", len(containers)))
	}

	// Discover images
	if images, err := i.discoverImages(); err != nil {
		logger.Warn("⚠️ Failed to discover images", zap.Error(err))
	} else {
		info.Images = images
		logger.Debug("🖼️ Discovered images", zap.Int("count", len(images)))
	}

	// Discover networks
	if networks, err := i.discoverNetworks(); err != nil {
		logger.Warn("⚠️ Failed to discover networks", zap.Error(err))
	} else {
		info.Networks = networks
		logger.Debug("🌐 Discovered networks", zap.Int("count", len(networks)))
	}

	// Discover volumes
	if volumes, err := i.discoverVolumes(); err != nil {
		logger.Warn("⚠️ Failed to discover volumes", zap.Error(err))
	} else {
		info.Volumes = volumes
		logger.Debug("💾 Discovered volumes", zap.Int("count", len(volumes)))
	}

	// Discover compose files
	if composeFiles, err := i.discoverComposeFiles(); err != nil {
		logger.Warn("⚠️ Failed to discover compose files", zap.Error(err))
	} else {
		info.ComposeFiles = composeFiles
		logger.Debug("📄 Discovered compose files", zap.Int("count", len(composeFiles)))
	}

	logger.Debug("✅ Docker discovery completed")
	return info, nil
}

// discoverContainers discovers all Docker containers
func (i *Inspector) discoverContainers() ([]DockerContainer, error) {
	var containers []DockerContainer

	// Get container IDs
	output, err := i.runCommand("docker", "ps", "-aq")
	if err != nil {
		return nil, err
	}

	if output == "" {
		return containers, nil
	}

	containerIDs := strings.Split(output, "\n")
	
	for _, id := range containerIDs {
		if id == "" {
			continue
		}

		// Get detailed container info
		inspectOutput, err := i.runCommand("docker", "inspect", id)
		if err != nil {
			logger := otelzap.Ctx(i.rc.Ctx)
			logger.Warn("⚠️ Failed to inspect container", 
				zap.String("id", id),
				zap.Error(err))
			continue
		}

		var inspectData []struct {
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
				Networks map[string]interface{} `json:"Networks"`
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

		if err := json.Unmarshal([]byte(inspectOutput), &inspectData); err != nil {
			logger := otelzap.Ctx(i.rc.Ctx)
			logger.Warn("⚠️ Failed to parse container inspect data", 
				zap.String("id", id),
				zap.Error(err))
			continue
		}

		for _, data := range inspectData {
			container := DockerContainer{
				ID:      data.ID,
				Name:    strings.TrimPrefix(data.Name, "/"),
				Image:   data.Config.Image,
				Status:  data.State.Status,
				State:   map[bool]string{true: "running", false: "stopped"}[data.State.Running],
				Labels:  data.Config.Labels,
				Restart: data.HostConfig.RestartPolicy.Name,
			}

			// Parse created time
			if t, err := time.Parse(time.RFC3339Nano, data.Created); err == nil {
				container.Created = t
			}

			// Parse environment variables
			container.Environment = make(map[string]string)
			for _, env := range data.Config.Env {
				parts := strings.SplitN(env, "=", 2)
				if len(parts) == 2 {
					// Don't include sensitive values
					if strings.Contains(strings.ToLower(parts[0]), "password") ||
						strings.Contains(strings.ToLower(parts[0]), "secret") ||
						strings.Contains(strings.ToLower(parts[0]), "token") ||
						strings.Contains(strings.ToLower(parts[0]), "key") {
						container.Environment[parts[0]] = "***"
					} else {
						container.Environment[parts[0]] = parts[1]
					}
				}
			}

			// Parse command
			if len(data.Config.Cmd) > 0 {
				container.Command = strings.Join(data.Config.Cmd, " ")
			}

			// Parse networks
			for network := range data.NetworkSettings.Networks {
				container.Networks = append(container.Networks, network)
			}

			// Parse ports
			for port, bindings := range data.NetworkSettings.Ports {
				if bindings != nil {
					for _, binding := range bindings {
						portStr := fmt.Sprintf("%s:%s->%s", binding.HostIP, binding.HostPort, port)
						container.Ports = append(container.Ports, portStr)
					}
				}
			}

			// Parse volumes
			for _, mount := range data.Mounts {
				volStr := fmt.Sprintf("%s:%s:%s", mount.Source, mount.Destination, mount.Mode)
				container.Volumes = append(container.Volumes, volStr)
			}

			containers = append(containers, container)
		}
	}

	return containers, nil
}

// discoverImages discovers Docker images
func (i *Inspector) discoverImages() ([]DockerImage, error) {
	var images []DockerImage

	output, err := i.runCommand("docker", "images", "--format", "{{json .}}")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
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
			logger := otelzap.Ctx(i.rc.Ctx)
			logger.Warn("⚠️ Failed to parse image data", zap.Error(err))
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

		// Parse size (convert from human-readable to bytes)
		if sizeBytes, err := parseHumanSize(imageData.Size); err == nil {
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

// discoverNetworks discovers Docker networks
func (i *Inspector) discoverNetworks() ([]DockerNetwork, error) {
	var networks []DockerNetwork

	output, err := i.runCommand("docker", "network", "ls", "--format", "{{json .}}")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
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
			logger := otelzap.Ctx(i.rc.Ctx)
			logger.Warn("⚠️ Failed to parse network data", zap.Error(err))
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

// discoverVolumes discovers Docker volumes
func (i *Inspector) discoverVolumes() ([]DockerVolume, error) {
	var volumes []DockerVolume

	output, err := i.runCommand("docker", "volume", "ls", "--format", "{{json .}}")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		var volData struct {
			Name       string `json:"Name"`
			Driver     string `json:"Driver"`
			Mountpoint string `json:"Mountpoint"`
		}

		if err := json.Unmarshal([]byte(line), &volData); err != nil {
			logger := otelzap.Ctx(i.rc.Ctx)
			logger.Warn("⚠️ Failed to parse volume data", zap.Error(err))
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

// discoverComposeFiles finds docker-compose files
func (i *Inspector) discoverComposeFiles() ([]ComposeFile, error) {
	var composeFiles []ComposeFile

	// Common locations to search for compose files
	searchPaths := []string{
		"/home",
		"/root",
		"/opt",
		"/srv",
		"/var",
	}

	for _, basePath := range searchPaths {
		// Use find command to locate compose files
		output, err := i.runCommand("find", basePath, 
			"-name", "docker-compose.yml",
			"-o", "-name", "docker-compose.yaml",
			"-o", "-name", "compose.yml",
			"-o", "-name", "compose.yaml",
			"-type", "f",
			"2>/dev/null")
		
		if err != nil {
			continue
		}

		paths := strings.Split(output, "\n")
		for _, path := range paths {
			if path == "" {
				continue
			}

			composeFile := ComposeFile{
				Path: path,
			}

			// Try to read and parse the compose file
			content, err := os.ReadFile(path)
			if err != nil {
				logger := otelzap.Ctx(i.rc.Ctx)
				logger.Warn("⚠️ Failed to read compose file",
					zap.String("path", path),
					zap.Error(err))
				continue
			}

			var composeData map[string]interface{}
			if err := yaml.Unmarshal(content, &composeData); err != nil {
				logger := otelzap.Ctx(i.rc.Ctx)
				logger.Warn("⚠️ Failed to parse compose file",
					zap.String("path", path),
					zap.Error(err))
				continue
			}

			// Extract services
			if services, ok := composeData["services"].(map[string]interface{}); ok {
				composeFile.Services = services
			}

			composeFiles = append(composeFiles, composeFile)
		}
	}

	return composeFiles, nil
}

// parseHumanSize converts human-readable sizes to bytes
func parseHumanSize(size string) (int64, error) {
	size = strings.TrimSpace(size)
	if size == "" {
		return 0, nil
	}

	// Remove any spaces between number and unit
	size = strings.ReplaceAll(size, " ", "")

	var multiplier int64 = 1
	var numStr string

	if strings.HasSuffix(size, "GB") {
		multiplier = 1024 * 1024 * 1024
		numStr = strings.TrimSuffix(size, "GB")
	} else if strings.HasSuffix(size, "MB") {
		multiplier = 1024 * 1024
		numStr = strings.TrimSuffix(size, "MB")
	} else if strings.HasSuffix(size, "KB") {
		multiplier = 1024
		numStr = strings.TrimSuffix(size, "KB")
	} else if strings.HasSuffix(size, "B") {
		numStr = strings.TrimSuffix(size, "B")
	} else {
		// Assume it's already in bytes
		numStr = size
	}

	var num float64
	if _, err := fmt.Sscanf(numStr, "%f", &num); err != nil {
		return 0, fmt.Errorf("failed to parse size %s: %w", size, err)
	}

	return int64(num * float64(multiplier)), nil
}