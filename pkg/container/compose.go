// pkg/docker/compose.go

package container

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	cerr "github.com/cockroachdb/errors"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"gopkg.in/yaml.v3"
)

const (
	// SECURITY: Maximum docker-compose file size to prevent resource exhaustion
	MaxComposeFileSize = 5 * 1024 * 1024 // 5MB
)

// UncommentSegment finds the marker (e.g. "uncomment if using Jenkins behind Hecate")
// in the docker compose file ("docker-compose.yml") and uncomments every line (removes a leading '#')
// until reaching the line that contains "# <- finish". It returns an error if something goes wrong.
func UncommentSegment(segmentComment string) error {
	dockerComposePath := "docker-compose.yml"
	inputFile, err := os.Open(dockerComposePath)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", dockerComposePath, err)
	}
	defer func() {
		if cerr := inputFile.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "failed to close input file: %v\n", cerr)
		}
	}()

	var lines []string
	scanner := bufio.NewScanner(inputFile)
	uncommenting := false
	re := regexp.MustCompile(`^(\s*)#\s*(.*)$`) // compile once

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, segmentComment) {
			uncommenting = true
		}
		if uncommenting && strings.Contains(line, "<- finish") {
			lines = append(lines, line)
			uncommenting = false
			continue
		}
		if uncommenting && re.MatchString(line) {
			line = re.ReplaceAllString(line, "$1$2")
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file %s: %w", dockerComposePath, err)
	}

	outputFile, err := os.Create(dockerComposePath)
	if err != nil {
		return fmt.Errorf("failed to open file for writing %s: %w", dockerComposePath, err)
	}
	defer func() {
		if cerr := outputFile.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "failed to close output file: %v\n", cerr)
		}
	}()

	for _, l := range lines {
		if _, err := fmt.Fprintln(outputFile, l); err != nil {
			return fmt.Errorf("failed writing to file %s: %w", dockerComposePath, err)
		}
	}

	return nil
}

// RunDockerComposeAllServices starts a specific service from a docker compose file.
func RunDockerComposeAllServices(composeFile, service string) error {
	args := []string{"-f", composeFile, "up", "-d"}
	cmd, err := GetDockerComposeCmd(args...)
	if err != nil {
		return err
	}
	output, err := cmd.CombinedOutput()
	fmt.Println(string(output))
	if err != nil {
		return fmt.Errorf("docker compose up failed: %s", output)
	}
	return nil
}

// GetDockerComposeCmd returns an *exec.Cmd for running Docker Compose commands.
// It first checks for "docker-compose". If not found, it falls back to "docker compose".
// The provided args should include the subcommands (e.g. "-f", "docker-compose.yaml", "up", "-d").
func GetDockerComposeCmd(args ...string) (*exec.Cmd, error) {
	if _, err := exec.LookPath("docker-compose"); err == nil {
		return exec.Command("docker-compose", args...), nil
	}
	if _, err := exec.LookPath("docker"); err == nil {
		fullArgs := append([]string{"compose"}, args...)
		return exec.Command("docker", fullArgs...), nil
	}
	return nil, fmt.Errorf("neither docker compose nor docker CLI with compose plugin found in PATH")
}

func FindDockerComposeFile() (string, error) {
	filesToCheck := []string{
		"docker-compose.yaml",
		"docker-compose.yml",
	}

	for _, file := range filesToCheck {
		if _, err := os.Stat(file); err == nil {
			// Found a file that exists
			return file, nil
		}
	}
	return "", fmt.Errorf("could not find docker-compose.yaml or docker-compose.yml")
}

// ParseComposeFile attempts to read and parse the docker compose file.
// It returns the file contents as a byte slice.
func ParseComposeFile(composePath string) ([]byte, error) {
	// SECURITY: Check file size before reading to prevent resource exhaustion
	fileInfo, err := os.Stat(composePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat %s: %w", composePath, err)
	}

	if fileInfo.Size() > MaxComposeFileSize {
		return nil, fmt.Errorf("compose file too large: %d bytes (max %d)", fileInfo.Size(), MaxComposeFileSize)
	}

	data, err := os.ReadFile(composePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", composePath, err)
	}

	// SECURITY: Validate YAML structure before returning
	var cfg ComposeConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid docker-compose.yml structure: %w", err)
	}

	return data, nil
}

// ExtractComposeMetadata parses docker compose metadata from the file data.
// SECURITY: Validates image sources against allowed registries.
func ExtractComposeMetadata(data []byte) ([]string, []string, []string, error) {
	var cfg ComposeConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse compose config: %w", err)
	}

	// SECURITY: Whitelist of allowed container registries
	allowedRegistries := []string{
		"docker.io/",
		"ghcr.io/",
		"registry.gitlab.com/",
		"quay.io/",
		"gcr.io/",
		"registry.hub.docker.com/",
	}

	var containers, images, volumes []string

	for name, service := range cfg.Services {
		containers = append(containers, name)

		// SECURITY: Validate image source against whitelist
		imageValid := false
		for _, registry := range allowedRegistries {
			// Allow images without registry prefix (official Docker images)
			if !strings.Contains(service.Image, "/") {
				imageValid = true
				break
			}
			// Check if image starts with allowed registry
			if strings.HasPrefix(service.Image, registry) {
				imageValid = true
				break
			}
		}

		if !imageValid {
			return nil, nil, nil, fmt.Errorf("untrusted image registry: %s (allowed: %v)", service.Image, allowedRegistries)
		}

		images = append(images, service.Image)
	}

	for volName := range cfg.Volumes {
		volumes = append(volumes, volName)
	}

	return containers, images, volumes, nil
}

func ComposeUp(rc *eos_io.RuntimeContext, path string) error {
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "-f", path, "up", "-d"},
		// Context already passed via rc.Ctx in Run() call above
	})
	return cerr.WithHint(err, "Failed to run docker compose up")
}

type ComposeService struct {
	Image   string   `yaml:"image"`
	Ports   []string `yaml:"ports"`
	Volumes []string `yaml:"volumes"`
	Env     []string `yaml:"environment"`
}

type ComposeConfig struct {
	Services map[string]ComposeService `yaml:"services"`
	Volumes  map[string]interface{}    `yaml:"volumes"`
	Networks map[string]interface{}    `yaml:"networks"`
}

func ComposeUpInDir(rc *eos_io.RuntimeContext, dir string) error {
	yamlPath := filepath.Join(dir, "docker-compose.yml")
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		return fmt.Errorf("read compose file: %w", err)
	}

	var cfg ComposeConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse yaml: %w", err)
	}

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("init docker client: %w", err)
	}

	// Step 1: Create networks
	for netName := range cfg.Networks {
		opts := network.CreateOptions{
			Driver:     "bridge",
			EnableIPv6: nil,
			EnableIPv4: nil,
			// Optionally fill in IPAM, DNS, etc.
		}
		if _, err := cli.NetworkCreate(rc.Ctx, netName, opts); err != nil {
			return fmt.Errorf("create network %s: %w", netName, err)
		}
	}

	// Step 2: Create volumes
	for volName := range cfg.Volumes {
		volReq := volume.CreateOptions{
			Name:       volName,
			Driver:     "",
			DriverOpts: nil,
			Labels:     nil,
		}
		if _, err := cli.VolumeCreate(rc.Ctx, volReq); err != nil {
			return fmt.Errorf("create volume %s: %w", volName, err)
		}
	}

	// Step 3: Create & start containers
	for svcName, svc := range cfg.Services {
		portSet := nat.PortSet{}
		portMap := nat.PortMap{}
		for _, b := range svc.Ports {
			parts := strings.SplitN(b, ":", 2)
			hostPort, containerPort := parts[0], parts[1]
			p := nat.Port(containerPort + "/tcp")
			portSet[p] = struct{}{}
			portMap[p] = []nat.PortBinding{{HostPort: hostPort}}
		}

		contCfg := &container.Config{
			Image:        svc.Image,
			Env:          svc.Env,
			ExposedPorts: portSet,
		}
		hostCfg := &container.HostConfig{
			Binds:        svc.Volumes,
			PortBindings: portMap,
		}

		resp, err := cli.ContainerCreate(rc.Ctx, contCfg, hostCfg, &network.NetworkingConfig{}, nil, svcName)
		if err != nil {
			return fmt.Errorf("create container %s: %w", svcName, err)
		}

		if err := cli.ContainerStart(rc.Ctx, resp.ID, container.StartOptions{}); err != nil {
			return fmt.Errorf("start container %s: %w", svcName, err)
		}
	}

	return nil
}
