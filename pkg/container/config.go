// pkg/docker/config.go
package container

import (
	"fmt"
	"strings"
)

type ComposeFile struct {
	Services map[string]Service     `yaml:"services"`
	Volumes  map[string]interface{} `yaml:"volumes,omitempty"`
	Networks map[string]interface{} `yaml:"networks,omitempty"`
}

type Service struct {
	Image         string            `yaml:"image"`
	ContainerName string            `yaml:"container_name"`
	Ports         []string          `yaml:"ports,omitempty"`       // Maps "ports" section
	Environment   map[string]string `yaml:"environment,omitempty"` // Maps "environment" section
	Volumes       []string          `yaml:"volumes,omitempty"`     // Maps "volumes" section
	DependsOn     []string          `yaml:"depends_on,omitempty"`  // Maps "depends_on" section
	Restart       string            `yaml:"restart,omitempty"`     // Maps "restart" section
	Networks      []string          `yaml:"networks,omitempty"`    // Maps "networks" section
}

// ------------------ Shared Docker config constants ------------------ //

const (
	DockerNetworkName = "arachne-net"
	DockerIPv4Subnet  = "172.30.0.0/16"
	DockerIPv6Subnet  = "fd00:dead:beef::/64"
)

// ValidateVolumeMapping validates a volume mapping string for security
func ValidateVolumeMapping(volumeMapping string) error {
	if volumeMapping == "" {
		return fmt.Errorf("volume mapping cannot be empty")
	}

	// Check for null bytes and control characters
	if strings.ContainsAny(volumeMapping, "\x00\n\r\t") {
		return fmt.Errorf("volume mapping cannot contain null bytes or control characters")
	}

	// Check for command injection patterns
	if strings.ContainsAny(volumeMapping, ";|&`$(){}[]") {
		return fmt.Errorf("volume mapping contains command injection patterns")
	}

	// Parse the volume mapping
	parts := strings.Split(volumeMapping, ":")
	if len(parts) < 2 {
		// Named volume - less security concerns
		return nil
	}

	hostPath := parts[0]

	// Validate host path
	if err := validateHostPath(hostPath); err != nil {
		return fmt.Errorf("invalid host path: %w", err)
	}

	return nil
}

// validateHostPath validates a host path for volume mounting
func validateHostPath(path string) error {
	// Check for path traversal
	if strings.Contains(path, "..") {
		return fmt.Errorf("host path cannot contain '..' (path traversal)")
	}

	// Check for sensitive system paths
	sensitivePaths := []string{
		"/", "/etc", "/boot", "/dev", "/proc", "/sys", "/root",
		"/var/run/docker.sock", "/etc/passwd", "/etc/shadow",
		"/etc/sudoers", "/etc/ssh", "/home", "/usr/bin", "/bin",
	}

	// Clean and check against sensitive paths
	cleanPath := strings.TrimSuffix(path, "/")
	for _, sensitive := range sensitivePaths {
		if cleanPath == sensitive || strings.HasPrefix(cleanPath, sensitive+"/") {
			return fmt.Errorf("cannot mount sensitive system path: %s", sensitive)
		}
	}

	return nil
}

// ValidateContainerName validates a container name for security
func ValidateContainerName(name string) error {
	if name == "" {
		return fmt.Errorf("container name cannot be empty")
	}

	// Check for null bytes and control characters
	if strings.ContainsAny(name, "\x00\n\r\t") {
		return fmt.Errorf("container name cannot contain null bytes or control characters")
	}

	// Check for command injection patterns
	if strings.ContainsAny(name, ";|&`$(){}[]<>\"'") {
		return fmt.Errorf("container name contains invalid characters")
	}

	// Check length limit
	if len(name) > 255 {
		return fmt.Errorf("container name too long (max 255 characters)")
	}

	return nil
}

// ValidateServiceName validates a Docker Compose service name
func ValidateServiceName(name string) error {
	if name == "" {
		return fmt.Errorf("service name cannot be empty")
	}

	// Check for null bytes and control characters
	if strings.ContainsAny(name, "\x00\n\r\t") {
		return fmt.Errorf("service name cannot contain null bytes or control characters")
	}

	// Check for command injection patterns
	if strings.ContainsAny(name, ";|&`$(){}[]<>\"'") {
		return fmt.Errorf("service name contains invalid characters")
	}

	// Check length limit
	if len(name) > 255 {
		return fmt.Errorf("service name too long (max 255 characters)")
	}

	return nil
}
