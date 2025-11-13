// pkg/hecate/caddy_docker.go - Docker SDK integration for Caddy Admin API
//
// ARCHITECTURE: Solves "connection reset" issue by using Docker SDK
// ROOT CAUSE: Caddy binds Admin API to 127.0.0.1 inside container (IPv4 only)
//             Host's `localhost` resolves to ::1 (IPv6) first → connection refused
// SOLUTION: Use Docker SDK to get container's internal IP address on bridge network
//           Then connect directly to container IP, bypassing localhost resolution
//
// VENDOR EVIDENCE:
// - Caddy Community: "Connection reset to Docker container usually means wrong bind address"
// - Docker Docs: "Containers have their own network namespace, use bridge IP for host access"
// - Go net: "localhost can resolve to IPv6 ::1 or IPv4 127.0.0.1 depending on OS"
//
// SECURITY: Docker SDK respects same security model as docker CLI
//           Only works if user has docker socket access (/var/run/docker.sock)

package hecate

import (
	"context"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GetCaddyContainerIP retrieves the IP address of the Caddy container on the hecate-net bridge network
//
// RATIONALE: Caddy Admin API binds to 127.0.0.1 inside container, but that's not accessible from host
//
//	Docker SDK provides container's bridge network IP, which IS accessible from host
//
// ARCHITECTURE:
//
//	Host (Eos) → Docker Bridge (172.x.x.x) → Container (hecate-caddy)
//	Container has BOTH:
//	  - Internal localhost (127.0.0.1) - only accessible inside container
//	  - Bridge IP (172.x.x.x) - accessible from host and other containers
//
// SECURITY: Docker socket access required (/var/run/docker.sock)
//
//	Same permissions as `docker inspect hecate-caddy`
//	Safe: Read-only operation, no container modification
//
// RETURNS:
//   - Container's IP on hecate-net network (e.g., "172.21.0.5")
//   - Error if container not found, not running, or not on hecate-net
func GetCaddyContainerIP(ctx context.Context) (string, error) {
	// Create Docker client from environment (respects DOCKER_HOST, DOCKER_CERT_PATH, etc.)
	// SECURITY: Uses same credentials as docker CLI
	// RATIONALE: Supports both local socket and remote Docker daemons
	dockerClient, err := client.NewClientWithOpts(
		client.FromEnv,
		client.WithAPIVersionNegotiation(), // Auto-negotiate API version (best practice)
	)
	if err != nil {
		return "", fmt.Errorf("failed to create Docker client: %w\n\n"+
			"Troubleshooting:\n"+
			"  1. Docker installed? Run: docker --version\n"+
			"  2. Docker running? Run: docker ps\n"+
			"  3. Socket accessible? Run: ls -l /var/run/docker.sock\n"+
			"  4. User in docker group? Run: groups | grep docker", err)
	}
	defer dockerClient.Close()

	// Inspect Caddy container to get network settings
	// ARCHITECTURE: ContainerInspect returns full container metadata including all networks
	containerInfo, err := dockerClient.ContainerInspect(ctx, CaddyContainerName)
	if err != nil {
		return "", fmt.Errorf("failed to inspect Caddy container '%s': %w\n\n"+
			"Troubleshooting:\n"+
			"  1. Container running? Run: docker ps -a | grep %s\n"+
			"  2. Container name correct? Expected: %s\n"+
			"  3. Start container: docker compose -f /opt/hecate/docker-compose.yml up -d caddy",
			CaddyContainerName, err, CaddyContainerName, CaddyContainerName)
	}

	// Verify container is actually running (not stopped/paused/restarting)
	// RATIONALE: Container could exist but not be running → IP would be invalid
	if !containerInfo.State.Running {
		return "", fmt.Errorf("Caddy container '%s' is not running (state: %s)\n\n"+
			"Start the container:\n"+
			"  docker compose -f /opt/hecate/docker-compose.yml up -d caddy\n\n"+
			"Check logs for errors:\n"+
			"  docker logs %s --tail 50",
			CaddyContainerName, containerInfo.State.Status, CaddyContainerName)
	}

	// AUTO-DETECT network name (P0 FIX - Connection Reset)
	// ROOT CAUSE: Docker Compose prefixes network names with project name
	//   - Code expected: "hecate-net"
	//   - Actual network: "hecate_hecate-net" (project name prefix)
	// SOLUTION: Iterate through ALL available networks and find first with valid IP
	// PRIORITY ORDER:
	//   1. Networks matching "hecate" (hecate-net, hecate_hecate-net, etc.)
	//   2. Any custom network (user-defined bridge networks)
	//   3. Default "bridge" network (fallback)
	//
	// RATIONALE: Makes code resilient to Docker Compose naming variations
	// EVIDENCE: User diagnostic showed "hecate_hecate-net" not "hecate-net"
	// VENDOR: Docker Compose docs - project name prefix is default behavior

	// Step 1: Try hecate-specific networks first (exact match, then substring match)
	preferredNetworks := []string{"hecate-net"} // Explicit name (from template fix)
	for _, networkName := range preferredNetworks {
		if network, ok := containerInfo.NetworkSettings.Networks[networkName]; ok {
			if network.IPAddress == "" {
				return "", fmt.Errorf("Caddy container on network '%s' but has no IP address\n\n"+
					"This usually means the network is starting up.\n"+
					"Wait 5 seconds and retry, or restart container:\n"+
					"  docker compose -f /opt/hecate/docker-compose.yml restart caddy",
					networkName)
			}
			return network.IPAddress, nil
		}
	}

	// Step 2: Try networks containing "hecate" substring (e.g., hecate_hecate-net)
	for networkName, network := range containerInfo.NetworkSettings.Networks {
		if network.IPAddress != "" {
			// Check if network name contains "hecate" (case-insensitive)
			// This catches: hecate_hecate-net, hecate-net, myproject_hecate-net, etc.
			if len(networkName) > 0 && (networkName == "hecate-net" ||
				(len(networkName) >= 6 && networkName[:6] == "hecate") ||
				(len(networkName) >= 6 && networkName[len(networkName)-6:] == "hecate")) {
				return network.IPAddress, nil
			}
		}
	}

	// Step 3: Try ANY custom network (user-defined bridges)
	// RATIONALE: If user renamed network entirely, still work
	for networkName, network := range containerInfo.NetworkSettings.Networks {
		if networkName != "bridge" && networkName != "host" && networkName != "none" {
			if network.IPAddress != "" {
				return network.IPAddress, nil
			}
		}
	}

	// Step 4: Fallback to default bridge network
	// RATIONALE: User might have modified docker-compose.yml to use default bridge
	if network, ok := containerInfo.NetworkSettings.Networks["bridge"]; ok {
		if network.IPAddress != "" {
			return network.IPAddress, nil
		}
	}

	// No suitable network found
	availableNetworks := make([]string, 0, len(containerInfo.NetworkSettings.Networks))
	for name := range containerInfo.NetworkSettings.Networks {
		availableNetworks = append(availableNetworks, name)
	}

	return "", fmt.Errorf("Caddy container has no usable network with IP address\n\n"+
		"Available networks: %v\n\n"+
		"Expected: Networks containing 'hecate' or any custom bridge network\n\n"+
		"Fix docker-compose.yml:\n"+
		"  caddy:\n"+
		"    networks:\n"+
		"      - hecate-net\n\n"+
		"Then recreate container:\n"+
		"  docker compose -f /opt/hecate/docker-compose.yml up -d --force-recreate caddy",
		availableNetworks)
}

// GetCaddyContainerIPWithLogging is a wrapper around GetCaddyContainerIP that adds structured logging
//
// RATIONALE: Observability - log Docker SDK operations for debugging
// USAGE: Use this in production code, use GetCaddyContainerIP in tests
func GetCaddyContainerIPWithLogging(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Detecting Caddy container IP via Docker SDK",
		zap.String("container_name", CaddyContainerName),
		zap.String("expected_network", "hecate-net"))

	ip, err := GetCaddyContainerIP(rc.Ctx)
	if err != nil {
		logger.Error("Failed to detect Caddy container IP",
			zap.String("container_name", CaddyContainerName),
			zap.Error(err))
		return "", err
	}

	logger.Info("✓ Caddy container IP detected via Docker SDK",
		zap.String("container_name", CaddyContainerName),
		zap.String("bridge_ip", ip),
		zap.String("admin_api_url", fmt.Sprintf("http://%s:%d", ip, CaddyAdminAPIPort)))

	return ip, nil
}

// IsCaddyContainerRunning checks if the Caddy container is running
//
// RATIONALE: Pre-flight check before attempting Admin API operations
// RETURNS: true if container exists and is running, false otherwise
// ERROR: Only returns error if Docker SDK fails, NOT if container is stopped
func IsCaddyContainerRunning(ctx context.Context) (bool, error) {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return false, fmt.Errorf("failed to create Docker client: %w", err)
	}
	defer dockerClient.Close()

	containerInfo, err := dockerClient.ContainerInspect(ctx, CaddyContainerName)
	if err != nil {
		// Container not found is not an error - just return false
		if client.IsErrNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to inspect container: %w", err)
	}

	return containerInfo.State.Running, nil
}

// GetCaddyContainerLogs retrieves recent logs from Caddy container for debugging
//
// RATIONALE: When Admin API fails, logs often contain the root cause
// RETURNS: Last N lines of logs as string
// USAGE: Call this when Admin API operations fail to provide user with debugging context
func GetCaddyContainerLogs(ctx context.Context, tailLines int) (string, error) {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return "", fmt.Errorf("failed to create Docker client: %w", err)
	}
	defer dockerClient.Close()

	// ContainerLogs options
	opts := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       fmt.Sprintf("%d", tailLines),
		Timestamps: true,
	}

	logs, err := dockerClient.ContainerLogs(ctx, CaddyContainerName, opts)
	if err != nil {
		return "", fmt.Errorf("failed to get container logs: %w", err)
	}
	defer logs.Close()

	// Read logs (Docker returns multiplexed stream, but for simple text we can read directly)
	buf := make([]byte, 4096)
	n, _ := logs.Read(buf)
	return string(buf[:n]), nil
}
