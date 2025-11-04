// pkg/hecate/debug_caddy.go - Caddy Admin API diagnostics

package hecate

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RunCaddyAdminAPIDebug performs comprehensive Caddy Admin API diagnostics
// Diagnoses connection reset issues and Admin API connectivity
func RunCaddyAdminAPIDebug(rc *eos_io.RuntimeContext, hecatePath string, verbose bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Println("\n=========================================")
	fmt.Println("Caddy Admin API Diagnostics")
	fmt.Println("=========================================")

	logger.Info("Starting Caddy Admin API diagnostics",
		zap.String("hecate_path", hecatePath),
		zap.Bool("verbose", verbose))

	// Create Caddy Admin API client
	client := NewCaddyAdminClient(CaddyAdminAPIHost)

	// Test 1: Port Accessibility
	fmt.Println("[1/7] Checking Admin API port accessibility...")
	portAccessible := checkCaddyAdminAPIPort(logger)
	if portAccessible {
		fmt.Printf("✓ Port %s:%d is open and accepting connections\n\n", CaddyAdminAPIHost, CaddyAdminAPIPort)
	} else {
		fmt.Printf("✗ Port %s:%d is not accessible\n", CaddyAdminAPIHost, CaddyAdminAPIPort)
		fmt.Println("  Remediation:")
		fmt.Println("    • Check Caddy is running: docker compose -f /opt/hecate/docker-compose.yml ps caddy")
		fmt.Println("    • Check port mapping: docker compose port caddy 2019")
		fmt.Println("    • Check firewall: sudo ufw status | grep 2019")
		fmt.Println()
		return fmt.Errorf("Caddy Admin API port not accessible")
	}

	// Test 2: Health Endpoint (single attempt)
	fmt.Println("[2/7] Testing Admin API health endpoint...")
	healthErr := client.Health(rc.Ctx)
	if healthErr != nil {
		fmt.Printf("✗ Health check failed: %v\n", healthErr)
		logger.Warn("Admin API health check failed", zap.Error(healthErr))
		fmt.Println("  This could indicate:")
		fmt.Println("    • Caddy is starting up (wait 10 seconds and retry)")
		fmt.Println("    • Admin API is disabled in Caddyfile")
		fmt.Println("    • Permissions issue accessing Admin API")
		fmt.Println()
	} else {
		fmt.Println("✓ Health endpoint responding")
	}

	// Test 3: Health Endpoint with Retry (simulates actual usage)
	fmt.Println("[3/7] Testing health endpoint with retry logic...")
	healthRetryErr := testHealthWithRetries(rc, client, logger, 3)
	if healthRetryErr != nil {
		fmt.Printf("✗ Health check failed after 3 retries: %v\n", healthRetryErr)
		fmt.Println()
	} else {
		fmt.Println("✓ Health endpoint responding after retry")
	}

	// Test 4: Config Retrieval (single attempt)
	fmt.Println("[4/7] Testing config retrieval (single attempt)...")
	config, configErr := client.GetConfig(rc.Ctx)
	if configErr != nil {
		fmt.Printf("✗ Config retrieval failed: %v\n", configErr)
		logger.Warn("Config retrieval failed", zap.Error(configErr))

		// Analyze error type
		if strings.Contains(configErr.Error(), "connection reset") {
			fmt.Println("\n  ⚠️ CONNECTION RESET DETECTED")
			fmt.Println("  This is the error causing self-enrollment to fail!")
			fmt.Println("  Root cause: Transient network issue, NOT permanent failure")
			fmt.Println("  Solution: Retry with exponential backoff (see recommendation below)")
		}
		fmt.Println()
	} else {
		fmt.Printf("✓ Config retrieved successfully (%d bytes)\n", len(fmt.Sprintf("%v", config)))
		if verbose {
			configJSON, _ := json.MarshalIndent(config, "  ", "  ")
			fmt.Printf("  Config preview (first 500 chars):\n%s\n", string(configJSON)[:min(500, len(configJSON))])
		}
		fmt.Println()
	}

	// Test 5: Config Retrieval with Retry
	fmt.Println("[5/7] Testing config retrieval with retry logic...")
	configRetry, configRetryErr := testGetConfigWithRetries(rc, client, logger, 3)
	if configRetryErr != nil {
		fmt.Printf("✗ Config retrieval failed after 3 retries: %v\n", configRetryErr)
		fmt.Println()
	} else {
		fmt.Printf("✓ Config retrieved successfully with retry (%d top-level keys)\n", len(configRetry))
		if verbose {
			fmt.Println("  Top-level config keys:")
			for key := range configRetry {
				fmt.Printf("    - %s\n", key)
			}
		}
		fmt.Println()
	}

	// Test 6: Route Listing (tests ListAPIRoutes used by domain auto-detection)
	fmt.Println("[6/7] Testing route listing (used by domain auto-detection)...")
	routes, routesErr := ListAPIRoutes(rc)
	if routesErr != nil {
		fmt.Printf("✗ Route listing failed: %v\n", routesErr)
		logger.Warn("Route listing failed", zap.Error(routesErr))

		if strings.Contains(routesErr.Error(), "connection reset") {
			fmt.Println("\n  ⚠️ CONNECTION RESET DETECTED")
			fmt.Println("  This will cause domain auto-detection to fail!")
		}
		fmt.Println()
	} else {
		fmt.Printf("✓ Routes retrieved successfully (%d routes)\n", len(routes))
		if verbose && len(routes) > 0 {
			fmt.Println("  Routes:")
			for _, route := range routes {
				fmt.Printf("    - %s → %s\n", route.DNS, route.Backend)
			}
		}
		fmt.Println()
	}

	// Test 7: Performance Analysis
	fmt.Println("[7/7] Performance analysis (timing multiple requests)...")
	timings := performPerformanceTest(rc, client, logger, 5)

	avgDuration := time.Duration(0)
	for _, d := range timings {
		avgDuration += d
	}
	avgDuration = avgDuration / time.Duration(len(timings))

	fmt.Printf("  Requests: %d\n", len(timings))
	fmt.Printf("  Average: %v\n", avgDuration)
	fmt.Printf("  Min: %v\n", minDuration(timings))
	fmt.Printf("  Max: %v\n", maxDuration(timings))

	if avgDuration > 1*time.Second {
		fmt.Println("  ⚠️ Slow response times detected (>1s average)")
		fmt.Println("  This could cause timeouts under load")
	}
	fmt.Println()

	// Test 8: Docker SDK Container Detection
	fmt.Println("[8/13] Testing Docker SDK container detection...")
	testDockerSDKContainerDetection(rc, logger)
	fmt.Println()

	// Test 9: Container Running Status
	fmt.Println("[9/13] Checking Caddy container status...")
	testContainerRunningStatus(rc, logger)
	fmt.Println()

	// Test 10: Container Network Configuration
	fmt.Println("[10/13] Checking container network configuration...")
	testContainerNetworks(rc, logger)
	fmt.Println()

	// Test 11: Container IP Address Extraction
	fmt.Println("[11/13] Extracting container IP address...")
	testContainerIPExtraction(rc, logger)
	fmt.Println()

	// Test 12: Docker Socket Permissions
	fmt.Println("[12/13] Checking Docker socket permissions...")
	testDockerSocketPermissions(rc, logger)
	fmt.Println()

	// Test 13: Docker SDK Access Test
	fmt.Println("[13/13] Testing Docker SDK access...")
	testDockerSDKAccess(rc, logger)
	fmt.Println()

	// Summary
	fmt.Println("=========================================")
	fmt.Println("Summary & Recommendations")
	fmt.Println("=========================================")

	if configRetryErr == nil && routesErr == nil {
		fmt.Println("✅ All tests PASSED")
		fmt.Println("Caddy Admin API is healthy and responsive")
	} else {
		fmt.Println("❌ Some tests FAILED")
		fmt.Println()
		fmt.Println("Recommendations:")
		fmt.Println("1. Add retry logic with exponential backoff to Caddy Admin API client")
		fmt.Println("   Location: pkg/hecate/caddy_admin_api.go")
		fmt.Println("   Pattern: See pkg/vault/client.go for retry example")
		fmt.Println()
		fmt.Println("2. Increase timeout from 30s to 60s for slower systems")
		fmt.Println("   Location: pkg/hecate/constants.go (CaddyAdminAPITimeout)")
		fmt.Println()
		fmt.Println("3. Check Caddy container resources:")
		fmt.Println("   docker stats hecate-caddy")
		fmt.Println()
		fmt.Println("4. Check for concurrent Admin API requests:")
		fmt.Println("   docker compose -f /opt/hecate/docker-compose.yml logs caddy | grep -i admin")
	}

	fmt.Println()
	return nil
}

// checkCaddyAdminAPIPort checks if the Admin API port is accessible
func checkCaddyAdminAPIPort(logger otelzap.LoggerWithCtx) bool {
	address := net.JoinHostPort(CaddyAdminAPIHost, strconv.Itoa(CaddyAdminAPIPort))
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		logger.Debug("Port check failed", zap.String("address", address), zap.Error(err))
		return false
	}
	defer conn.Close()
	return true
}

// testHealthWithRetries tests health endpoint with retry logic
func testHealthWithRetries(rc *eos_io.RuntimeContext, client *CaddyAdminClient, logger otelzap.LoggerWithCtx, maxAttempts int) error {
	var lastErr error
	delay := 500 * time.Millisecond

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := client.Health(rc.Ctx)
		if err == nil {
			if attempt > 1 {
				logger.Info("Health check succeeded after retry", zap.Int("attempt", attempt))
			}
			return nil
		}

		lastErr = err
		logger.Debug("Health check attempt failed",
			zap.Int("attempt", attempt),
			zap.Int("max_attempts", maxAttempts),
			zap.Error(err))

		if attempt < maxAttempts {
			time.Sleep(delay)
			delay = delay * 2 // Exponential backoff
		}
	}

	return fmt.Errorf("failed after %d attempts: %w", maxAttempts, lastErr)
}

// testGetConfigWithRetries tests config retrieval with retry logic
func testGetConfigWithRetries(rc *eos_io.RuntimeContext, client *CaddyAdminClient, logger otelzap.LoggerWithCtx, maxAttempts int) (map[string]interface{}, error) {
	var lastErr error
	delay := 500 * time.Millisecond

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		config, err := client.GetConfig(rc.Ctx)
		if err == nil {
			if attempt > 1 {
				logger.Info("Config retrieval succeeded after retry", zap.Int("attempt", attempt))
			}
			return config, nil
		}

		lastErr = err
		logger.Debug("Config retrieval attempt failed",
			zap.Int("attempt", attempt),
			zap.Int("max_attempts", maxAttempts),
			zap.Error(err))

		if attempt < maxAttempts {
			time.Sleep(delay)
			delay = delay * 2 // Exponential backoff
		}
	}

	return nil, fmt.Errorf("failed after %d attempts: %w", maxAttempts, lastErr)
}

// performPerformanceTest makes multiple requests to measure timing
func performPerformanceTest(rc *eos_io.RuntimeContext, client *CaddyAdminClient, logger otelzap.LoggerWithCtx, count int) []time.Duration {
	timings := make([]time.Duration, 0, count)

	for i := 0; i < count; i++ {
		start := time.Now()
		_ = client.Health(rc.Ctx) // Ignore errors for performance test
		duration := time.Since(start)
		timings = append(timings, duration)

		logger.Debug("Performance test request",
			zap.Int("request", i+1),
			zap.Duration("duration", duration))
	}

	return timings
}

// Helper functions
func minDuration(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	minVal := durations[0]
	for _, d := range durations[1:] {
		if d < minVal {
			minVal = d
		}
	}
	return minVal
}

func maxDuration(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	maxVal := durations[0]
	for _, d := range durations[1:] {
		if d > maxVal {
			maxVal = d
		}
	}
	return maxVal
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// testDockerSDKContainerDetection tests if Docker SDK can detect Caddy container
// STRATEGY: Docker SDK first, shell fallback second
func testDockerSDKContainerDetection(rc *eos_io.RuntimeContext, logger otelzap.LoggerWithCtx) bool {
	logger.Info("Testing Docker SDK container detection")

	// Try Docker SDK first
	containerIP, err := GetCaddyContainerIP(rc.Ctx)
	if err == nil {
		fmt.Printf("✓ Docker SDK detected container IP: %s\n", containerIP)
		logger.Info("Docker SDK container detection successful",
			zap.String("container_ip", containerIP))
		return true
	}

	// Docker SDK failed - log why
	fmt.Printf("✗ Docker SDK detection failed: %v\n", err)
	logger.Warn("Docker SDK container detection failed",
		zap.Error(err),
		zap.String("container_name", CaddyContainerName))

	// Fallback to shell command
	fmt.Println("  Attempting shell fallback: docker ps -a | grep hecate-caddy")

	shellCmd := fmt.Sprintf("docker ps -a | grep %s", CaddyContainerName)
	output, shellErr := executeShellCommand(rc, shellCmd)

	if shellErr == nil && output != "" {
		fmt.Printf("  ✓ Shell command found container:\n    %s\n", strings.TrimSpace(output))
		logger.Info("Shell fallback successful",
			zap.String("output", output))

		fmt.Println("\n  ⚠️ DIAGNOSIS: Docker SDK fails but shell command works")
		fmt.Println("  Possible causes:")
		fmt.Println("    1. Docker SDK permission issue")
		fmt.Println("    2. Container name mismatch")
		fmt.Println("    3. Docker API version incompatibility")
		return false
	}

	fmt.Printf("  ✗ Shell command also failed: %v\n", shellErr)
	fmt.Println("\n  ⚠️ DIAGNOSIS: Container not found by SDK or shell")
	fmt.Println("  Container may not exist or Docker is not running")
	return false
}

// testContainerRunningStatus checks if container is running
func testContainerRunningStatus(rc *eos_io.RuntimeContext, logger otelzap.LoggerWithCtx) {
	logger.Info("Checking container running status")

	// Try Docker SDK first
	running, err := IsCaddyContainerRunning(rc.Ctx)
	if err == nil {
		if running {
			fmt.Printf("✓ Docker SDK reports container is RUNNING\n")
			logger.Info("Container running status confirmed", zap.Bool("running", true))
		} else {
			fmt.Printf("✗ Docker SDK reports container is NOT RUNNING\n")
			logger.Warn("Container not running", zap.Bool("running", false))
			fmt.Println("  Start container: docker compose -f /opt/hecate/docker-compose.yml up -d caddy")
		}
		return
	}

	// Docker SDK failed - log why
	fmt.Printf("✗ Docker SDK status check failed: %v\n", err)
	logger.Warn("Docker SDK status check failed", zap.Error(err))

	// Fallback to shell command
	fmt.Println("  Attempting shell fallback: docker inspect hecate-caddy --format '{{.State.Running}}'")

	shellCmd := fmt.Sprintf("docker inspect %s --format '{{.State.Running}}'", CaddyContainerName)
	output, shellErr := executeShellCommand(rc, shellCmd)

	if shellErr == nil {
		isRunning := strings.TrimSpace(output) == "true"
		if isRunning {
			fmt.Printf("  ✓ Shell command reports container is RUNNING\n")
		} else {
			fmt.Printf("  ✗ Shell command reports container is NOT RUNNING\n")
		}
	} else {
		fmt.Printf("  ✗ Shell command failed: %v\n", shellErr)
	}
}

// testContainerNetworks checks which networks container is connected to
func testContainerNetworks(rc *eos_io.RuntimeContext, logger otelzap.LoggerWithCtx) {
	logger.Info("Checking container network configuration")

	// Try Docker SDK first
	containerIP, err := GetCaddyContainerIP(rc.Ctx)
	if err == nil {
		fmt.Printf("✓ Docker SDK found container on network with IP: %s\n", containerIP)
		logger.Info("Container network detection successful",
			zap.String("container_ip", containerIP))
		return
	}

	fmt.Printf("✗ Docker SDK network detection failed: %v\n", err)
	logger.Warn("Docker SDK network detection failed", zap.Error(err))

	// Fallback to shell command with jq
	fmt.Println("  Attempting shell fallback: docker inspect hecate-caddy | jq '.[0].NetworkSettings.Networks'")

	shellCmd := fmt.Sprintf("docker inspect %s | jq '.[0].NetworkSettings.Networks'", CaddyContainerName)
	output, shellErr := executeShellCommand(rc, shellCmd)

	if shellErr == nil && output != "" {
		fmt.Printf("  ✓ Shell command found networks:\n")
		// Indent the JSON output
		for _, line := range strings.Split(output, "\n") {
			if line != "" {
				fmt.Printf("    %s\n", line)
			}
		}
		return
	}

	// Try without jq if jq not installed
	fmt.Println("  jq not available, trying raw inspect:")
	shellCmd = fmt.Sprintf("docker inspect %s --format '{{range $net, $conf := .NetworkSettings.Networks}}{{$net}}: {{$conf.IPAddress}}{{\"\\n\"}}{{end}}'", CaddyContainerName)
	output, shellErr = executeShellCommand(rc, shellCmd)

	if shellErr == nil && output != "" {
		fmt.Printf("  ✓ Networks:\n")
		for _, line := range strings.Split(output, "\n") {
			if line != "" {
				fmt.Printf("    %s\n", line)
			}
		}
	} else {
		fmt.Printf("  ✗ Shell command failed: %v\n", shellErr)
	}
}

// testContainerIPExtraction tests extracting container IP address
func testContainerIPExtraction(rc *eos_io.RuntimeContext, logger otelzap.LoggerWithCtx) {
	logger.Info("Testing container IP extraction")

	// Try Docker SDK first
	containerIP, err := GetCaddyContainerIP(rc.Ctx)
	if err == nil {
		fmt.Printf("✓ Docker SDK extracted IP: %s\n", containerIP)
		logger.Info("IP extraction successful", zap.String("ip", containerIP))

		// Verify IP is accessible
		fmt.Printf("  Testing connectivity to %s:%d...\n", containerIP, CaddyAdminAPIPort)

		client := NewCaddyAdminClient(containerIP)
		if err := client.Health(rc.Ctx); err == nil {
			fmt.Printf("  ✓ Admin API accessible at container IP!\n")
			fmt.Println("\n  ✅ SUCCESS: Docker SDK solution works!")
			fmt.Println("  NewCaddyAdminClient should auto-detect this IP")
		} else {
			fmt.Printf("  ✗ Admin API not accessible at container IP: %v\n", err)
			fmt.Printf("  This suggests Caddy Admin API may not be bound to bridge network\n")
		}
		return
	}

	fmt.Printf("✗ Docker SDK IP extraction failed: %v\n", err)
	logger.Warn("Docker SDK IP extraction failed", zap.Error(err))

	// Fallback to shell command
	fmt.Println("  Attempting shell fallback: docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'")

	shellCmd := fmt.Sprintf("docker inspect %s --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'", CaddyContainerName)
	output, shellErr := executeShellCommand(rc, shellCmd)

	if shellErr == nil && output != "" {
		ip := strings.TrimSpace(output)
		fmt.Printf("  ✓ Shell command extracted IP: %s\n", ip)

		// Test connectivity
		fmt.Printf("  Testing connectivity to %s:%d...\n", ip, CaddyAdminAPIPort)
		client := NewCaddyAdminClient(ip)
		if err := client.Health(rc.Ctx); err == nil {
			fmt.Printf("  ✓ Admin API accessible at container IP!\n")
		} else {
			fmt.Printf("  ✗ Admin API not accessible: %v\n", err)
		}
	} else {
		fmt.Printf("  ✗ Shell command failed: %v\n", shellErr)
	}
}

// testDockerSocketPermissions checks Docker socket permissions
func testDockerSocketPermissions(rc *eos_io.RuntimeContext, logger otelzap.LoggerWithCtx) {
	logger.Info("Checking Docker socket permissions")

	// Shell command to check socket permissions
	shellCmd := "ls -l /var/run/docker.sock"
	output, err := executeShellCommand(rc, shellCmd)

	if err == nil && output != "" {
		fmt.Printf("✓ Docker socket exists:\n  %s\n", strings.TrimSpace(output))
		logger.Info("Docker socket found", zap.String("permissions", output))

		// Parse permissions
		if strings.Contains(output, "srw-rw----") || strings.Contains(output, "srwxrwxrwx") {
			if strings.Contains(output, "docker") {
				fmt.Println("  ✓ Socket owned by docker group")
			}
			if strings.Contains(output, "rw-rw") {
				fmt.Println("  ✓ Socket readable by group members")
			}
		}
	} else {
		fmt.Printf("✗ Failed to check socket: %v\n", err)
		logger.Warn("Docker socket check failed", zap.Error(err))
	}

	// Check if current user has access
	fmt.Println("\n  Checking if current user can access Docker...")
	shellCmd = "groups"
	output, err = executeShellCommand(rc, shellCmd)

	if err == nil && output != "" {
		groups := strings.TrimSpace(output)
		fmt.Printf("  Current user groups: %s\n", groups)

		if strings.Contains(groups, "docker") {
			fmt.Println("  ✓ User is in docker group")
		} else {
			fmt.Println("  ✗ User NOT in docker group")
			fmt.Println("  Fix: sudo usermod -aG docker $USER && newgrp docker")
		}
	}
}

// testDockerSDKAccess tests if Docker SDK can connect
func testDockerSDKAccess(rc *eos_io.RuntimeContext, logger otelzap.LoggerWithCtx) {
	logger.Info("Testing Docker SDK access")

	// Try to list containers via SDK
	running, err := IsCaddyContainerRunning(rc.Ctx)
	if err == nil {
		fmt.Printf("✓ Docker SDK successfully connected\n")
		fmt.Printf("  Container running: %v\n", running)
		logger.Info("Docker SDK access successful", zap.Bool("container_running", running))
		return
	}

	fmt.Printf("✗ Docker SDK connection failed: %v\n", err)
	logger.Warn("Docker SDK connection failed", zap.Error(err))

	// Analyze error
	errStr := err.Error()
	if strings.Contains(errStr, "permission denied") {
		fmt.Println("\n  ⚠️ DIAGNOSIS: Permission denied")
		fmt.Println("  Fix: Add user to docker group or run as root")
		fmt.Println("    sudo usermod -aG docker $USER && newgrp docker")
	} else if strings.Contains(errStr, "no such file") {
		fmt.Println("\n  ⚠️ DIAGNOSIS: Docker socket not found")
		fmt.Println("  Fix: Start Docker daemon")
		fmt.Println("    sudo systemctl start docker")
	} else if strings.Contains(errStr, "connection refused") {
		fmt.Println("\n  ⚠️ DIAGNOSIS: Docker daemon not responding")
		fmt.Println("  Fix: Check Docker status")
		fmt.Println("    sudo systemctl status docker")
	}

	// Fallback to shell command
	fmt.Println("\n  Attempting shell fallback: docker ps")
	_, shellErr := executeShellCommand(rc, "docker ps")

	if shellErr == nil {
		fmt.Printf("  ✓ Shell command works (docker ps successful)\n")
		fmt.Println("\n  ⚠️ DIAGNOSIS: Shell works but SDK fails")
		fmt.Println("  This suggests Docker SDK library issue, not permission issue")
	} else {
		fmt.Printf("  ✗ Shell command also failed: %v\n", shellErr)
		fmt.Println("\n  ⚠️ DIAGNOSIS: Both SDK and shell fail")
		fmt.Println("  Docker is not accessible at all")
	}
}

// executeShellCommand executes a shell command and returns output
// RATIONALE: Diagnostic tool, so we use exec directly for simplicity
// NOTE: In production code, use pkg/execute with proper context/timeout
func executeShellCommand(rc *eos_io.RuntimeContext, command string) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Executing shell command",
		zap.String("command", command))

	// Use sh -c to execute command (supports pipes, redirects, etc.)
	cmd := exec.CommandContext(rc.Ctx, "sh", "-c", command)

	// Capture both stdout and stderr
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Debug("Shell command failed",
			zap.String("command", command),
			zap.Error(err),
			zap.String("output", string(output)))
		return string(output), err
	}

	logger.Debug("Shell command succeeded",
		zap.String("command", command),
		zap.Int("output_bytes", len(output)))

	return string(output), nil
}
