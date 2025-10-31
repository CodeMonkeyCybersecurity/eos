// pkg/hecate/debug_caddy.go - Caddy Admin API diagnostics

package hecate

import (
	"encoding/json"
	"fmt"
	"net"
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
	address := fmt.Sprintf("%s:%d", CaddyAdminAPIHost, CaddyAdminAPIPort)
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
