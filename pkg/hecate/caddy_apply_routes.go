// pkg/hecate/caddy_apply_routes.go - Apply routes to running Caddy via Admin API

package hecate

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ApplyRoutesFromConfig applies all routes from YAMLHecateConfig to running Caddy via Admin API
// This is called AFTER containers are started, replacing Caddyfile-based route generation
//
// ARCHITECTURE: Hybrid approach
// 1. Caddyfile contains ONLY global config (logging, security snippets)
// 2. Admin API manages ALL routes (zero-downtime, atomic, idempotent)
func ApplyRoutesFromConfig(rc *eos_io.RuntimeContext, config *YAMLHecateConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Applying routes to Caddy via Admin API",
		zap.Int("route_count", len(config.Apps)))

	// Wait for Caddy to be ready (container might need a few seconds to start)
	if err := waitForCaddyReady(rc, 30*time.Second); err != nil {
		return fmt.Errorf("Caddy Admin API not ready: %w\n\n"+
			"Possible causes:\n"+
			"  - Container still starting (check: docker ps)\n"+
			"  - Port 2019 not exposed in docker-compose.yml\n"+
			"  - Caddy crashed on startup (check: docker logs hecate-caddy-1)",
			err)
	}

	// Apply routes for each app
	successCount := 0
	for appName, app := range config.Apps {
		logger.Info("Adding route for app",
			zap.String("app", appName),
			zap.String("dns", app.Domain),
			zap.String("backend", fmt.Sprintf("%s:%d", app.Backend, app.BackendPort)))

		appCopy := app // Create copy to get pointer
		routeConfig := buildRouteConfigFromApp(appName, &appCopy)

		if err := EnsureAPIRoute(rc, routeConfig); err != nil {
			logger.Error("Failed to add route",
				zap.String("app", appName),
				zap.String("dns", app.Domain),
				zap.Error(err))
			// Continue with other routes instead of failing completely
			continue
		}

		successCount++
		logger.Info("✓ Route added successfully",
			zap.String("app", appName),
			zap.String("dns", app.Domain))
	}

	if successCount == 0 {
		return fmt.Errorf("failed to add any routes (%d apps configured)", len(config.Apps))
	}

	if successCount < len(config.Apps) {
		logger.Warn("Some routes failed to add",
			zap.Int("success", successCount),
			zap.Int("total", len(config.Apps)))
	}

	logger.Info("✓ All routes applied via Admin API",
		zap.Int("success_count", successCount),
		zap.Int("total_count", len(config.Apps)))

	return nil
}

// waitForCaddyReady waits for Caddy Admin API to become available
func waitForCaddyReady(rc *eos_io.RuntimeContext, timeout time.Duration) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Waiting for Caddy Admin API to become ready",
		zap.Duration("timeout", timeout))

	client := NewCaddyAdminClient(CaddyAdminAPIHost)
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for Caddy Admin API (waited %s)", timeout)
		}

		if err := client.Health(rc.Ctx); err == nil {
			logger.Debug("Caddy Admin API is ready")
			return nil
		}

		logger.Debug("Caddy Admin API not ready yet, retrying...",
			zap.Duration("remaining", time.Until(deadline)))

		<-ticker.C
	}
}

// buildRouteConfigFromApp converts a YAMLHecateConfig app to a RouteConfig
func buildRouteConfigFromApp(appName string, app *AppConfig) *RouteConfig {
	backend := fmt.Sprintf("%s:%d", app.Backend, app.BackendPort)

	config := &RouteConfig{
		DNS:      app.Domain,
		Backend:  backend,
		LogFile:  fmt.Sprintf("/var/log/caddy/%s-%s.log", appName, app.Type),
		LogLevel: app.LogLevel,
	}

	// Add SSO if enabled
	if app.SSO {
		config.ForwardAuth = &ForwardAuthConfig{
			UpstreamURL: "hecate-server-1:9000", // Authentik container name
			AuthURI:     "/outpost.goauthentik.io/auth/caddy",
			Headers: map[string]string{
				"X-Authentik-Username": "X-Auth-Request-User",
				"X-Authentik-Email":    "X-Auth-Request-Email",
				"X-Authentik-Groups":   "X-Auth-Request-Groups",
			},
		}

		// Add Authentik outpost paths
		config.Handles = []HandleConfig{
			{
				PathPrefix: "/outpost.goauthentik.io/*",
				Backend:    "localhost:9000",
			},
		}
	}

	return config
}
