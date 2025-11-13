// pkg/hecate/add/add_via_api.go - Add routes via Caddy Admin API (zero-downtime)
//
// ARCHITECTURE: Replaces text-based Caddyfile editing with Admin API calls
// - No file backups needed (API is atomic)
// - No file locking needed (API handles concurrency)
// - No reload needed (API hot-reloads automatically)
// - Idempotent by design

package add

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// runAppendRoutePhaseViaAPI adds a route using Caddy Admin API instead of text file editing
// This replaces runAppendRoutePhase when Admin API is available
func runAppendRoutePhaseViaAPI(rc *eos_io.RuntimeContext, opts *ServiceOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Phase 4/6: Adding route via Caddy Admin API...")

	// Build route configuration
	routeConfig := buildRouteConfigFromOptions(opts)

	// Add or update route via API (atomic, zero-downtime)
	if err := hecate.EnsureAPIRoute(rc, routeConfig); err != nil {
		return fmt.Errorf("failed to add route via Admin API: %w", err)
	}

	logger.Info("✓ Route added via Admin API (zero-downtime reload)")
	return nil
}

// buildRouteConfigFromOptions converts ServiceOptions to RouteConfig for Admin API
func buildRouteConfigFromOptions(opts *ServiceOptions) *hecate.RouteConfig {
	config := &hecate.RouteConfig{
		DNS:      opts.DNS,
		Backend:  opts.Backend,
		LogFile:  fmt.Sprintf("/var/log/caddy/%s.log", opts.Service),
		LogLevel: "INFO",
	}

	// Add SSO if enabled
	if opts.SSO {
		config.ForwardAuth = &hecate.ForwardAuthConfig{
			UpstreamURL: "hecate-server-1:9000", // Authentik container
			AuthURI:     "/outpost.goauthentik.io/auth/caddy",
			Headers: map[string]string{
				"X-Authentik-Username": "X-Auth-Request-User",
				"X-Authentik-Email":    "X-Auth-Request-Email",
				"X-Authentik-Groups":   "X-Auth-Request-Groups",
			},
		}

		// Add Authentik outpost proxy paths
		config.Handles = []hecate.HandleConfig{
			{
				PathPrefix: "/outpost.goauthentik.io/*",
				Backend:    "localhost:9000",
			},
		}
	}

	return config
}

// runCaddyReloadPhaseViaAPI is a no-op when using Admin API (reload happens automatically)
func runCaddyReloadPhaseViaAPI(rc *eos_io.RuntimeContext, backupPath string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Phase 5/6: Caddy reload (skipped - Admin API auto-reloaded)")
	logger.Debug("Admin API automatically reloaded Caddy with zero downtime")
	return nil
}
