// pkg/hecate/caddy_routes.go - Caddy route management via Admin API
//
// ARCHITECTURE: API-first approach for Caddy configuration
// - Atomic operations (validate + apply + reload in one step)
// - Zero-downtime reloads
// - No text parsing, no brace tracking, no backup/rollback
// - Idempotent by design

package hecate

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RouteConfig defines a Caddy route configuration
type RouteConfig struct {
	// Required
	DNS     string // Domain name (e.g., "bionicgpt.example.com")
	Backend string // Backend address (e.g., "100.71.196.79:8513" or "http://backend:8080")

	// Optional - Forward Auth (SSO)
	ForwardAuth *ForwardAuthConfig

	// Optional - Logging
	LogFile  string // Path to log file (e.g., "/var/log/caddy/bionicgpt.log")
	LogLevel string // Log level (DEBUG, INFO, WARN, ERROR)

	// Optional - Additional handlers
	Handles []HandleConfig
}

// ForwardAuthConfig defines forward_auth configuration for SSO
type ForwardAuthConfig struct {
	UpstreamURL string            // Authentik outpost URL (e.g., "http://localhost:9000")
	AuthURI     string            // Auth validation URI (e.g., "/outpost.goauthentik.io/auth/caddy")
	Headers     map[string]string // Header mappings (X-Authentik-Username -> X-Auth-Request-User)
}

// HandleConfig defines custom handle blocks
type HandleConfig struct {
	PathPrefix string // Path prefix to match (e.g., "/outpost.goauthentik.io/*")
	Backend    string // Backend to proxy to
}

// AddRoute adds a new route to Caddy via Admin API
// This is atomic - validates, applies, and reloads in one operation
func AddAPIRoute(rc *eos_io.RuntimeContext, config *RouteConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Adding Caddy route via Admin API",
		zap.String("dns", config.DNS),
		zap.String("backend", config.Backend))

	// Build route JSON structure
	route := buildRouteJSON(config)

	// Get Admin API client
	client := NewCaddyAdminClient(CaddyAdminAPIHost)

	// Check if Caddy is healthy
	if err := client.Health(rc.Ctx); err != nil {
		return fmt.Errorf("Caddy Admin API not available: %w\n\n"+
			"Ensure port %d is exposed in docker-compose.yml:\n"+
			"  caddy:\n"+
			"    ports:\n"+
			"      - \"127.0.0.1:%d:%d\"",
			err, CaddyAdminAPIPort, CaddyAdminAPIPort, CaddyAdminAPIPort)
	}

	// Get current config
	currentConfig, err := client.GetConfig(rc.Ctx)
	if err != nil {
		return fmt.Errorf("failed to get current Caddy config: %w", err)
	}

	// Navigate to HTTP routes
	routes, err := getHTTPRoutes(currentConfig)
	if err != nil {
		return fmt.Errorf("failed to navigate to HTTP routes: %w", err)
	}

	// Check if route already exists
	existingIndex := findRouteIndex(routes, config.DNS)
	if existingIndex >= 0 {
		logger.Warn("Route already exists, will update",
			zap.String("dns", config.DNS),
			zap.Int("index", existingIndex))

		// Update existing route
		path := fmt.Sprintf("apps/http/servers/srv0/routes/%d", existingIndex)
		if err := client.PatchConfig(rc.Ctx, path, route); err != nil {
			return fmt.Errorf("failed to update existing route: %w", err)
		}

		logger.Info("✓ Route updated via Admin API (zero-downtime reload)",
			zap.String("dns", config.DNS))
	} else {
		// Add new route (prepend to routes array for priority)
		path := "apps/http/servers/srv0/routes/0"
		if err := client.PatchConfig(rc.Ctx, path, route); err != nil {
			return fmt.Errorf("failed to add new route: %w", err)
		}

		logger.Info("✓ Route added via Admin API (zero-downtime reload)",
			zap.String("dns", config.DNS))
	}

	return nil
}

// UpdateRoute updates an existing route or creates it if it doesn't exist
func UpdateAPIRoute(rc *eos_io.RuntimeContext, config *RouteConfig) error {
	// AddAPIRoute is idempotent - it updates if exists, creates if not
	return AddAPIRoute(rc, config)
}

// DeleteRoute removes a route from Caddy via Admin API
func DeleteAPIRoute(rc *eos_io.RuntimeContext, dns string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Deleting Caddy route via Admin API",
		zap.String("dns", dns))

	client := NewCaddyAdminClient(CaddyAdminAPIHost)

	// Get current config
	currentConfig, err := client.GetConfig(rc.Ctx)
	if err != nil {
		return fmt.Errorf("failed to get current Caddy config: %w", err)
	}

	// Navigate to HTTP routes
	routes, err := getHTTPRoutes(currentConfig)
	if err != nil {
		return fmt.Errorf("failed to navigate to HTTP routes: %w", err)
	}

	// Find route index
	existingIndex := findRouteIndex(routes, dns)
	if existingIndex < 0 {
		logger.Warn("Route not found, nothing to delete",
			zap.String("dns", dns))
		return nil // Idempotent - not an error
	}

	// Delete route
	path := fmt.Sprintf("apps/http/servers/srv0/routes/%d", existingIndex)
	if err := client.DeleteConfig(rc.Ctx, path); err != nil {
		return fmt.Errorf("failed to delete route: %w", err)
	}

	logger.Info("✓ Route deleted via Admin API (zero-downtime reload)",
		zap.String("dns", dns))

	return nil
}

// GetRoute retrieves route configuration for a specific DNS
func GetAPIRoute(rc *eos_io.RuntimeContext, dns string) (*RouteConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Getting Caddy route via Admin API",
		zap.String("dns", dns))

	client := NewCaddyAdminClient(CaddyAdminAPIHost)

	// Get current config
	currentConfig, err := client.GetConfig(rc.Ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get current Caddy config: %w", err)
	}

	// Navigate to HTTP routes
	routes, err := getHTTPRoutes(currentConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to navigate to HTTP routes: %w", err)
	}

	// Find route
	existingIndex := findRouteIndex(routes, dns)
	if existingIndex < 0 {
		return nil, fmt.Errorf("route not found for DNS: %s", dns)
	}

	// Parse route into RouteConfig
	routeMap := routes[existingIndex].(map[string]interface{})
	config := parseRouteJSON(routeMap)

	return config, nil
}

// ListRoutes returns all configured routes
func ListAPIRoutes(rc *eos_io.RuntimeContext) ([]*RouteConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Listing all Caddy routes via Admin API")

	client := NewCaddyAdminClient(CaddyAdminAPIHost)

	// Get current config
	currentConfig, err := client.GetConfig(rc.Ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get current Caddy config: %w", err)
	}

	// Navigate to HTTP routes
	routes, err := getHTTPRoutes(currentConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to navigate to HTTP routes: %w", err)
	}

	// Parse all routes
	var configs []*RouteConfig
	for _, routeInterface := range routes {
		routeMap, ok := routeInterface.(map[string]interface{})
		if !ok {
			continue
		}

		config := parseRouteJSON(routeMap)
		if config != nil {
			configs = append(configs, config)
		}
	}

	return configs, nil
}

// buildRouteJSON constructs the JSON structure for a Caddy route
func buildRouteJSON(config *RouteConfig) map[string]interface{} {
	route := map[string]interface{}{
		"match": []map[string]interface{}{
			{
				"host": []string{config.DNS},
			},
		},
		"handle": []map[string]interface{}{},
	}

	handlers := route["handle"].([]map[string]interface{})

	// Add custom handle blocks (e.g., Authentik outpost paths)
	for _, handle := range config.Handles {
		handler := map[string]interface{}{
			"handler": "subroute",
			"routes": []map[string]interface{}{
				{
					"match": []map[string]interface{}{
						{
							"path": []string{handle.PathPrefix},
						},
					},
					"handle": []map[string]interface{}{
						{
							"handler": "reverse_proxy",
							"upstreams": []map[string]interface{}{
								{"dial": normalizeBackend(handle.Backend)},
							},
						},
					},
				},
			},
		}
		handlers = append(handlers, handler)
	}

	// Add forward_auth if configured
	if config.ForwardAuth != nil {
		forwardAuthHandler := map[string]interface{}{
			"handler": "forward_auth",
			"uri":     config.ForwardAuth.AuthURI,
			"upstreams": []map[string]interface{}{
				{"dial": normalizeBackend(config.ForwardAuth.UpstreamURL)},
			},
		}

		// Add header mappings (renaming)
		if len(config.ForwardAuth.Headers) > 0 {
			copyHeaders := make(map[string]interface{})
			for from, to := range config.ForwardAuth.Headers {
				copyHeaders[from] = to
			}
			forwardAuthHandler["copy_headers"] = copyHeaders
		}

		handlers = append(handlers, forwardAuthHandler)
	}

	// Add reverse_proxy to backend
	backendHandler := map[string]interface{}{
		"handler": "reverse_proxy",
		"upstreams": []map[string]interface{}{
			{"dial": normalizeBackend(config.Backend)},
		},
	}
	handlers = append(handlers, backendHandler)

	route["handle"] = handlers

	// Add terminal directive (prevents falling through to other routes)
	route["terminal"] = true

	return route
}

// parseRouteJSON converts Caddy JSON route to RouteConfig
func parseRouteJSON(routeMap map[string]interface{}) *RouteConfig {
	config := &RouteConfig{}

	// Extract DNS from match
	if match, ok := routeMap["match"].([]interface{}); ok && len(match) > 0 {
		if firstMatch, ok := match[0].(map[string]interface{}); ok {
			if hosts, ok := firstMatch["host"].([]interface{}); ok && len(hosts) > 0 {
				if dns, ok := hosts[0].(string); ok {
					config.DNS = dns
				}
			}
		}
	}

	// Extract handlers
	if handle, ok := routeMap["handle"].([]interface{}); ok {
		for _, handlerInterface := range handle {
			handler, ok := handlerInterface.(map[string]interface{})
			if !ok {
				continue
			}

			handlerType, _ := handler["handler"].(string)

			switch handlerType {
			case "forward_auth":
				config.ForwardAuth = &ForwardAuthConfig{
					AuthURI: getString(handler, "uri"),
					Headers: make(map[string]string),
				}

				if upstreams, ok := handler["upstreams"].([]interface{}); ok && len(upstreams) > 0 {
					if upstream, ok := upstreams[0].(map[string]interface{}); ok {
						config.ForwardAuth.UpstreamURL = getString(upstream, "dial")
					}
				}

				if copyHeaders, ok := handler["copy_headers"].(map[string]interface{}); ok {
					for from, to := range copyHeaders {
						if toStr, ok := to.(string); ok {
							config.ForwardAuth.Headers[from] = toStr
						}
					}
				}

			case "reverse_proxy":
				if upstreams, ok := handler["upstreams"].([]interface{}); ok && len(upstreams) > 0 {
					if upstream, ok := upstreams[0].(map[string]interface{}); ok {
						config.Backend = getString(upstream, "dial")
					}
				}
			}
		}
	}

	return config
}

// getHTTPRoutes navigates Caddy config JSON to find HTTP routes array
func getHTTPRoutes(config map[string]interface{}) ([]interface{}, error) {
	apps, ok := config["apps"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("config missing 'apps' section")
	}

	httpApp, ok := apps["http"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("config missing 'apps.http' section")
	}

	servers, ok := httpApp["servers"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("config missing 'apps.http.servers' section")
	}

	// Typically uses "srv0" as the default server name
	server, ok := servers["srv0"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("config missing 'apps.http.servers.srv0' section")
	}

	routes, ok := server["routes"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("config missing 'apps.http.servers.srv0.routes' section")
	}

	return routes, nil
}

// findRouteIndex finds the index of a route matching the given DNS
func findRouteIndex(routes []interface{}, dns string) int {
	for i, routeInterface := range routes {
		route, ok := routeInterface.(map[string]interface{})
		if !ok {
			continue
		}

		match, ok := route["match"].([]interface{})
		if !ok || len(match) == 0 {
			continue
		}

		firstMatch, ok := match[0].(map[string]interface{})
		if !ok {
			continue
		}

		hosts, ok := firstMatch["host"].([]interface{})
		if !ok {
			continue
		}

		for _, hostInterface := range hosts {
			host, ok := hostInterface.(string)
			if ok && host == dns {
				return i
			}
		}
	}

	return -1 // Not found
}

// normalizeBackend ensures backend has no protocol prefix (Caddy adds it)
func normalizeBackend(backend string) string {
	backend = strings.TrimPrefix(backend, "http://")
	backend = strings.TrimPrefix(backend, "https://")
	return backend
}

// getString safely extracts a string value from a map
func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

// NewBionicGPTRoute creates a RouteConfig for BionicGPT with Authentik SSO
func NewBionicGPTRoute(dns, backend string) *RouteConfig {
	return &RouteConfig{
		DNS:     dns,
		Backend: backend,
		ForwardAuth: &ForwardAuthConfig{
			UpstreamURL: "localhost:9000",
			AuthURI:     "/outpost.goauthentik.io/auth/caddy",
			Headers: map[string]string{
				"X-Authentik-Username": "X-Auth-Request-User",
				"X-Authentik-Email":    "X-Auth-Request-Email",
				"X-Authentik-Groups":   "X-Auth-Request-Groups",
				"X-Authentik-Name":     "X-Auth-Request-Name",
				"X-Authentik-Uid":      "X-Auth-Request-Uid",
			},
		},
		Handles: []HandleConfig{
			{
				PathPrefix: "/outpost.goauthentik.io/*",
				Backend:    "localhost:9000",
			},
		},
		LogFile:  "/var/log/caddy/bionicgpt.log",
		LogLevel: "DEBUG",
	}
}

// NewSimpleRoute creates a basic reverse proxy route
func NewSimpleRoute(dns, backend string) *RouteConfig {
	return &RouteConfig{
		DNS:     dns,
		Backend: backend,
	}
}

// NewSSORoute creates a route with Authentik forward auth
func NewSSORoute(dns, backend, upstreamURL string) *RouteConfig {
	return &RouteConfig{
		DNS:     dns,
		Backend: backend,
		ForwardAuth: &ForwardAuthConfig{
			UpstreamURL: upstreamURL,
			AuthURI:     "/outpost.goauthentik.io/auth/caddy",
			Headers: map[string]string{
				"X-Authentik-Username": "X-Auth-Request-User",
				"X-Authentik-Email":    "X-Auth-Request-Email",
				"X-Authentik-Groups":   "X-Auth-Request-Groups",
			},
		},
		Handles: []HandleConfig{
			{
				PathPrefix: "/outpost.goauthentik.io/*",
				Backend:    upstreamURL,
			},
		},
	}
}

// EnsureRoute ensures a route exists with the given configuration (idempotent)
func EnsureAPIRoute(rc *eos_io.RuntimeContext, config *RouteConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if route exists
	existing, err := GetAPIRoute(rc, config.DNS)
	if err != nil {
		// Route doesn't exist - create it
		logger.Debug("Route does not exist, creating",
			zap.String("dns", config.DNS))
		return AddAPIRoute(rc, config)
	}

	// Route exists - check if update needed
	if routesMatch(existing, config) {
		logger.Debug("Route already configured correctly",
			zap.String("dns", config.DNS))
		return nil // Idempotent - already correct
	}

	// Update needed
	logger.Debug("Route exists but configuration differs, updating",
		zap.String("dns", config.DNS))
	return UpdateAPIRoute(rc, config)
}

// routesMatch checks if two RouteConfig instances are equivalent
func routesMatch(a, b *RouteConfig) bool {
	if a.DNS != b.DNS || a.Backend != b.Backend {
		return false
	}

	// Check forward auth
	if (a.ForwardAuth == nil) != (b.ForwardAuth == nil) {
		return false
	}

	if a.ForwardAuth != nil {
		if a.ForwardAuth.UpstreamURL != b.ForwardAuth.UpstreamURL ||
			a.ForwardAuth.AuthURI != b.ForwardAuth.AuthURI {
			return false
		}

		// Check headers (simplified - just check key count matches)
		if len(a.ForwardAuth.Headers) != len(b.ForwardAuth.Headers) {
			return false
		}
	}

	return true
}
