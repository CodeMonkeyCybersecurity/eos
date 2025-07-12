package hecate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreateRoute creates a new reverse proxy route in Caddy
func CreateRoute(rc *eos_io.RuntimeContext, route *Route) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check prerequisites
	logger.Info("Assessing route creation prerequisites",
		zap.String("domain", route.Domain),
		zap.String("upstream", route.Upstream))

	// Check if upstream exists
	if err := validateUpstreamExists(rc, route.Upstream); err != nil {
		return eos_err.NewUserError("upstream %s does not exist", route.Upstream)
	}

	// Check if route already exists
	exists, err := routeExists(rc, route.Domain)
	if err != nil {
		return fmt.Errorf("failed to check route existence: %w", err)
	}
	if exists {
		return eos_err.NewUserError("route for domain %s already exists", route.Domain)
	}

	// Validate auth policy if specified
	if route.AuthPolicy != "" {
		if err := validateAuthPolicyExists(rc, route.AuthPolicy); err != nil {
			return eos_err.NewUserError("auth policy %s does not exist", route.AuthPolicy)
		}
	}

	// INTERVENE - Create the route
	logger.Info("Creating route in Caddy",
		zap.String("domain", route.Domain))

	// Build Caddy configuration
	caddyConfig := buildCaddyRouteConfig(route)

	// Apply to Caddy via Admin API
	if err := applyCaddyConfig(rc, route.Domain, caddyConfig); err != nil {
		return fmt.Errorf("failed to apply Caddy configuration: %w", err)
	}

	// Create DNS record if needed
	if err := ensureDNSRecord(rc, route.Domain); err != nil {
		// Rollback Caddy config on DNS failure
		logger.Warn("DNS creation failed, rolling back Caddy config",
			zap.Error(err))
		_ = deleteCaddyRoute(rc, route.Domain)
		return fmt.Errorf("failed to create DNS record: %w", err)
	}

	// Update state store
	if err := updateStateStore(rc, "routes", route.Domain, route); err != nil {
		logger.Warn("Failed to update state store",
			zap.Error(err))
		// Non-fatal - route is working
	}

	// EVALUATE - Verify the route is working
	logger.Info("Verifying route functionality",
		zap.String("domain", route.Domain))

	if err := verifyRoute(rc, route); err != nil {
		return fmt.Errorf("route verification failed: %w", err)
	}

	logger.Info("Route created successfully",
		zap.String("domain", route.Domain),
		zap.String("upstream", route.Upstream))

	return nil
}

// UpdateRoute modifies an existing route
func UpdateRoute(rc *eos_io.RuntimeContext, domain string, updates map[string]interface{}) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check if route exists and get current config
	logger.Info("Assessing route update prerequisites",
		zap.String("domain", domain))

	currentRoute, err := getRoute(rc, domain)
	if err != nil {
		return eos_err.NewUserError("route %s not found", domain)
	}

	// Create backup for rollback
	backup := *currentRoute

	// INTERVENE - Apply updates
	logger.Info("Applying route updates",
		zap.String("domain", domain),
		zap.Any("updates", updates))

	// Apply updates to route object
	if err := applyRouteUpdates(currentRoute, updates); err != nil {
		return fmt.Errorf("failed to apply updates: %w", err)
	}

	// Validate updated configuration
	if err := validateRoute(currentRoute); err != nil {
		return eos_err.NewUserError("invalid route configuration: %v", err)
	}

	// Apply to Caddy
	caddyConfig := buildCaddyRouteConfig(currentRoute)
	if err := applyCaddyConfig(rc, domain, caddyConfig); err != nil {
		return fmt.Errorf("failed to apply Caddy configuration: %w", err)
	}

	// Update state store
	if err := updateStateStore(rc, "routes", domain, currentRoute); err != nil {
		// Rollback on state store failure
		logger.Warn("State store update failed, rolling back",
			zap.Error(err))
		_ = applyCaddyConfig(rc, domain, buildCaddyRouteConfig(&backup))
		return fmt.Errorf("failed to update state store: %w", err)
	}

	// EVALUATE - Verify the updated route works
	logger.Info("Verifying updated route functionality",
		zap.String("domain", domain))

	if err := verifyRoute(rc, currentRoute); err != nil {
		// Rollback on verification failure
		logger.Warn("Route verification failed, rolling back",
			zap.Error(err))
		_ = applyCaddyConfig(rc, domain, buildCaddyRouteConfig(&backup))
		_ = updateStateStore(rc, "routes", domain, &backup)
		return fmt.Errorf("route verification failed: %w", err)
	}

	logger.Info("Route updated successfully",
		zap.String("domain", domain))

	return nil
}

// DeleteRoute removes a route from the reverse proxy
func DeleteRoute(rc *eos_io.RuntimeContext, domain string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check if route exists
	logger.Info("Assessing route deletion prerequisites",
		zap.String("domain", domain))

	route, err := getRoute(rc, domain)
	if err != nil {
		return eos_err.NewUserError("route %s not found", domain)
	}

	// INTERVENE - Delete the route
	logger.Info("Deleting route from Caddy",
		zap.String("domain", domain))

	// Delete from Caddy
	if err := deleteCaddyRoute(rc, domain); err != nil {
		return fmt.Errorf("failed to delete route from Caddy: %w", err)
	}

	// Delete DNS record if managed
	if err := deleteDNSRecord(rc, domain); err != nil {
		logger.Warn("Failed to delete DNS record",
			zap.Error(err))
		// Non-fatal - continue with deletion
	}

	// Delete from state store
	if err := deleteFromStateStore(rc, "routes", domain); err != nil {
		logger.Warn("Failed to delete from state store",
			zap.Error(err))
		// Non-fatal - route is already deleted from Caddy
	}

	// EVALUATE - Verify deletion
	logger.Info("Verifying route deletion",
		zap.String("domain", domain))

	exists, err := routeExists(rc, domain)
	if err != nil {
		return fmt.Errorf("failed to verify route deletion: %w", err)
	}
	if exists {
		return fmt.Errorf("route still exists after deletion")
	}

	logger.Info("Route deleted successfully",
		zap.String("domain", domain),
		zap.String("upstream", route.Upstream))

	return nil
}

// Helper function to build Caddy configuration
func buildCaddyRouteConfig(route *Route) map[string]interface{} {
	handlers := []map[string]interface{}{}

	// Add authentication if policy is specified
	if route.AuthPolicy != "" {
		handlers = append(handlers, map[string]interface{}{
			"handler": "authentication",
			"providers": map[string]interface{}{
				"http_basic": map[string]interface{}{
					"accounts": []interface{}{}, // Would be populated from auth policy
				},
			},
		})
	}

	// Build upstream configuration
	upstreams := []map[string]interface{}{
		{
			"dial": route.Upstream,
		},
	}

	// Add headers if specified
	requestHeaders := map[string]interface{}{}
	if len(route.Headers) > 0 {
		for k, v := range route.Headers {
			requestHeaders[k] = []string{v}
		}
	}

	// Add reverse proxy handler
	reverseProxyConfig := map[string]interface{}{
		"handler":   "reverse_proxy",
		"upstreams": upstreams,
	}

	if len(requestHeaders) > 0 {
		reverseProxyConfig["headers"] = map[string]interface{}{
			"request": map[string]interface{}{
				"set": requestHeaders,
			},
		}
	}

	// Add health check if configured
	if route.HealthCheck != nil {
		reverseProxyConfig["health_checks"] = map[string]interface{}{
			"active": map[string]interface{}{
				"path":     route.HealthCheck.Path,
				"interval": route.HealthCheck.Interval.String(),
				"timeout":  route.HealthCheck.Timeout.String(),
			},
		}
	}

	handlers = append(handlers, reverseProxyConfig)

	// Build complete configuration
	return map[string]interface{}{
		"@id": fmt.Sprintf("route_%s", strings.ReplaceAll(route.Domain, ".", "_")),
		"match": []map[string]interface{}{
			{"host": []string{route.Domain}},
		},
		"handle": handlers,
	}
}

// applyCaddyConfig applies configuration to Caddy via Admin API
func applyCaddyConfig(rc *eos_io.RuntimeContext, routeID string, config map[string]interface{}) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get Caddy admin endpoint
	caddyAdminURL := getCaddyAdminURL(rc)
	url := fmt.Sprintf("%s/config/apps/http/servers/srv0/routes", caddyAdminURL)

	// Marshal configuration
	body, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(rc.Ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Send request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to apply config to Caddy: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Check response
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("caddy API returned error %d: %s", resp.StatusCode, string(body))
	}

	logger.Debug("Successfully applied Caddy configuration",
		zap.String("route_id", routeID))

	return nil
}

// routeExists checks if a route exists in Caddy
func routeExists(rc *eos_io.RuntimeContext, domain string) (bool, error) {
	routes, err := listCaddyRoutes(rc)
	if err != nil {
		return false, err
	}

	for _, route := range routes {
		if route.Domain == domain {
			return true, nil
		}
	}

	return false, nil
}

// validateUpstreamExists checks if an upstream configuration exists
func validateUpstreamExists(rc *eos_io.RuntimeContext, upstream string) error {
	// TODO: Implement upstream validation
	// For now, accept any upstream format
	if upstream == "" {
		return fmt.Errorf("upstream cannot be empty")
	}
	return nil
}

// validateAuthPolicyExists checks if an auth policy exists
func validateAuthPolicyExists(rc *eos_io.RuntimeContext, policyName string) error {
	// TODO: Implement auth policy validation with Authentik
	// For now, accept any policy name
	if policyName == "" {
		return fmt.Errorf("auth policy name cannot be empty")
	}
	return nil
}

// verifyRoute verifies that a route is working correctly
func verifyRoute(rc *eos_io.RuntimeContext, route *Route) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Build test URL
	testURL := fmt.Sprintf("https://%s", route.Domain)
	if route.HealthCheck != nil && route.HealthCheck.Path != "" {
		testURL = fmt.Sprintf("%s%s", testURL, route.HealthCheck.Path)
	}

	// Create HTTP client with custom settings
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow up to 3 redirects
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	// Create request
	req, err := http.NewRequestWithContext(rc.Ctx, "GET", testURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create verification request: %w", err)
	}

	// Send request
	logger.Debug("Sending verification request",
		zap.String("url", testURL))

	resp, err := client.Do(req)
	if err != nil {
		// Check if it's a certificate error (common for new routes)
		if strings.Contains(err.Error(), "certificate") {
			logger.Warn("Certificate validation failed, route may need time for cert provisioning",
				zap.Error(err))
			// This might not be a fatal error if auto-HTTPS is enabled
			return nil
		}
		return fmt.Errorf("verification request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Check response status
	if route.HealthCheck != nil && len(route.HealthCheck.ExpectedStatus) > 0 {
		statusOK := false
		for _, expectedStatus := range route.HealthCheck.ExpectedStatus {
			if resp.StatusCode == expectedStatus {
				statusOK = true
				break
			}
		}
		if !statusOK {
			return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}
	} else {
		// Default: accept 2xx and 3xx
		if resp.StatusCode >= 400 {
			return fmt.Errorf("route returned error status: %d", resp.StatusCode)
		}
	}

	logger.Debug("Route verification successful",
		zap.String("domain", route.Domain),
		zap.Int("status_code", resp.StatusCode))

	return nil
}

// Helper functions for Caddy API operations

func getCaddyAdminURL(rc *eos_io.RuntimeContext) string {
	// TODO: Make this configurable
	return "http://localhost:2019"
}

func listCaddyRoutes(rc *eos_io.RuntimeContext) ([]*Route, error) {
	// TODO: Implement listing routes from Caddy API
	return []*Route{}, nil
}

func deleteCaddyRoute(rc *eos_io.RuntimeContext, domain string) error {
	// TODO: Implement route deletion via Caddy API
	return nil
}

func getRoute(rc *eos_io.RuntimeContext, domain string) (*Route, error) {
	// TODO: Implement fetching route from state store or Caddy
	return nil, fmt.Errorf("not implemented")
}

func applyRouteUpdates(route *Route, updates map[string]interface{}) error {
	// TODO: Implement applying updates to route object
	return nil
}

func validateRoute(route *Route) error {
	if route.Domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}
	if route.Upstream == "" {
		return fmt.Errorf("upstream cannot be empty")
	}
	return nil
}

// DNS management helpers (placeholder implementations)

func ensureDNSRecord(rc *eos_io.RuntimeContext, domain string) error {
	// TODO: Implement DNS record creation via Hetzner API
	return nil
}

func deleteDNSRecord(rc *eos_io.RuntimeContext, domain string) error {
	// TODO: Implement DNS record deletion via Hetzner API
	return nil
}

// State store helpers (placeholder implementations)

func updateStateStore(rc *eos_io.RuntimeContext, storeType, key string, value interface{}) error {
	// TODO: Implement state store update (Consul/etcd/file)
	return nil
}

func deleteFromStateStore(rc *eos_io.RuntimeContext, storeType, key string) error {
	// TODO: Implement state store deletion
	return nil
}