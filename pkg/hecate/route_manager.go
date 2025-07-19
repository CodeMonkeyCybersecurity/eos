package hecate

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/consul/api"
	// "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RouteManager handles all route operations
type RouteManager struct {
	client *HecateClient
}

// NewRouteManager creates a new route manager
func NewRouteManager(client *HecateClient) *RouteManager {
	return &RouteManager{client: client}
}

// Note: Types are defined in api_types.go and types.go


// UpstreamConfig represents an upstream configuration
type UpstreamConfig struct {
	Dial string `json:"dial"`
}



// RouteFilter represents filters for listing routes
type RouteFilter struct {
	Domain     string `json:"domain,omitempty"`
	AuthPolicy string `json:"auth_policy,omitempty"`
}

// RouteInfo represents extended route information
type RouteInfo struct {
	ID         string            `json:"id"`
	Domain     string            `json:"domain"`
	Upstreams  []string          `json:"upstreams"`
	AuthPolicy string            `json:"auth_policy"`
	Headers    map[string]string `json:"headers"`
	Middleware []string          `json:"middleware"`
	EnableSSL  bool              `json:"enable_ssl"`
	ManageDNS  bool              `json:"manage_dns"`
	IngressIP  string            `json:"ingress_ip"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
	Status     string            `json:"status"`
}

// Validate validates the create route request
func (req *CreateRouteRequest) Validate() error {
	if req.Domain == "" {
		return fmt.Errorf("domain is required")
	}
	if len(req.Upstreams) == 0 {
		return fmt.Errorf("at least one upstream is required")
	}
	for _, upstream := range req.Upstreams {
		if upstream == "" {
			return fmt.Errorf("upstream dial address is required")
		}
	}
	return nil
}

// CreateRoute creates a new route
func (rm *RouteManager) CreateRoute(ctx context.Context, req *CreateRouteRequest) (*RouteInfo, error) {
	logger := otelzap.Ctx(rm.client.rc.Ctx)
	logger.Info("Creating route",
		zap.String("domain", req.Domain),
		zap.Any("upstreams", req.Upstreams))

	// Validate request
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Validate route input using security validation
	if err := ValidateRouteInput(req.Domain, req.Upstreams); err != nil {
		return nil, fmt.Errorf("route validation failed: %w", err)
	}

	// Validate DNS target if DNS management is enabled
	if req.ManageDNS && req.DNSTarget != "" {
		if err := ValidateIPAddress(req.DNSTarget); err != nil {
			return nil, fmt.Errorf("invalid DNS target: %w", err)
		}
	}

	route := &RouteInfo{
		ID:         generateRouteID(req.Domain),
		Domain:     req.Domain,
		Upstreams:  req.Upstreams,
		AuthPolicy: req.AuthPolicy,
		Headers:    req.Headers,
		Middleware: req.Middleware,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	// Step 1: Configure DNS if requested
	if req.ManageDNS {
		logger.Info("Configuring DNS for route", zap.String("domain", req.Domain))
		
		// Use DNS manager for proper DNS lifecycle management
		dnsManager := NewDNSManager(rm.client)
		if err := dnsManager.CreateDNSRecord(ctx, req.Domain, req.DNSTarget); err != nil {
			return nil, fmt.Errorf("failed to configure DNS: %w", err)
		}
		
		// Set DNS fields in route
		route.ManageDNS = true
		route.IngressIP = req.DNSTarget
	}

	// Step 2: Configure SSL certificate
	if req.EnableSSL {
		logger.Info("Configuring SSL certificate", zap.String("domain", req.Domain))
		if err := rm.configureCertificate(ctx, req.Domain); err != nil {
			// Rollback DNS if it was created
			if req.ManageDNS {
				dnsManager := NewDNSManager(rm.client)
				_ = dnsManager.DeleteDNSRecord(ctx, req.Domain)
			}
			return nil, fmt.Errorf("failed to configure certificate: %w", err)
		}
	}

	// Step 3: Configure authentication if specified
	if req.AuthPolicy != "" {
		logger.Info("Configuring authentication", 
			zap.String("domain", req.Domain),
			zap.String("policy", req.AuthPolicy))
		if err := rm.configureAuth(ctx, route); err != nil {
			// Rollback
			if req.ManageDNS {
				dnsManager := NewDNSManager(rm.client)
				_ = dnsManager.DeleteDNSRecord(ctx, req.Domain)
			}
			return nil, fmt.Errorf("failed to configure authentication: %w", err)
		}
	}

	// Step 4: Apply Caddy configuration
	logger.Info("Applying Caddy configuration", zap.String("domain", req.Domain))
	caddyRoute := rm.buildCaddyRoute(route)
	if err := rm.client.caddy.AddRoute(ctx, caddyRoute); err != nil {
		// Rollback
		if req.ManageDNS {
			dnsManager := NewDNSManager(rm.client)
			_ = dnsManager.DeleteDNSRecord(ctx, req.Domain)
		}
		return nil, fmt.Errorf("failed to add route to Caddy: %w", err)
	}

	// Step 5: Store in Consul
	logger.Info("Storing route in Consul", zap.String("domain", req.Domain))
	if err := rm.storeRoute(ctx, route); err != nil {
		// Log error but don't fail - route is working
		logger.Warn("Failed to store route in Consul",
			zap.String("domain", req.Domain),
			zap.Error(err))
	}

	// Step 6: Apply via Salt
	logger.Info("Applying Salt state for route", zap.String("domain", req.Domain))
	if err := rm.applySaltState(ctx, route); err != nil {
		logger.Warn("Failed to apply Salt state",
			zap.String("domain", req.Domain),
			zap.Error(err))
	}

	logger.Info("Route created successfully",
		zap.String("domain", route.Domain),
		zap.String("id", route.ID))

	return route, nil
}

// UpdateRoute updates an existing route
func (rm *RouteManager) UpdateRoute(ctx context.Context, domain string, updates *UpdateRouteRequest) (*RouteInfo, error) {
	logger := otelzap.Ctx(rm.client.rc.Ctx)
	logger.Info("Updating route",
		zap.String("domain", domain))

	// Get current route
	route, err := rm.GetRoute(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get route: %w", err)
	}

	// Create backup for rollback
	backup := rm.cloneRoute(route)

	// Apply updates
	if updates.Upstreams != nil {
		route.Upstreams = updates.Upstreams
	}
	if updates.AuthPolicy != "" {
		route.AuthPolicy = updates.AuthPolicy
	}
	if updates.Headers != nil {
		route.Headers = updates.Headers
	}
	if updates.Middleware != nil {
		route.Middleware = updates.Middleware
	}

	route.UpdatedAt = time.Now()

	// Update Caddy configuration
	caddyRoute := rm.buildCaddyRoute(route)
	if err := rm.client.caddy.UpdateRoute(ctx, caddyRoute); err != nil {
		return nil, fmt.Errorf("failed to update Caddy route: %w", err)
	}

	// Verify the update worked
	if err := rm.verifyRoute(ctx, domain); err != nil {
		// Rollback
		logger.Warn("Route verification failed, rolling back",
			zap.String("domain", domain),
			zap.Error(err))
		_ = rm.client.caddy.UpdateRoute(ctx, rm.buildCaddyRoute(backup))
		return nil, fmt.Errorf("route verification failed: %w", err)
	}

	// Update Consul
	if err := rm.storeRoute(ctx, route); err != nil {
		logger.Warn("Failed to update route in Consul",
			zap.String("domain", domain),
			zap.Error(err))
	}

	logger.Info("Route updated successfully",
		zap.String("domain", route.Domain),
		zap.String("id", route.ID))

	return route, nil
}

// DeleteRoute deletes a route
func (rm *RouteManager) DeleteRoute(ctx context.Context, domain string, options *DeleteOptions) error {
	logger := otelzap.Ctx(rm.client.rc.Ctx)
	logger.Info("Deleting route",
		zap.String("domain", domain))

	// Get route to check if it exists
	route, err := rm.GetRoute(ctx, domain)
	if err != nil {
		return fmt.Errorf("route not found: %w", err)
	}

	// Remove from Caddy
	if err := rm.client.caddy.DeleteRoute(ctx, domain); err != nil {
		return fmt.Errorf("failed to delete route from Caddy: %w", err)
	}

	// Remove from Consul
	if err := rm.deleteRouteFromConsul(ctx, domain); err != nil {
		logger.Warn("Failed to delete route from Consul",
			zap.String("domain", domain),
			zap.Error(err))
	}

	// Delete certificate if requested
	// Delete certificate if requested
	// TODO: Implement certificate deletion when supported
	// if err := rm.deleteCertificate(ctx, domain); err != nil {
	//     logger.Warn("Failed to delete certificate", zap.String("domain", domain), zap.Error(err))
	// }

	// Delete DNS if managed by Hecate and requested
	if route.ManageDNS && (options == nil || options.RemoveDNS) {
		logger.Info("Deleting DNS record", zap.String("domain", domain))
		dnsManager := NewDNSManager(rm.client)
		if err := dnsManager.DeleteDNSRecord(ctx, domain); err != nil {
			logger.Warn("Failed to delete DNS record",
				zap.String("domain", domain),
				zap.Error(err))
		}
	}

	logger.Info("Route deleted successfully",
		zap.String("domain", domain),
		zap.String("id", route.ID))

	return nil
}

// GetRoute retrieves a route by domain
func (rm *RouteManager) GetRoute(ctx context.Context, domain string) (*RouteInfo, error) {
	logger := otelzap.Ctx(rm.client.rc.Ctx)
	logger.Debug("Getting route",
		zap.String("domain", domain))

	// Try to get from Consul first
	data, _, err := rm.client.consul.KV().Get(fmt.Sprintf("hecate/routes/%s", domain), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get route from Consul: %w", err)
	}

	if data == nil {
		return nil, fmt.Errorf("route not found")
	}

	var route RouteInfo
	if err := json.Unmarshal(data.Value, &route); err != nil {
		return nil, fmt.Errorf("failed to unmarshal route: %w", err)
	}

	return &route, nil
}

// ListRoutes lists all routes
func (rm *RouteManager) ListRoutes(ctx context.Context, filter *RouteFilter) ([]*RouteInfo, error) {
	logger := otelzap.Ctx(rm.client.rc.Ctx)
	logger.Debug("Listing routes",
		zap.Any("filter", filter))

	keys, _, err := rm.client.consul.KV().Keys("hecate/routes/", "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %w", err)
	}

	routes := make([]*RouteInfo, 0, len(keys))
	for _, key := range keys {
		domain := strings.TrimPrefix(key, "hecate/routes/")
		if domain == "" {
			continue
		}

		route, err := rm.GetRoute(ctx, domain)
		if err != nil {
			logger.Warn("Failed to get route",
				zap.String("domain", domain),
				zap.Error(err))
			continue
		}

		// Apply filters
		if filter != nil {
			if filter.Domain != "" && !strings.Contains(route.Domain, filter.Domain) {
				continue
			}
			if filter.AuthPolicy != "" && route.AuthPolicy != filter.AuthPolicy {
				continue
			}
		}

		routes = append(routes, route)
	}

	logger.Debug("Listed routes",
		zap.Int("count", len(routes)))

	return routes, nil
}

// Helper methods

func (rm *RouteManager) buildCaddyRoute(route *RouteInfo) *CaddyRoute {
	handlers := []CaddyHandler{}

	// Add auth handler if needed
	if route.AuthPolicy != "" {
		handlers = append(handlers, rm.buildAuthHandler(route))
	}

	// Add proxy handler
	handlers = append(handlers, rm.buildProxyHandler(route))

	return &CaddyRoute{
		ID: route.ID,
		Match: []CaddyMatcher{{
			Host: []string{route.Domain},
		}},
		Handle: handlers,
	}
}

func (rm *RouteManager) buildAuthHandler(route *RouteInfo) CaddyHandler {
	return &CaddyForwardAuth{
		Handler: "forward_auth",
		URI: fmt.Sprintf("http://authentik:9000/outpost.goauthentik.io/auth/caddy"),
		Headers: map[string][]string{
			"X-Authentik-Meta-Outpost": {"authentik-embedded-outpost"},
			"X-Authentik-Meta-Provider": {route.AuthPolicy},
			"X-Authentik-Meta-App": {route.Domain},
		},
	}
}

func (rm *RouteManager) buildProxyHandler(route *RouteInfo) CaddyHandler {
	upstreams := make([]CaddyUpstream, len(route.Upstreams))
	for i, u := range route.Upstreams {
		upstreams[i] = CaddyUpstream{
			Dial: u,
		}
	}

	return &CaddyReverseProxy{
		Handler:   "reverse_proxy",
		Upstreams: upstreams,
		Headers: &CaddyHeaders{
			Request: &CaddyHeaderOps{
				Set: route.Headers,
			},
		},
	}
}

func (rm *RouteManager) storeRoute(ctx context.Context, route *RouteInfo) error {
	data, err := json.Marshal(route)
	if err != nil {
		return err
	}

	_, err = rm.client.consul.KV().Put(&api.KVPair{
		Key:   fmt.Sprintf("hecate/routes/%s", route.Domain),
		Value: data,
	}, nil)

	return err
}

func (rm *RouteManager) deleteRouteFromConsul(ctx context.Context, domain string) error {
	_, err := rm.client.consul.KV().Delete(fmt.Sprintf("hecate/routes/%s", domain), nil)
	return err
}

// Note: DNS operations now handled by DNSManager for better lifecycle management

func (rm *RouteManager) configureCertificate(ctx context.Context, domain string) error {
	// Caddy handles this automatically with Let's Encrypt
	// Just ensure the domain is accessible
	return rm.verifyDNS(ctx, domain)
}

func (rm *RouteManager) deleteCertificate(ctx context.Context, domain string) error {
	// TODO: Implement certificate deletion if needed
	// Caddy manages certificates automatically
	return nil
}

func (rm *RouteManager) configureAuth(ctx context.Context, route *RouteInfo) error {
	// Auth configuration is handled by the Caddy configuration
	// Additional setup might be needed in Authentik
	return nil
}

func (rm *RouteManager) applySaltState(ctx context.Context, route *RouteInfo) error {
	state := map[string]interface{}{
		"hecate_route": map[string]interface{}{
			"domain":      route.Domain,
			"upstreams":   route.Upstreams,
			"auth_policy": route.AuthPolicy,
			"headers":     route.Headers,
		},
	}

	return rm.client.salt.ApplyState(ctx, "hecate.route", state)
}

func (rm *RouteManager) verifyRoute(ctx context.Context, domain string) error {
	logger := otelzap.Ctx(rm.client.rc.Ctx)
	logger.Info("Verifying route health",
		zap.String("domain", domain))

	// Simple HTTP check
	client := resty.New().SetTimeout(10 * time.Second)
	resp, err := client.R().Get(fmt.Sprintf("https://%s/health", domain))

	if err != nil {
		// Try HTTP if HTTPS fails
		resp, err = client.R().Get(fmt.Sprintf("http://%s/health", domain))
		if err != nil {
			return fmt.Errorf("health check failed: %w", err)
		}
	}

	if resp.StatusCode() >= 400 {
		return fmt.Errorf("health check returned status %d", resp.StatusCode())
	}

	logger.Info("Route health check passed",
		zap.String("domain", domain),
		zap.Int("status", resp.StatusCode()))

	return nil
}

func (rm *RouteManager) verifyDNS(ctx context.Context, domain string) error {
	// TODO: Implement DNS verification
	// For now, we'll assume DNS is configured correctly
	return nil
}

func (rm *RouteManager) cloneRoute(route *RouteInfo) *RouteInfo {
	clone := &RouteInfo{
		ID:         route.ID,
		Domain:     route.Domain,
		Upstreams:  make([]string, len(route.Upstreams)),
		AuthPolicy: route.AuthPolicy,
		Headers:    make(map[string]string),
		Middleware: make([]string, len(route.Middleware)),
		CreatedAt:  route.CreatedAt,
		UpdatedAt:  route.UpdatedAt,
	}

	copy(clone.Upstreams, route.Upstreams)
	copy(clone.Middleware, route.Middleware)
	for k, v := range route.Headers {
		clone.Headers[k] = v
	}

	return clone
}

func generateRouteID(domain string) string {
	// Simple ID generation - could be improved with UUIDs
	return fmt.Sprintf("route-%s-%d", domain, time.Now().Unix())
}