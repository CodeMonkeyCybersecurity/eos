// pkg/hecate/oauth2_signout.go - Add OAuth2 logout handler to existing routes
//
// PATTERN: Augments existing Authentik-protected routes with logout functionality
// - Detects routes with forward_auth to Authentik
// - Injects /oauth2/sign_out handler via Caddy Admin API
// - Fetches application slugs from Authentik API for correct redirect URLs

package hecate

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// OAuth2SignoutConfig holds configuration for logout handler deployment
type OAuth2SignoutConfig struct {
	AuthentikHost string // Authentik base URL (e.g., "hera.codemonkey.net.au")
	AuthentikPort int    // Authentik port (default: 9000)
	DryRun        bool   // If true, only show what would be changed
}

// AuthentikApplicationResponse represents an Authentik application from API
type AuthentikApplicationResponse struct {
	Results []AuthentikApplication `json:"results"`
}

// AuthentikApplication represents a single Authentik application
type AuthentikApplication struct {
	PK    string `json:"pk"`    // Application UUID
	Slug  string `json:"slug"`  // Application slug (used in URLs)
	Name  string `json:"name"`  // Application name
	Group string `json:"group"` // Application group
}

// EnableOAuth2Signout adds logout handlers to all Authentik-protected routes
// ASSESS → INTERVENE → EVALUATE pattern
func EnableOAuth2Signout(rc *eos_io.RuntimeContext, config *OAuth2SignoutConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Enabling OAuth2 /oauth2/sign_out logout handlers")

	// ========================================
	// ASSESS: Discover routes that need logout handlers
	// ========================================

	logger.Info("Phase 1/4: Discovering Authentik-protected routes")

	// Get Caddy Admin API client
	client := NewCaddyAdminClient(CaddyAdminAPIHost)

	// Check Caddy health
	if err := client.Health(rc.Ctx); err != nil {
		return fmt.Errorf("Caddy Admin API not available: %w", err)
	}

	// Get current Caddy config
	caddyConfig, err := client.GetConfig(rc.Ctx)
	if err != nil {
		return fmt.Errorf("failed to get Caddy config: %w", err)
	}

	// Find all routes with forward_auth (Authentik-protected)
	protectedRoutes, err := findAuthentikProtectedRoutes(caddyConfig)
	if err != nil {
		return fmt.Errorf("failed to find protected routes: %w", err)
	}

	if len(protectedRoutes) == 0 {
		logger.Info("No Authentik-protected routes found (no routes with forward_auth)")
		return nil
	}

	logger.Info("Found Authentik-protected routes",
		zap.Int("count", len(protectedRoutes)),
		zap.Strings("domains", protectedRoutes))

	// ========================================
	// ASSESS: Get Authentik application slugs
	// ========================================

	logger.Info("Phase 2/4: Fetching Authentik application slugs via API")

	// Get Authentik API token
	token, err := getAuthentikAPIToken(rc)
	if err != nil {
		return fmt.Errorf("failed to get Authentik API token: %w\n\n"+
			"Set AUTHENTIK_BOOTSTRAP_TOKEN or AUTHENTIK_API_TOKEN in /opt/hecate/.env\n"+
			"Get token from: https://%s/if/admin/#/core/tokens", err, config.AuthentikHost)
	}

	// Fetch applications from Authentik
	applications, err := fetchAuthentikApplications(rc, config.AuthentikHost, config.AuthentikPort, token)
	if err != nil {
		return fmt.Errorf("failed to fetch Authentik applications: %w", err)
	}

	logger.Info("Fetched Authentik applications",
		zap.Int("count", len(applications)))

	// Build domain → slug mapping
	domainToSlug := buildDomainSlugMapping(protectedRoutes, applications)

	// ========================================
	// INTERVENE: Inject logout handlers
	// ========================================

	logger.Info("Phase 3/4: Injecting /oauth2/sign_out handlers")

	successCount := 0
	failureCount := 0

	for _, domain := range protectedRoutes {
		slug, found := domainToSlug[domain]
		if !found {
			logger.Warn("No Authentik application found for domain, using generic logout",
				zap.String("domain", domain))
			slug = "default" // Fallback to generic logout
		}

		logoutURL := buildLogoutURL(config.AuthentikHost, slug, domain)

		logger.Info("Injecting logout handler",
			zap.String("domain", domain),
			zap.String("slug", slug),
			zap.String("logout_url", logoutURL))

		if config.DryRun {
			logger.Info("[DRY RUN] Would inject logout handler",
				zap.String("domain", domain),
				zap.String("path", "/oauth2/sign_out"),
				zap.String("redirect", logoutURL))
			successCount++
			continue
		}

		// Inject handler via Caddy Admin API
		if err := injectLogoutHandler(rc, client, domain, logoutURL); err != nil {
			logger.Error("Failed to inject logout handler",
				zap.String("domain", domain),
				zap.Error(err))
			failureCount++
			continue
		}

		successCount++
	}

	// ========================================
	// EVALUATE: Report results
	// ========================================

	logger.Info("Phase 4/4: Logout handler deployment complete",
		zap.Int("success", successCount),
		zap.Int("failed", failureCount),
		zap.Int("total", len(protectedRoutes)))

	if config.DryRun {
		logger.Info("[DRY RUN] No changes applied - remove --dry-run to apply")
	} else if successCount > 0 {
		logger.Info("✓ Logout handlers deployed successfully (zero-downtime)")
		logger.Info("Test logout: curl https://your-domain.com/oauth2/sign_out")
	}

	if failureCount > 0 {
		return fmt.Errorf("%d/%d logout handlers failed to deploy", failureCount, len(protectedRoutes))
	}

	return nil
}

// findAuthentikProtectedRoutes finds all routes with forward_auth configured
func findAuthentikProtectedRoutes(config map[string]interface{}) ([]string, error) {
	var domains []string

	// Navigate to HTTP routes
	routes, err := getHTTPRoutes(config)
	if err != nil {
		return nil, err
	}

	// Iterate through routes
	for _, route := range routes {
		routeMap, ok := route.(map[string]interface{})
		if !ok {
			continue
		}

		// Check for match (domain matcher)
		matches, ok := routeMap["match"].([]interface{})
		if !ok || len(matches) == 0 {
			continue
		}

		// Extract domain from first matcher
		firstMatch, ok := matches[0].(map[string]interface{})
		if !ok {
			continue
		}

		hosts, ok := firstMatch["host"].([]interface{})
		if !ok || len(hosts) == 0 {
			continue
		}

		domain, ok := hosts[0].(string)
		if !ok {
			continue
		}

		// Check for forward_auth in handlers
		if hasForwardAuth(routeMap) {
			domains = append(domains, domain)
		}
	}

	return domains, nil
}

// hasForwardAuth checks if a route has forward_auth configured
func hasForwardAuth(route map[string]interface{}) bool {
	handle, ok := route["handle"].([]interface{})
	if !ok {
		return false
	}

	for _, h := range handle {
		handler, ok := h.(map[string]interface{})
		if !ok {
			continue
		}

		// Check for authentication handler
		if handler["handler"] == "authentication" {
			return true
		}

		// Check for subroute with forward_auth
		subroute, ok := handler["routes"].([]interface{})
		if ok {
			for _, sr := range subroute {
				srMap, ok := sr.(map[string]interface{})
				if ok && hasForwardAuth(srMap) {
					return true
				}
			}
		}
	}

	return false
}

// fetchAuthentikApplications fetches all applications from Authentik API
func fetchAuthentikApplications(rc *eos_io.RuntimeContext, host string, port int, token string) ([]AuthentikApplication, error) {
	logger := otelzap.Ctx(rc.Ctx)

	baseURL := fmt.Sprintf("http://%s:%d/api/v3/core/applications/", host, port)

	req, err := http.NewRequestWithContext(rc.Ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var response AuthentikApplicationResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	logger.Debug("Fetched Authentik applications",
		zap.Int("count", len(response.Results)))

	return response.Results, nil
}

// buildDomainSlugMapping maps domains to Authentik application slugs
// Uses heuristics: domain prefix matching, application name matching
func buildDomainSlugMapping(domains []string, applications []AuthentikApplication) map[string]string {
	mapping := make(map[string]string)

	for _, domain := range domains {
		// Try to match domain prefix with application slug
		domainPrefix := extractDomainPrefix(domain)

		for _, app := range applications {
			// Exact slug match
			if app.Slug == domainPrefix {
				mapping[domain] = app.Slug
				break
			}

			// Lowercase name match
			if strings.ToLower(app.Name) == domainPrefix {
				mapping[domain] = app.Slug
				break
			}
		}

		// If no match found, leave unmapped (will use fallback)
	}

	return mapping
}

// extractDomainPrefix extracts the first part of a domain
// Example: "chat.codemonkey.net.au" → "chat"
func extractDomainPrefix(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return domain
}

// buildLogoutURL constructs the Authentik logout URL
func buildLogoutURL(authentikHost, slug, returnDomain string) string {
	return fmt.Sprintf("https://%s/application/o/%s/end-session/?post_logout_redirect_uri=https://%s/",
		authentikHost, slug, returnDomain)
}

// injectLogoutHandler injects /oauth2/sign_out handler into a route via Caddy Admin API
func injectLogoutHandler(rc *eos_io.RuntimeContext, client *CaddyAdminClient, domain, logoutURL string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get current config
	config, err := client.GetConfig(rc.Ctx)
	if err != nil {
		return fmt.Errorf("failed to get config: %w", err)
	}

	// Find route index for this domain
	routes, err := getHTTPRoutes(config)
	if err != nil {
		return fmt.Errorf("failed to get routes: %w", err)
	}

	routeIndex := findRouteIndex(routes, domain)
	if routeIndex < 0 {
		return fmt.Errorf("route not found for domain: %s", domain)
	}

	// Build logout handler JSON
	logoutHandler := map[string]interface{}{
		"handle": []interface{}{
			map[string]interface{}{
				"handler": "subroute",
				"routes": []interface{}{
					map[string]interface{}{
						"handle": []interface{}{
							// Clear authentication cookie
							map[string]interface{}{
								"handler": "headers",
								"response": map[string]interface{}{
									"set": map[string]interface{}{
										"Set-Cookie": []string{
											"authentik_proxy=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax",
										},
									},
								},
							},
							// Redirect to Authentik logout
							map[string]interface{}{
								"handler":     "static_response",
								"status_code": "302",
								"headers": map[string]interface{}{
									"Location": []string{logoutURL},
								},
							},
						},
					},
				},
			},
		},
		"match": []interface{}{
			map[string]interface{}{
				"path": []string{"/oauth2/sign_out"},
			},
		},
	}

	// Prepend logout handler to route's handle array
	// This ensures it matches before forward_auth
	path := fmt.Sprintf("apps/http/servers/srv0/routes/%d/handle/0", routeIndex)

	if err := client.PatchConfig(rc.Ctx, path, logoutHandler); err != nil {
		return fmt.Errorf("failed to inject handler: %w", err)
	}

	logger.Info("✓ Injected logout handler",
		zap.String("domain", domain),
		zap.String("path", "/oauth2/sign_out"))

	return nil
}
