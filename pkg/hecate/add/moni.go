// pkg/hecate/add/moni.go - Moni-specific integration using Authentik OIDC + ForwardAuth

package add

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// MoniIntegrator implements service-specific integration for Moni
// ARCHITECTURE: Hybrid OIDC + ForwardAuth approach
// - OIDC provider for OAuth2 authentication (Authorization Code + PKCE)
// - ForwardAuth for header-based identity propagation (x-authentik-uid, x-authentik-email, etc.)
// - Stable identity via Authentik UUID (not username)
type MoniIntegrator struct {
	resources *IntegrationResources // Track created resources for rollback
}

func init() {
	// Register Moni integrator constructor
	// CRITICAL: Use constructor pattern to create fresh instance per invocation
	// This prevents resource leaks when rollback is triggered on multiple concurrent/sequential runs
	RegisterServiceIntegrator("moni", func() ServiceIntegrator {
		return &MoniIntegrator{
			resources: &IntegrationResources{},
		}
	})
}

// IsConfigured checks if Moni is FULLY configured (Caddyfile + Authentik OIDC)
// P1 #4: Plugin-based idempotency check instead of hardcoded service checks
// ARCHITECTURE: Comprehensive check - both routing layer AND OIDC provider must exist
func (m *MoniIntegrator) IsConfigured(rc *eos_io.RuntimeContext, opts *ServiceOptions) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check 1: Caddyfile route exists and is correct
	caddyfileOK, err := m.checkCaddyfileConfiguration(rc, opts.DNS)
	if err != nil {
		logger.Debug("Caddyfile check failed", zap.Error(err))
		return false, nil // Non-fatal - treat as not configured
	}

	if !caddyfileOK {
		logger.Debug("Caddyfile configuration incomplete or incorrect")
		return false, nil
	}

	// Check 2: Authentik OIDC provider configured
	authentikToken, authentikURL, err := m.getAuthentikCredentials(rc.Ctx)
	if err != nil {
		return false, fmt.Errorf("failed to get Authentik credentials: %w", err)
	}

	// Connect to Authentik API
	authentikClient := authentik.NewClient(authentikURL, authentikToken)

	// Check if Moni OAuth2 provider exists
	providers, err := authentikClient.ListOAuth2Providers(rc.Ctx)
	if err != nil {
		return false, fmt.Errorf("failed to list Authentik OAuth2 providers: %w", err)
	}

	providerName := "Moni OIDC"
	for _, provider := range providers {
		if provider.Name == providerName {
			logger.Debug("Moni fully configured (Caddyfile + Authentik OIDC)",
				zap.String("provider_name", provider.Name),
				zap.String("client_id", provider.ClientID))
			return true, nil // Both Caddyfile AND OIDC provider are configured
		}
	}

	logger.Debug("Moni OIDC provider not found in Authentik",
		zap.String("expected_provider_name", providerName))
	return false, nil
}

// checkCaddyfileConfiguration verifies Caddyfile has correct route with headers
// Returns true only if: route exists, no duplicates, required headers present
func (m *MoniIntegrator) checkCaddyfileConfiguration(rc *eos_io.RuntimeContext, dns string) (bool, error) {
	content, err := os.ReadFile(hecate.CaddyfilePath)
	if err != nil {
		return false, fmt.Errorf("failed to read Caddyfile: %w", err)
	}

	caddyfileContent := string(content)

	// Check 1: Route exists (at least once)
	dnsPattern := fmt.Sprintf("\n%s {", dns)
	count := strings.Count(caddyfileContent, dnsPattern)

	if count == 0 {
		return false, nil // Route doesn't exist
	}

	if count > 1 {
		return false, nil // Duplicates exist - not correctly configured
	}

	// Check 2: Required headers for Moni (stable identity propagation)
	requiredHeaders := []string{
		"header_up X-Authentik-Uid",      // Stable UUID (required by Moni)
		"header_up X-Authentik-Email",    // User email
		"header_up X-Authentik-Name",     // User display name
		"header_up X-Auth-Request-Groups", // Group membership for authz
	}

	for _, header := range requiredHeaders {
		if !strings.Contains(caddyfileContent, header) {
			return false, nil // Missing critical header mapping
		}
	}

	// All checks passed - route exists, no duplicates, headers present
	return true, nil
}

// ValidateService checks if Moni is running at the backend address
// RESEARCH: Moni health endpoint strategy
// Strategy: Check /health or root path, accept 200/401/403 as proof service is running
func (m *MoniIntegrator) ValidateService(rc *eos_io.RuntimeContext, opts *ServiceOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("  [1/4] Validating Moni is running at backend", zap.String("backend", opts.Backend))

	// DRY-RUN: Skip network validation, just preview what would be checked
	if opts.DryRun {
		backend := opts.Backend
		if !strings.Contains(backend, ":") {
			backend = backend + ":8080"
		}
		if !strings.HasPrefix(backend, "http://") && !strings.HasPrefix(backend, "https://") {
			backend = "http://" + backend
		}
		logger.Info("  [DRY RUN] Would validate Moni is accessible at: " + backend)
		logger.Info("  [DRY RUN] Would check endpoints: /health, /")
		return nil
	}

	// Add default port if not specified
	backend := opts.Backend
	if !strings.Contains(backend, ":") {
		logger.Warn("No port specified in --upstream, using Moni default",
			zap.String("default_port", "8080"))
		backend = backend + ":8080"
	}

	// Ensure http:// or https:// prefix
	if !strings.HasPrefix(backend, "http://") && !strings.HasPrefix(backend, "https://") {
		backend = "http://" + backend
	}

	// Try /health endpoint first
	healthURL := backend + "/health"
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(healthURL)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			logger.Info("  ✓ Moni health check passed", zap.String("url", healthURL))
			return nil
		}
	}

	// Fallback: Try root path
	rootURL := backend + "/"
	resp, err = client.Get(rootURL)
	if err != nil {
		return eos_err.NewUserError(
			"Cannot reach Moni at %s\n\n"+
				"Troubleshooting:\n"+
				"  1. Check Moni is running: docker ps | grep moni\n"+
				"  2. Verify port: docker port <moni-container>\n"+
				"  3. Test manually: curl -I %s\n\n"+
				"Error: %v",
			backend, backend, err)
	}
	defer resp.Body.Close()

	// Accept 200, 401, 403 as proof service is running
	acceptableCodes := []int{http.StatusOK, http.StatusUnauthorized, http.StatusForbidden}
	for _, code := range acceptableCodes {
		if resp.StatusCode == code {
			logger.Info("  ✓ Moni is running (returned expected status)",
				zap.Int("status_code", resp.StatusCode),
				zap.String("url", rootURL))
			return nil
		}
	}

	return eos_err.NewUserError(
		"Moni returned unexpected status %d from %s\n"+
			"Expected: 200, 401, or 403\n"+
			"Check if Moni is correctly configured and running",
		resp.StatusCode, rootURL)
}

// ConfigureAuthentication sets up Authentik OIDC provider, groups, and property mappings for Moni
// ASSESS → INTERVENE → EVALUATE pattern
func (m *MoniIntegrator) ConfigureAuthentication(rc *eos_io.RuntimeContext, opts *ServiceOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("  [2/4] Configuring Authentik OIDC for Moni")

	// DRY-RUN: Preview what would be created without making API calls
	if opts.DryRun {
		adminGroup := opts.AdminGroup
		if adminGroup == "" {
			adminGroup = "moni-admin"
		}
		logger.Info("  [DRY RUN] Would create the following Authentik resources:")
		logger.Info("    - Admin group: " + adminGroup + " (if not exists)")
		logger.Info("    - OIDC scope mappings: openid, profile, email (use managed), groups (custom)")
		logger.Info("    - OAuth2/OIDC provider: Moni OIDC")
		logger.Info("      - Client type: confidential")
		logger.Info("      - Sub mode: user_uuid (stable identity)")
		logger.Info("      - Redirect URIs: https://" + opts.DNS + "/auth/callback")
		logger.Info("    - Authentik application: Moni (slug: moni)")
		logger.Info("      - Launch URL: https://" + opts.DNS)
		logger.Info("")
		logger.Info("  [DRY RUN] Would print OIDC credentials (client_id, client_secret)")
		return nil
	}

	// ASSESS: Get Authentik credentials
	authentikToken, authentikURL, err := m.getAuthentikCredentials(rc.Ctx)
	if err != nil {
		return fmt.Errorf("failed to get Authentik credentials: %w", err)
	}

	// Connect to Authentik API
	authentikClient := authentik.NewClient(authentikURL, authentikToken)

	// Step 1: Create admin group (if doesn't exist)
	adminGroup := opts.AdminGroup
	if adminGroup == "" {
		adminGroup = "moni-admin" // Default
	}

	logger.Info("    Creating admin group", zap.String("group", adminGroup))
	groupExists, err := authentikClient.GroupExists(rc.Ctx, adminGroup)
	if err != nil {
		return fmt.Errorf("failed to check if group exists: %w", err)
	}

	if !groupExists {
		groupResp, err := authentikClient.CreateGroup(rc.Ctx, adminGroup, nil)
		if err != nil {
			return fmt.Errorf("failed to create admin group: %w", err)
		}
		logger.Info("    ✓ Created admin group", zap.String("group", adminGroup), zap.String("pk", groupResp.PK))
		m.resources.GroupPKs = append(m.resources.GroupPKs, groupResp.PK) // Track for rollback
	} else {
		logger.Info("    ✓ Admin group already exists", zap.String("group", adminGroup))
	}

	// Step 2: Create OIDC property mappings (claims)
	logger.Info("    Creating OIDC property mappings (claims)")
	mappingPKs, err := authentikClient.CreateMoniOIDCMappings(rc.Ctx)
	if err != nil {
		return fmt.Errorf("failed to create OIDC property mappings: %w", err)
	}
	logger.Info("    ✓ Created/verified OIDC property mappings", zap.Int("count", len(mappingPKs)))

	// Track custom property mappings for rollback (managed scopes are NOT cleaned up)
	// P0-3 FIX: Track only the LAST mapping (custom "groups" scope), not managed ones
	if len(mappingPKs) > 0 {
		customMappingPK := mappingPKs[len(mappingPKs)-1] // Last one is custom "groups" scope
		m.resources.PropertyMappingPKs = append(m.resources.PropertyMappingPKs, customMappingPK)
	}

	// Step 3: Get default authorization flow
	logger.Info("    Fetching default authorization flow")
	flow, err := m.getDefaultAuthFlow(rc.Ctx, authentikClient)
	if err != nil {
		return fmt.Errorf("failed to get default authorization flow: %w", err)
	}
	logger.Info("    ✓ Using authorization flow", zap.String("flow", flow))

	// Step 4: Create OAuth2/OIDC provider
	providerName := "Moni OIDC"
	redirectURIs := []string{
		fmt.Sprintf("https://%s/auth/callback", opts.DNS),
		fmt.Sprintf("https://%s/api/auth/callback/authentik", opts.DNS),
	}

	logger.Info("    Creating OAuth2/OIDC provider",
		zap.String("provider_name", providerName),
		zap.Strings("redirect_uris", redirectURIs))

	provider, err := authentikClient.CreateOAuth2ProviderWithMappings(
		rc.Ctx,
		providerName,
		redirectURIs,
		flow,
		mappingPKs,
	)
	if err != nil {
		return fmt.Errorf("failed to create OAuth2 provider: %w", err)
	}

	logger.Info("    ✓ Created OAuth2/OIDC provider",
		zap.String("provider_name", provider.Name),
		zap.String("client_id", provider.ClientID))

	m.resources.ProxyProviderPK = provider.PK // Track for rollback

	// Step 5: Create Authentik application
	appName := "Moni"
	appSlug := "moni"
	launchURL := fmt.Sprintf("https://%s", opts.DNS)

	logger.Info("    Creating Authentik application",
		zap.String("app_name", appName),
		zap.String("slug", appSlug),
		zap.String("launch_url", launchURL))

	app, err := m.createAuthentikApplication(rc.Ctx, authentikClient, appName, appSlug, launchURL, provider.PK)
	if err != nil {
		return fmt.Errorf("failed to create Authentik application: %w", err)
	}

	logger.Info("    ✓ Created Authentik application", zap.String("slug", app.Slug))
	m.resources.ApplicationPK = app.PK // Track for rollback
	m.resources.ApplicationSlug = app.Slug

	// EVALUATE: Print OIDC credentials for user
	// SECURITY: Sanitize client secret - show prefix only, not full value
	sanitizedSecret := provider.ClientSecret
	if len(sanitizedSecret) > 12 {
		sanitizedSecret = sanitizedSecret[:12] + "..." + " (full value shown below)"
	}

	logger.Info("\n")
	logger.Info("════════════════════════════════════════════════════════════════")
	logger.Info("  Moni OIDC Configuration Complete")
	logger.Info("════════════════════════════════════════════════════════════════")
	logger.Info("")
	logger.Info("  Add these to your Moni configuration:")
	logger.Info("")
	logger.Info("  AUTHENTIK_CLIENT_ID:     " + provider.ClientID)
	logger.Info("  AUTHENTIK_CLIENT_SECRET: " + sanitizedSecret) // Sanitized for telemetry
	logger.Info("  AUTHENTIK_ISSUER:        " + authentikURL + "/application/o/" + appSlug + "/")
	logger.Info("  AUTHENTIK_REDIRECT_URI:  https://" + opts.DNS + "/auth/callback")
	logger.Info("")
	logger.Info("  Admin group: " + adminGroup)
	logger.Info("")
	logger.Info("════════════════════════════════════════════════════════════════")
	logger.Info("\n")

	// P0-5 FIX: Print full client secret to terminal ONLY using fmt.Println
	// CRITICAL: logger.Info() logs to BOTH terminal AND telemetry
	// We MUST use fmt.Println() to keep secret out of telemetry system
	fmt.Println("  Full client secret (copy this to your Moni configuration):")
	fmt.Println("  " + provider.ClientSecret)
	fmt.Println("")
	fmt.Println("  SECURITY: This secret will NOT be shown again. Store it securely.")
	fmt.Println("")

	return nil
}

// ConfigureCaddy adds Moni route to Caddyfile with ForwardAuth headers
func (m *MoniIntegrator) ConfigureCaddy(rc *eos_io.RuntimeContext, opts *ServiceOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("  [3/4] Adding Moni route to Caddyfile")

	// DRY-RUN: Preview Caddyfile changes without modifying
	if opts.DryRun {
		logger.Info("  [DRY RUN] Would add the following Caddyfile route:")
		logger.Info("    DNS: " + opts.DNS)
		logger.Info("    Backend: " + opts.Backend)
		logger.Info("    Auth: Authentik ForwardAuth at /outpost.goauthentik.io/auth/caddy")
		logger.Info("    Headers: X-Authentik-Uid, X-Authentik-Email, X-Authentik-Name, X-Auth-Request-Groups")
		logger.Info("  [DRY RUN] Caddyfile would be written to: " + hecate.CaddyfilePath)
		logger.Info("  [DRY RUN] Would reload Caddy after changes")
		return nil
	}

	// Generate Caddyfile snippet for Moni
	// ARCHITECTURE: Caddy forwards requests to Authentik for authentication,
	// then passes identity headers to Moni backend
	snippet := fmt.Sprintf(`
%s {
	# Moni - AI Chat Platform
	# Authentication: Authentik ForwardAuth
	# Identity headers: x-authentik-uid (stable UUID), email, name, groups

	forward_auth authentik:9000 {
		uri /outpost.goauthentik.io/auth/caddy
		copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Email X-Authentik-Name X-Authentik-Uid

		# Pass identity headers to upstream
		header_up X-Authentik-Uid {http.request.header.X-Authentik-Uid}
		header_up X-Authentik-Email {http.request.header.X-Authentik-Email}
		header_up X-Authentik-Name {http.request.header.X-Authentik-Name}
		header_up X-Auth-Request-Groups {http.request.header.X-Authentik-Groups}
	}

	reverse_proxy %s
}
`, opts.DNS, opts.Backend)

	// Read current Caddyfile
	content, err := os.ReadFile(hecate.CaddyfilePath)
	if err != nil {
		return fmt.Errorf("failed to read Caddyfile: %w", err)
	}

	caddyfileContent := string(content)

	// Check for duplicates
	dnsPattern := fmt.Sprintf("\n%s {", opts.DNS)
	if strings.Contains(caddyfileContent, dnsPattern) {
		logger.Warn("  ⚠ Route already exists in Caddyfile, skipping", zap.String("dns", opts.DNS))
		return nil
	}

	// Append snippet
	updatedContent := caddyfileContent + "\n" + snippet

	// Write back to file
	if err := os.WriteFile(hecate.CaddyfilePath, []byte(updatedContent), 0644); err != nil {
		return fmt.Errorf("failed to write Caddyfile: %w", err)
	}

	logger.Info("    ✓ Added Moni route to Caddyfile", zap.String("dns", opts.DNS))

	// Reload Caddy configuration
	logger.Info("    Reloading Caddy configuration")
	if err := hecate.ReloadCaddy(rc); err != nil {
		return fmt.Errorf("failed to reload Caddy: %w", err)
	}
	logger.Info("    ✓ Caddy reloaded successfully")

	return nil
}

// PostInstall performs post-installation tasks (e.g., prompt to add user to admin group)
func (m *MoniIntegrator) PostInstall(rc *eos_io.RuntimeContext, opts *ServiceOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("  [4/4] Post-installation tasks")

	adminGroup := opts.AdminGroup
	if adminGroup == "" {
		adminGroup = "moni-admin"
	}

	logger.Info("\n")
	logger.Info("════════════════════════════════════════════════════════════════")
	logger.Info("  Next Steps")
	logger.Info("════════════════════════════════════════════════════════════════")
	logger.Info("")
	logger.Info("  1. Add your user to the admin group:")
	logger.Info("     eos update authentik --add-user-to-group <username> " + adminGroup)
	logger.Info("")
	logger.Info("  2. Test Moni login:")
	logger.Info("     Open: https://" + opts.DNS)
	logger.Info("")
	logger.Info("  3. Verify stable identity (sub claim):")
	logger.Info("     - Login to Moni")
	logger.Info("     - Check that your user ID remains the same across logins")
	logger.Info("")
	logger.Info("════════════════════════════════════════════════════════════════")
	logger.Info("\n")

	return nil
}

// HealthCheck verifies Authentik OIDC configuration
func (m *MoniIntegrator) HealthCheck(rc *eos_io.RuntimeContext, opts *ServiceOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("  [4/4] Verifying Authentik OIDC configuration")

	// DRY-RUN: Skip actual health check, just preview
	if opts.DryRun {
		logger.Info("  [DRY RUN] Would verify:")
		logger.Info("    - Authentik is accessible")
		logger.Info("    - OAuth2 provider 'Moni OIDC' exists")
		logger.Info("    - Provider has correct configuration")
		logger.Info("  ✓ Health check would be performed")
		return nil
	}

	// Basic check: verify Authentik OIDC provider exists
	authentikToken, authentikURL, err := m.getAuthentikCredentials(rc.Ctx)
	if err != nil {
		return fmt.Errorf("failed to get Authentik credentials: %w", err)
	}

	authentikClient := authentik.NewClient(authentikURL, authentikToken)

	// Verify OAuth2 provider exists
	providers, err := authentikClient.ListOAuth2Providers(rc.Ctx)
	if err != nil {
		return fmt.Errorf("failed to list OAuth2 providers: %w", err)
	}

	providerFound := false
	for _, provider := range providers {
		if provider.Name == "Moni OIDC" {
			providerFound = true
			logger.Info("    ✓ Moni OIDC provider verified", zap.String("client_id", provider.ClientID))
			break
		}
	}

	if !providerFound {
		return fmt.Errorf("Moni OIDC provider not found - configuration may have failed")
	}

	logger.Info("  ✓ Health check passed")
	return nil
}

// Rollback removes all created resources if integration fails
// P0-2 FIX: Improved error handling, complete cleanup, manual remediation instructions
func (m *MoniIntegrator) Rollback(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Warn("Rolling back Moni integration due to error")

	// Get Authentik credentials
	authentikToken, authentikURL, err := m.getAuthentikCredentials(rc.Ctx)
	if err != nil {
		logger.Error("Failed to get Authentik credentials for rollback", zap.Error(err))
		logger.Error("MANUAL CLEANUP REQUIRED: Login to Authentik UI and remove Moni resources")
		logger.Error("  Authentik UI: " + authentikURL + "/if/admin")
		return fmt.Errorf("rollback failed: cannot authenticate to Authentik: %w", err)
	}

	authentikClient := authentik.NewClient(authentikURL, authentikToken)

	// Track rollback errors to return aggregated error
	var rollbackErrors []string

	// Remove application (P0-2 FIX: Now implemented)
	if m.resources.ApplicationSlug != "" {
		logger.Info("  Removing application", zap.String("slug", m.resources.ApplicationSlug))
		if err := authentikClient.DeleteApplication(rc.Ctx, m.resources.ApplicationSlug); err != nil {
			errMsg := fmt.Sprintf("application deletion failed: %v", err)
			rollbackErrors = append(rollbackErrors, errMsg)
			logger.Error("Failed to delete application",
				zap.String("slug", m.resources.ApplicationSlug),
				zap.Error(err),
				zap.String("remediation", "Manual cleanup: Authentik UI → Applications → Delete 'Moni'"))
		} else {
			logger.Info("  ✓ Removed application", zap.String("slug", m.resources.ApplicationSlug))
		}
	}

	// Remove OAuth2 provider
	if m.resources.ProxyProviderPK != 0 {
		logger.Info("  Removing OAuth2 provider", zap.Int("pk", m.resources.ProxyProviderPK))
		if err := authentikClient.DeleteOAuth2Provider(rc.Ctx, m.resources.ProxyProviderPK); err != nil {
			errMsg := fmt.Sprintf("OAuth2 provider deletion failed (PK %d): %v", m.resources.ProxyProviderPK, err)
			rollbackErrors = append(rollbackErrors, errMsg)
			logger.Error("Failed to delete OAuth2 provider",
				zap.Int("pk", m.resources.ProxyProviderPK),
				zap.Error(err),
				zap.String("remediation", "Manual cleanup: Authentik UI → Providers → OAuth2 → Delete 'Moni OIDC'"))
		} else {
			logger.Info("  ✓ Removed OAuth2 provider", zap.Int("pk", m.resources.ProxyProviderPK))
		}
	}

	// Remove custom property mappings (P0-3 FIX)
	// SECURITY: Only custom mappings tracked, managed Authentik scopes are NOT deleted
	if len(m.resources.PropertyMappingPKs) > 0 {
		logger.Info("  Removing custom OIDC property mappings", zap.Int("count", len(m.resources.PropertyMappingPKs)))
		for _, pk := range m.resources.PropertyMappingPKs {
			if err := authentikClient.DeleteOIDCPropertyMapping(rc.Ctx, pk); err != nil {
				errMsg := fmt.Sprintf("property mapping deletion failed (PK %s): %v", pk, err)
				rollbackErrors = append(rollbackErrors, errMsg)
				logger.Error("Failed to delete property mapping",
					zap.String("pk", pk),
					zap.Error(err),
					zap.String("remediation", "Manual cleanup: Authentik UI → Customization → Property Mappings → Delete 'OIDC Groups Scope'"))
			} else {
				logger.Info("  ✓ Removed property mapping", zap.String("pk", pk))
			}
		}
	}

	// Groups are NOT removed during rollback (could be used by other services)
	// RATIONALE: Admin groups may be shared across multiple services
	if len(m.resources.GroupPKs) > 0 {
		logger.Info("  Groups NOT removed (may be used by other services)", zap.Strings("group_pks", m.resources.GroupPKs))
		logger.Info("  To manually remove groups: Authentik UI → Directory → Groups")
	}

	// Log completion status
	if len(rollbackErrors) > 0 {
		logger.Error("Rollback completed with errors", zap.Int("error_count", len(rollbackErrors)))
		logger.Error("Manual cleanup required - see errors above for remediation steps")
		logger.Error("Authentik UI: " + authentikURL + "/if/admin")
		return fmt.Errorf("rollback completed with %d errors: %s", len(rollbackErrors), strings.Join(rollbackErrors, "; "))
	}

	logger.Info("Rollback completed successfully")
	return nil
}

// getAuthentikCredentials retrieves Authentik API credentials from /opt/hecate/.env
// PATTERN: Reuses existing BionicGPT credential discovery logic
func (m *MoniIntegrator) getAuthentikCredentials(ctx context.Context) (token, url string, err error) {
	// Read /opt/hecate/.env
	envPath := "/opt/hecate/.env"
	content, readErr := os.ReadFile(envPath)
	if readErr != nil {
		return "", "", fmt.Errorf("failed to read %s: %w", envPath, readErr)
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "AUTHENTIK_BOOTSTRAP_TOKEN=") {
			token = strings.TrimPrefix(line, "AUTHENTIK_BOOTSTRAP_TOKEN=")
			token = strings.Trim(token, "\"' ")
		}
		if strings.HasPrefix(line, "AUTHENTIK_BASE_URL=") {
			url = strings.TrimPrefix(line, "AUTHENTIK_BASE_URL=")
			url = strings.Trim(url, "\"' ")
		}
	}

	if token == "" {
		return "", "", fmt.Errorf("AUTHENTIK_BOOTSTRAP_TOKEN not found in %s", envPath)
	}
	if url == "" {
		return "", "", fmt.Errorf("AUTHENTIK_BASE_URL not found in %s", envPath)
	}

	return token, url, nil
}

// getDefaultAuthFlow retrieves the default authorization flow from Authentik
func (m *MoniIntegrator) getDefaultAuthFlow(ctx context.Context, client *authentik.APIClient) (string, error) {
	// Use default-authentication-flow (most common)
	// TODO: Make this configurable if needed
	return "default-authentication-flow", nil
}

// createAuthentikApplication creates an Authentik application linked to the OIDC provider
func (m *MoniIntegrator) createAuthentikApplication(ctx context.Context, client *authentik.APIClient, name, slug, launchURL string, providerPK int) (*authentik.ApplicationResponse, error) {
	// Check if application already exists
	apps, err := client.ListApplications(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list applications: %w", err)
	}

	for _, app := range apps {
		if app.Slug == slug {
			// Application already exists
			return &app, nil
		}
	}

	// Create new application
	app, err := client.CreateApplication(ctx, name, slug, providerPK, launchURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create application: %w", err)
	}

	return app, nil
}
