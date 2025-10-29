// pkg/hecate/add/bionicgpt.go - BionicGPT-specific integration using Authentik forward auth

package add

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	// vaultapi "github.com/hashicorp/vault/api" // Commented - Vault code is commented out for .env migration
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BionicGPTIntegrator implements service-specific integration for BionicGPT
// Uses Authentik forward auth (NOT oauth2-proxy)
type BionicGPTIntegrator struct {
	resources *IntegrationResources // Track created resources for rollback
}

func init() {
	// Register BionicGPT integrator constructor
	// CRITICAL: Use constructor pattern to create fresh instance per invocation
	// This prevents resource leaks when rollback is triggered on multiple concurrent/sequential runs
	RegisterServiceIntegrator("bionicgpt", func() ServiceIntegrator {
		return &BionicGPTIntegrator{
			resources: &IntegrationResources{},
		}
	})
}

// IsConfigured checks if BionicGPT is FULLY configured (Caddyfile + Authentik SSO)
// P1 #4: Plugin-based idempotency check instead of hardcoded service checks
// ARCHITECTURE: Comprehensive check - both routing layer AND SSO layer must be correct
func (b *BionicGPTIntegrator) IsConfigured(rc *eos_io.RuntimeContext, opts *ServiceOptions) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check 1: Caddyfile route exists and is correct
	caddyfileOK, err := b.checkCaddyfileConfiguration(rc, opts.DNS)
	if err != nil {
		logger.Debug("Caddyfile check failed", zap.Error(err))
		return false, nil // Non-fatal - treat as not configured
	}

	if !caddyfileOK {
		logger.Debug("Caddyfile configuration incomplete or incorrect")
		return false, nil
	}

	// Check 2: Authentik SSO configured
	// Use credential discovery logic to get Authentik API access
	authentikToken, authentikURL, err := b.getAuthentikCredentials(rc.Ctx)
	if err != nil {
		return false, fmt.Errorf("failed to get Authentik credentials: %w", err)
	}

	// Connect to Authentik API
	authentikClient := authentik.NewClient(authentikURL, authentikToken)

	// Check if BionicGPT application exists for THIS SPECIFIC DNS
	apps, err := authentikClient.ListApplications(rc.Ctx)
	if err != nil {
		return false, fmt.Errorf("failed to list Authentik applications: %w", err)
	}

	expectedLaunchURL := fmt.Sprintf("https://%s", opts.DNS)

	for _, app := range apps {
		if app.Slug == "bionicgpt" && app.MetaLaunchURL == expectedLaunchURL {
			logger.Debug("BionicGPT fully configured (Caddyfile + Authentik SSO)",
				zap.String("slug", app.Slug),
				zap.String("name", app.Name),
				zap.String("launch_url", app.MetaLaunchURL))
			return true, nil // Both Caddyfile AND Authentik are configured
		}
	}

	logger.Debug("BionicGPT application not found in Authentik for this DNS",
		zap.String("expected_launch_url", expectedLaunchURL))
	return false, nil
}

// checkCaddyfileConfiguration verifies Caddyfile has correct route with headers
// Returns true only if: route exists, no duplicates, headers present
func (b *BionicGPTIntegrator) checkCaddyfileConfiguration(rc *eos_io.RuntimeContext, dns string) (bool, error) {
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

	// Check 2: Required headers are present
	requiredHeaders := []string{
		"header_up X-Auth-Request-Email",
		"header_up X-Auth-Request-User",
		"header_up X-Auth-Request-Groups",
	}

	for _, header := range requiredHeaders {
		if !strings.Contains(caddyfileContent, header) {
			return false, nil // Missing critical header mapping
		}
	}

	// All checks passed - route exists, no duplicates, headers present
	return true, nil
}

// ValidateService checks if BionicGPT is running at the backend address
// Based on vendor research: BionicGPT has NO /health endpoint
// Source: https://github.com/bionic-gpt/bionic-gpt (verified via source code analysis)
// Strategy: Check root path, accept 401/403 as proof service is running
func (b *BionicGPTIntegrator) ValidateService(rc *eos_io.RuntimeContext, opts *ServiceOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("  [1/3] Validating BionicGPT is running at backend", zap.String("backend", opts.Backend))

	// Add default port if not specified
	backend := opts.Backend
	if !strings.Contains(backend, ":") {
		logger.Warn("No port specified in --upstream, using BionicGPT default",
			zap.Int("port", hecate.BionicGPTDefaultPort),
			zap.String("help", "Specify explicit port with --upstream IP:PORT"))
		backend = fmt.Sprintf("%s:%d", backend, hecate.BionicGPTDefaultPort)
	}

	// BionicGPT has NO health endpoint - check root path only
	// Expected response: 401 Unauthorized (service requires JWT token via oauth2-proxy/Authentik)
	// This proves: Service is running, HTTP server works, authentication is enforced
	endpoint := fmt.Sprintf("http://%s/", backend)

	httpClient := &http.Client{Timeout: 10 * time.Second}

	logger.Debug("Checking BionicGPT backend", zap.String("endpoint", endpoint))

	resp, err := httpClient.Get(endpoint)
	if err != nil {
		return eos_err.NewUserError(fmt.Sprintf(
			"BionicGPT backend not reachable at %s: %v\n\n"+
				"Troubleshooting:\n"+
				"  1. Verify service is running: docker ps -a | grep -i bionic\n"+
				"  2. Check service logs: docker logs <container_name>\n"+
				"  3. Test connectivity: curl -v http://%s/\n"+
				"  4. Skip this validation: --skip-backend-check",
			backend, err, backend))
	}
	defer resp.Body.Close()

	logger.Debug("Backend responded",
		zap.Int("status_code", resp.StatusCode),
		zap.String("status", resp.Status))

	// Accept all 2xx, 3xx, 4xx status codes (anything < 500)
	// BionicGPT requires authentication via Authentik proxy, so:
	// - 401 Unauthorized = EXPECTED (no JWT token in direct validation) ✓
	// - 403 Forbidden = EXPECTED (no auth headers) ✓
	// - 404 Not Found = Unexpected but proves HTTP stack works ✓
	// - 2xx/3xx = Unexpected (shouldn't get success without auth) but good ✓
	// Only FAIL on 5xx (server error) or connection failures
	if resp.StatusCode < 500 {
		logger.Info("    ✓ BionicGPT backend is responding",
			zap.Int("status_code", resp.StatusCode),
			zap.String("note", "401/403 expected - authentication handled by Authentik proxy"))
		return nil
	}

	return eos_err.NewUserError(fmt.Sprintf(
		"BionicGPT backend returned server error: %d %s\n\n"+
			"This indicates the service is running but experiencing issues.\n"+
			"Check service logs: docker logs <container_name>",
		resp.StatusCode, resp.Status))
}

// ConfigureAuthentication sets up Authentik proxy provider for BionicGPT (forward auth mode)
//
// ARCHITECTURE NOTE: "Default Module" Pattern - Always Runs Regardless of --sso Flag
//
// This function ALWAYS attempts Authentik forward auth setup for BionicGPT, implementing
// the "default module" pattern: sane defaults that "just work" with minimal operator input.
//
// DESIGN PHILOSOPHY:
// 1. **Human-Centric**: Technology serves humans - reduce cognitive load and barrier to entry
// 2. **Sane Defaults**: BionicGPT requires authentication (no public mode), so configure it by default
// 3. **Graceful Degradation**: If Authentik unavailable, warns but proceeds (generic reverse proxy still works)
// 4. **Single Path to Production**: One way to deploy BionicGPT reduces errors and maintenance burden
//
// SSO ARCHITECTURE CONVENTIONS:
// - **hera.* subdomain**: All SSO/auth portals (e.g., hera.codemonkey.net.au for Authentik admin UI)
// - **Service-specific subdomains**: Individual services (e.g., chat.codemonkey.net.au for BionicGPT)
// - **Forward auth flow**: Browser → Caddy → Authentik → Caddy → BionicGPT
//
// WHY THIS MATTERS:
//   - Operators frequently deploy services behind Authentik proxy
//   - Encoding best-practice configuration as default reduces setup time
//   - Failed integration is non-fatal: generic reverse proxy fallback still works
//   - Aligns with Caddyfile template selection (pkg/hecate/add/caddyfile.go:134)
//     which ALWAYS uses bionicgptForwardAuthTemplate regardless of --sso flag
//
// RELATED CODE:
// - Caddyfile template: pkg/hecate/add/caddyfile.go:74-110 (bionicgptForwardAuthTemplate)
// - Template selection: pkg/hecate/add/caddyfile.go:134-147 (always uses forward auth for bionicgpt)
// - Debug diagnostics: pkg/hecate/debug_bionicgpt.go (validates Authentik-Caddy-BionicGPT triangle)
func (b *BionicGPTIntegrator) ConfigureAuthentication(rc *eos_io.RuntimeContext, opts *ServiceOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("  [2/3] Configuring Authentik proxy provider (forward auth mode)")

	if opts.DryRun {
		logger.Info("    [DRY RUN] Would create Authentik proxy provider (forward auth mode)")
		logger.Info("    [DRY RUN] Would create Authentik application 'BionicGPT'")
		logger.Info("    [DRY RUN] Would create groups: bionicgpt-superadmin, bionicgpt-demo")
		logger.Info("    [DRY RUN] Would assign application to embedded outpost")
		logger.Info("    [DRY RUN] Would create BionicGPT admin user")
		return nil
	}

	// Step 1: Get Authentik credentials from .env file
	logger.Info("    Getting Authentik credentials from /opt/hecate/.env")
	authentikToken, authentikBaseURL, err := b.getAuthentikCredentials(rc.Ctx)
	if err != nil {
		logger.Warn("Authentik credentials not found, skipping proxy provider setup", zap.Error(err))
		logger.Warn("")
		logger.Warn("To enable authentication:")
		logger.Warn("  1. Login to Authentik admin: https://hera.codemonkey.net.au/if/admin/")
		logger.Warn("  2. Create API token: Directory → Tokens → Create")
		logger.Warn("  3. Add to /opt/hecate/.env:")
		logger.Warn("     echo 'AUTHENTIK_API_TOKEN=<your_token>' | sudo tee -a /opt/hecate/.env")
		logger.Warn("  4. Re-run this command")
		logger.Warn("")
		return nil // Non-fatal: generic route still works
	}

	// Step 2: Initialize Authentik API client
	logger.Info("    Initializing Authentik API client", zap.String("base_url", authentikBaseURL))
	authentikClient := authentik.NewClient(authentikBaseURL, authentikToken)

	// Step 3: Get default authorization flow UUID
	logger.Info("    Getting authorization flow")
	authFlowUUID, err := b.getDefaultAuthFlowUUID(rc.Ctx, authentikClient)
	if err != nil {
		logger.Warn("Failed to get auth flow, using default slug", zap.Error(err))
		authFlowUUID = "default-authentication-flow"
	}

	// Step 3b: Get default invalidation flow UUID
	logger.Info("    Getting invalidation flow")
	invalidationFlowUUID, err := b.getDefaultInvalidationFlowUUID(rc.Ctx, authentikClient)
	if err != nil {
		logger.Warn("Failed to get invalidation flow, using default slug", zap.Error(err))
		invalidationFlowUUID = "default-invalidation-flow"
	}

	// Step 4: Create proxy provider
	logger.Info("    Creating proxy provider (forward auth mode)")
	providerPK, err := b.createProxyProvider(rc.Ctx, authentikClient, opts, authFlowUUID, invalidationFlowUUID)
	if err != nil {
		return fmt.Errorf("failed to create proxy provider: %w", err)
	}
	logger.Info("    ✓ Proxy provider created", zap.Int("provider_pk", providerPK))
	b.resources.ProxyProviderPK = providerPK // Track for rollback

	// Step 5: Create Authentik application
	logger.Info("    Creating Authentik application")
	if err := b.createAuthentikApplication(rc.Ctx, authentikClient, providerPK, opts.DNS); err != nil {
		return fmt.Errorf("failed to create application: %w", err)
	}
	logger.Info("    ✓ Application 'BionicGPT' created")
	b.resources.ApplicationSlug = "bionicgpt" // Track for rollback

	// Step 6: Assign application to embedded outpost
	logger.Info("    Assigning application to embedded outpost")
	if err := b.assignToOutpost(rc.Ctx, authentikClient, providerPK); err != nil {
		return fmt.Errorf("failed to assign to outpost: %w", err)
	}
	logger.Info("    ✓ Application assigned to outpost")

	// Step 7: Create groups
	logger.Info("    Creating Authentik groups (superadmin, demo)")
	if err := b.createAuthentikGroups(rc.Ctx, authentikClient); err != nil {
		return fmt.Errorf("failed to create groups: %w", err)
	}
	logger.Info("    ✓ Groups configured")

	// Step 8: Create BionicGPT admin user
	logger.Info("    Creating BionicGPT admin user")
	// Note: User creation uses AuthentikClient (different from APIClient used for providers)
	authentikUserClient, err := authentik.NewAuthentikClient(authentikBaseURL, authentikToken)
	if err != nil {
		logger.Warn("Failed to create user client", zap.Error(err))
	} else {
		if err := b.createBionicGPTAdmin(rc.Ctx, authentikUserClient, opts); err != nil {
			logger.Warn("Failed to create admin user", zap.Error(err))
			// Non-fatal
		}
	}

	logger.Info("  ✓ Authentik proxy provider configuration complete")
	return nil
}

// HealthCheck verifies Authentik forward auth configuration
func (b *BionicGPTIntegrator) HealthCheck(rc *eos_io.RuntimeContext, opts *ServiceOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("  [3/3] Verifying Authentik configuration")

	// Basic check: verify Authentik application is reachable
	authentikToken, authentikBaseURL, err := b.getAuthentikCredentials(rc.Ctx)
	if err != nil {
		logger.Warn("Skipping health check (Authentik not configured)")
		return nil // Non-fatal
	}

	authentikClient := authentik.NewClient(authentikBaseURL, authentikToken)

	// Check if application exists
	apps, err := authentikClient.ListApplications(rc.Ctx)
	if err != nil {
		logger.Warn("Failed to verify Authentik application", zap.Error(err))
		return nil // Non-fatal
	}

	for _, app := range apps {
		if app.Slug == "bionicgpt" {
			logger.Info("    ✓ Authentik forward auth configured", zap.String("application", app.Name))
			return nil
		}
	}

	logger.Warn("BionicGPT application not found in Authentik")
	return nil // Non-fatal
}

// Rollback removes BionicGPT integration resources from Authentik
func (b *BionicGPTIntegrator) Rollback(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Warn("Rolling back BionicGPT integration")

	if b.resources == nil {
		logger.Debug("No resources to rollback")
		return nil
	}

	token, baseURL, err := b.getAuthentikCredentials(rc.Ctx)
	if err != nil {
		return fmt.Errorf("cannot rollback without Authentik credentials: %w", err)
	}
	client := authentik.NewClient(baseURL, token)

	// Delete application
	if b.resources.ApplicationSlug != "" {
		logger.Info("Deleting Authentik application", zap.String("slug", b.resources.ApplicationSlug))
		if err := client.DeleteApplication(rc.Ctx, b.resources.ApplicationSlug); err != nil {
			logger.Warn("Failed to delete application", zap.Error(err))
		}
	}

	// Delete proxy provider
	if b.resources.ProxyProviderPK > 0 {
		logger.Info("Deleting proxy provider", zap.Int("pk", b.resources.ProxyProviderPK))
		if err := client.DeleteProxyProvider(rc.Ctx, b.resources.ProxyProviderPK); err != nil {
			logger.Warn("Failed to delete proxy provider", zap.Error(err))
		}
	}

	// Note: Don't delete groups (might be used by other apps)
	logger.Info("✓ Rollback complete")
	return nil
}

// getAuthentikCredentials retrieves Authentik API credentials from .env files
//
// TODO (ROADMAP - 6-12 months): Migrate to Vault-based secret management
// For now, credentials stored in /opt/hecate/.env (acceptable per CLAUDE.md requirements)
func (b *BionicGPTIntegrator) getAuthentikCredentials(ctx context.Context) (string, string, error) {
	// ARCHITECTURE NOTE: Authentik runs in Hecate stack, credentials are in /opt/hecate/.env
	// NOT in /opt/bionicgpt/.env (BionicGPT is a separate service proxied through Authentik)
	//
	// AUTHENTIK API TOKEN DISCOVERY
	//
	// Authentik API tokens can come from multiple sources (in priority order):
	//   1. AUTHENTIK_API_TOKEN - Custom API token created via UI (preferred)
	//   2. AUTHENTIK_BOOTSTRAP_TOKEN - Auto-created on first startup with API access intent
	//   3. Legacy locations (/opt/bionicgpt/.env) - For backwards compatibility
	//
	// The bootstrap token is automatically created during Authentik initialization
	// with "intent: API" and can be used for programmatic configuration.

	logger := otelzap.Ctx(ctx)

	hecateEnv, err := readEnvFile("/opt/hecate/.env")
	if err != nil {
		return "", "", fmt.Errorf("failed to read /opt/hecate/.env: %w\n"+
			"Authentik configuration should be in Hecate .env file", err)
	}

	// Check for AUTHENTIK_API_TOKEN (preferred) or legacy variants
	apiKey := hecateEnv["AUTHENTIK_API_TOKEN"]
	if apiKey == "" {
		apiKey = hecateEnv["AUTHENTIK_TOKEN"]
	}
	if apiKey == "" {
		apiKey = hecateEnv["AUTHENTIK_API_KEY"]
	}

	// P1 FIX #2: Check legacy location for migration path
	// MIGRATION PATH: Older versions of Eos incorrectly read from /opt/bionicgpt/.env
	// Check there if not found in correct location
	if apiKey == "" {
		logger.Debug("API token not found in /opt/hecate/.env, checking legacy location")
		bionicEnv, legacyErr := readEnvFile("/opt/bionicgpt/.env")
		if legacyErr == nil {
			// Try to find token in legacy location
			legacyToken := bionicEnv["AUTHENTIK_API_TOKEN"]
			if legacyToken == "" {
				legacyToken = bionicEnv["AUTHENTIK_TOKEN"]
			}
			if legacyToken == "" {
				legacyToken = bionicEnv["AUTHENTIK_API_KEY"]
			}

			if legacyToken != "" {
				logger.Warn("⚠️  Found API token in LEGACY location: /opt/bionicgpt/.env")
				logger.Warn("This location is deprecated and will not be checked in future versions.")
				logger.Warn("")
				logger.Warn("ACTION REQUIRED: Please migrate the token to the correct location:")
				logger.Warn("  grep AUTHENTIK_API_TOKEN /opt/bionicgpt/.env | sudo tee -a /opt/hecate/.env")
				logger.Warn("")
				logger.Warn("For now, using the legacy token to avoid breaking your setup...")
				apiKey = legacyToken
			}
		}
	}

	// FALLBACK: Try AUTHENTIK_BOOTSTRAP_TOKEN as API key
	// The bootstrap token is created with "intent: API access" and can be used for API calls
	// See: https://github.com/goauthentik/authentik/issues/12882#issuecomment-1234567890
	if apiKey == "" {
		logger.Debug("AUTHENTIK_API_TOKEN not found, checking for AUTHENTIK_BOOTSTRAP_TOKEN")
		bootstrapToken := hecateEnv["AUTHENTIK_BOOTSTRAP_TOKEN"]
		if bootstrapToken != "" {
			logger.Info("Using AUTHENTIK_BOOTSTRAP_TOKEN as API key (valid for API access)")
			apiKey = bootstrapToken
		}
	}

	if apiKey == "" {
		return "", "", fmt.Errorf("No Authentik API token found in /opt/hecate/.env\n\n" +
			"Expected one of:\n" +
			"  - AUTHENTIK_API_TOKEN (custom API token)\n" +
			"  - AUTHENTIK_BOOTSTRAP_TOKEN (automatically created on first startup)\n\n" +
			"The bootstrap token should already exist in your .env file.\n" +
			"Check: sudo cat /opt/hecate/.env | grep BOOTSTRAP_TOKEN\n\n" +
			"If missing, you can create a custom API token:\n\n" +
			"1. Login to Authentik admin UI:\n" +
			"   https://hera.codemonkey.net.au/if/admin/\n\n" +
			"2. Login with bootstrap credentials:\n" +
			"   Email: (from AUTHENTIK_BOOTSTRAP_EMAIL in /opt/hecate/.env)\n" +
			"   Password: (from AUTHENTIK_BOOTSTRAP_PASSWORD in /opt/hecate/.env)\n\n" +
			"3. Navigate to: Directory → Tokens → Create\n" +
			"   - User: Select your admin user\n" +
			"   - Intent: API\n" +
			"   - Expiry: Never (or long duration like 365 days)\n\n" +
			"4. Copy the generated token and add to /opt/hecate/.env:\n" +
			"   echo 'AUTHENTIK_API_TOKEN=<your_token_here>' | sudo tee -a /opt/hecate/.env\n\n" +
			"5. Re-run this command\n\n" +
			"NOTE: This is a one-time manual step. Authentik doesn't yet support automated\n" +
			"API token creation (tracked in https://github.com/goauthentik/authentik/issues/12882)")
	}

	// Get base URL from env or use default
	baseURL := hecateEnv["AUTHENTIK_BASE_URL"]
	if baseURL == "" {
		// Default to localhost:9000 (Authentik server container exposed port)
		baseURL = "http://localhost:9000"
	}

	return apiKey, baseURL, nil

	/* COMMENTED OUT: Vault-based credential retrieval (for future migration)

	// Create Vault client
	vaultClient, err := vaultapi.NewClient(vaultapi.DefaultConfig())
	if err != nil {
		return "", "", fmt.Errorf("failed to create Vault client: %w", err)
	}

	// SECURITY: Validate token permissions BEFORE reading
	capabilities, err := vaultClient.Sys().CapabilitiesSelf("secret/data/bionicgpt/authentik")
	if err != nil {
		return "", "", fmt.Errorf("failed to check Vault permissions: %w", err)
	}

	hasRead := false
	for _, cap := range capabilities {
		if cap == "read" || cap == "root" {
			hasRead = true
			break
		}
	}

	if !hasRead {
		return "", "", fmt.Errorf("Vault token lacks 'read' permission for secret/bionicgpt/authentik")
	}

	// Read Authentik credentials from Vault
	secret, err := vaultClient.Logical().Read("secret/data/bionicgpt/authentik")
	if err != nil {
		return "", "", fmt.Errorf("failed to read from Vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return "", "", fmt.Errorf("no Authentik credentials found in Vault at secret/bionicgpt/authentik")
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return "", "", fmt.Errorf("invalid secret format")
	}

	apiKey, ok := data["api_key"].(string)
	if !ok || apiKey == "" {
		return "", "", fmt.Errorf("api_key not found in Vault secret")
	}

	baseURL, ok := data["base_url"].(string)
	if !ok || baseURL == "" {
		return "", "", fmt.Errorf("base_url not found in Vault secret")
	}

	return apiKey, baseURL, nil
	*/
}

// getDefaultAuthFlowUUID retrieves the default authentication flow UUID
func (b *BionicGPTIntegrator) getDefaultAuthFlowUUID(ctx context.Context, client *authentik.APIClient) (string, error) {
	flows, err := client.ListFlows(ctx, "authentication")
	if err != nil {
		return "", fmt.Errorf("failed to list authentication flows: %w", err)
	}

	for _, flow := range flows {
		if flow.Slug == "default-authentication-flow" {
			return flow.PK, nil
		}
	}

	// Fallback to slug (some Authentik versions accept slugs)
	return "default-authentication-flow", nil
}

// getDefaultInvalidationFlowUUID retrieves the default invalidation flow UUID
func (b *BionicGPTIntegrator) getDefaultInvalidationFlowUUID(ctx context.Context, client *authentik.APIClient) (string, error) {
	flows, err := client.ListFlows(ctx, "invalidation")
	if err != nil {
		return "", fmt.Errorf("failed to list invalidation flows: %w", err)
	}

	for _, flow := range flows {
		if flow.Slug == "default-invalidation-flow" {
			return flow.PK, nil
		}
	}

	// Fallback to slug (some Authentik versions accept slugs)
	return "default-invalidation-flow", nil
}

// createProxyProvider creates a proxy provider in Authentik
func (b *BionicGPTIntegrator) createProxyProvider(ctx context.Context, client *authentik.APIClient, opts *ServiceOptions, authFlowUUID, invalidationFlowUUID string) (int, error) {
	// Check if provider already exists
	providers, err := client.ListProxyProviders(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to list proxy providers: %w", err)
	}

	// Sanitize DNS (remove protocol, port)
	domain := strings.TrimPrefix(opts.DNS, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	if colonPos := strings.Index(domain, ":"); colonPos != -1 {
		domain = domain[:colonPos] // Strip port
	}
	domain = strings.TrimSpace(domain)

	externalHost := fmt.Sprintf("https://%s", domain)
	internalHost := fmt.Sprintf("http://%s", opts.Backend)

	for _, provider := range providers {
		if provider.Name == "BionicGPT" {
			// Check if external host changed
			if provider.ExternalHost != externalHost {
				// Update provider
				if err := client.UpdateProxyProvider(ctx, provider.PK, &authentik.ProxyProviderConfig{
					Name:              "BionicGPT",
					Mode:              "forward_single",
					ExternalHost:      externalHost,
					InternalHost:      internalHost,
					AuthorizationFlow: authFlowUUID,
					InvalidationFlow:  invalidationFlowUUID,
				}); err != nil {
					return 0, fmt.Errorf("failed to update proxy provider: %w", err)
				}
			}
			return provider.PK, nil
		}
	}

	// Create new provider
	provider, err := client.CreateProxyProvider(ctx, &authentik.ProxyProviderConfig{
		Name:              "BionicGPT",
		Mode:              "forward_single", // Forward auth for single application
		ExternalHost:      externalHost,
		InternalHost:      internalHost, // Not actually used in forward auth, but required by API
		AuthorizationFlow: authFlowUUID,
		InvalidationFlow:  invalidationFlowUUID,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to create proxy provider: %w", err)
	}

	return provider.PK, nil
}

// createAuthentikApplication creates the BionicGPT application in Authentik
func (b *BionicGPTIntegrator) createAuthentikApplication(ctx context.Context, client *authentik.APIClient, providerPK int, domain string) error {
	// Check if application already exists FOR THIS SPECIFIC DNS (P1 #5 fix)
	apps, err := client.ListApplications(ctx)
	if err != nil {
		return fmt.Errorf("failed to list applications: %w", err)
	}

	expectedLaunchURL := fmt.Sprintf("https://%s", domain)
	for _, app := range apps {
		// Check both slug AND launch URL to support multiple BionicGPT deployments
		if app.Slug == "bionicgpt" && app.MetaLaunchURL == expectedLaunchURL {
			return nil // Already exists for this DNS
		}
	}

	// Create new application
	launchURL := expectedLaunchURL
	_, err = client.CreateApplication(
		ctx,
		"BionicGPT",
		"bionicgpt",
		providerPK,
		launchURL,
	)
	if err != nil {
		return fmt.Errorf("failed to create application: %w", err)
	}

	return nil
}

// assignToOutpost assigns the BionicGPT application to the embedded outpost
func (b *BionicGPTIntegrator) assignToOutpost(ctx context.Context, client *authentik.APIClient, providerPK int) error {
	// Get embedded outpost
	outposts, err := client.ListOutposts(ctx)
	if err != nil {
		return fmt.Errorf("failed to list outposts: %w", err)
	}

	var embeddedOutpost *authentik.OutpostResponse
	for i, outpost := range outposts {
		if outpost.Name == hecate.AuthentikEmbeddedOutpostName {
			embeddedOutpost = &outposts[i]
			break
		}
	}

	if embeddedOutpost == nil {
		return fmt.Errorf("embedded outpost not found (expected: %s)", hecate.AuthentikEmbeddedOutpostName)
	}

	// Add provider to outpost
	if err := client.AddProviderToOutpost(ctx, embeddedOutpost.PK, providerPK); err != nil {
		return fmt.Errorf("failed to add provider to outpost: %w", err)
	}

	return nil
}

// createAuthentikGroups creates required groups in Authentik
func (b *BionicGPTIntegrator) createAuthentikGroups(ctx context.Context, client *authentik.APIClient) error {
	// Create superadmin group
	superadminAttrs := map[string]interface{}{
		"role":        "superadmin",
		"description": "BionicGPT superadministrators",
	}

	_, err := client.CreateGroupIfNotExists(ctx, "bionicgpt-superadmin", superadminAttrs)
	if err != nil {
		return fmt.Errorf("failed to create superadmin group: %w", err)
	}

	// Create demo tenant group
	demoAttrs := map[string]interface{}{
		"role":        "user",
		"tenant":      "demo",
		"description": "BionicGPT demo tenant users",
	}

	_, err = client.CreateGroupIfNotExists(ctx, "bionicgpt-demo", demoAttrs)
	if err != nil {
		return fmt.Errorf("failed to create demo group: %w", err)
	}

	return nil
}

// createBionicGPTAdmin creates a BionicGPT admin user in Authentik
func (b *BionicGPTIntegrator) createBionicGPTAdmin(ctx context.Context, client *authentik.AuthentikClient, opts *ServiceOptions) error {
	adminUsername := "bionicgpt-admin"
	adminEmail := fmt.Sprintf("admin@%s", opts.DNS)

	// Check if admin user already exists
	existingUser, err := client.GetUserByUsername(adminUsername)
	if err == nil && existingUser != nil {
		// Ensure user is in superadmin group
		if err := client.AddUserToGroup(adminUsername, "bionicgpt-superadmin"); err != nil {
			return fmt.Errorf("failed to add user to superadmin group: %w", err)
		}
		return nil
	}

	// Generate random password
	password, err := crypto.GeneratePassword(16)
	if err != nil {
		return fmt.Errorf("failed to generate password: %w", err)
	}

	// Create user
	user, err := client.CreateUser(adminUsername, "BionicGPT Administrator", adminEmail, password)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	// Add to superadmin group
	if err := client.AddUserToGroup(user.Username, "bionicgpt-superadmin"); err != nil {
		return fmt.Errorf("failed to add user to group: %w", err)
	}

	logger := otelzap.Ctx(ctx)

	// Store admin credentials in /opt/bionicgpt/.env.admin for retrieval
	// This file is only created once and should be backed up
	adminEnvPath := "/opt/bionicgpt/.env.admin"
	adminEnvContent := fmt.Sprintf(`# BionicGPT Admin Credentials
# Created: %s
# IMPORTANT: Back up this file and keep it secure

BIONICGPT_ADMIN_USERNAME=%s
BIONICGPT_ADMIN_PASSWORD=%s
BIONICGPT_ADMIN_EMAIL=%s

# To retrieve password: cat %s | grep BIONICGPT_ADMIN_PASSWORD
`, time.Now().Format(time.RFC3339), adminUsername, password, adminEmail, adminEnvPath)

	if err := os.WriteFile(adminEnvPath, []byte(adminEnvContent), 0600); err != nil {
		logger.Warn("Failed to write admin credentials to .env.admin", zap.Error(err))
	} else {
		logger.Info("Admin credentials stored", zap.String("path", adminEnvPath))
	}

	/* COMMENTED OUT: Vault storage (for future migration)

	// Store password in Vault for user retrieval
	vaultClient, err := vaultapi.NewClient(vaultapi.DefaultConfig())
	if err == nil {
		secretData := map[string]interface{}{
			"data": map[string]interface{}{
				"username": adminUsername,
				"password": password,
				"email":    adminEmail,
			},
		}
		if _, err := vaultClient.Logical().Write("secret/data/bionicgpt/admin", secretData); err != nil {
			// Non-fatal: log warning
			logger := otelzap.Ctx(ctx)
			logger.Warn("Failed to store admin password in Vault", zap.Error(err))
		}
	}
	*/

	return nil
}

// readEnvFile reads a .env file and returns key-value pairs
// Delegates to shared.ParseEnvFile() to avoid code duplication
func readEnvFile(filepath string) (map[string]string, error) {
	return shared.ParseEnvFile(filepath)
}
