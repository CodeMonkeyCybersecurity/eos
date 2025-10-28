// pkg/hecate/add/bionicgpt.go - BionicGPT-specific integration using Authentik forward auth

package add

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
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
	// Register BionicGPT integrator
	RegisterServiceIntegrator("bionicgpt", &BionicGPTIntegrator{
		resources: &IntegrationResources{},
	})
}

// endpointAttempt tracks a single endpoint connection attempt for debugging
type endpointAttempt struct {
	URL        string
	StatusCode int
	Status     string
	Error      string
	Protocol   string // "HTTP" or "HTTPS"
}

// ValidateService checks if BionicGPT is running at the backend address
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

	// Try to connect to BionicGPT
	// Strategy: Try HTTP first (common for internal services), then HTTPS (if using TLS)
	// This pattern matches pkg/hecate/add/validation.go:307-315

	// HTTP client for HTTPS endpoints (with TLS skip verify for self-signed certs)
	httpsClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // BionicGPT often uses self-signed certs in dev
			},
		},
	}

	// HTTP client for plain HTTP endpoints
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Track all attempts for detailed error reporting
	var attempts []endpointAttempt

	// Try HTTP first (common for internal services on non-standard ports like 8513)
	// Priority: root path first (most likely to work), then /health endpoint
	httpEndpoints := []string{
		fmt.Sprintf("http://%s/", backend),
		fmt.Sprintf("http://%s%s", backend, hecate.BionicGPTHealthEndpoint),
	}

	for _, endpoint := range httpEndpoints {
		logger.Debug("Trying HTTP endpoint", zap.String("endpoint", endpoint))

		resp, err := httpClient.Get(endpoint)
		if err != nil {
			logger.Debug("HTTP connection failed",
				zap.String("endpoint", endpoint),
				zap.Error(err))
			attempts = append(attempts, endpointAttempt{
				URL:      endpoint,
				Error:    err.Error(),
				Protocol: "HTTP",
			})
			continue
		}
		defer resp.Body.Close()

		logger.Debug("HTTP response received",
			zap.String("endpoint", endpoint),
			zap.Int("status_code", resp.StatusCode),
			zap.String("status", resp.Status))

		// Accept all 2xx (success) and 3xx (redirect) status codes
		// BionicGPT may redirect to login, return 404 for /health, etc. - all indicate service is running
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			logger.Info("    ✓ BionicGPT is responding correctly",
				zap.String("endpoint", endpoint),
				zap.String("protocol", "HTTP"),
				zap.Int("status_code", resp.StatusCode))
			return nil
		}

		attempts = append(attempts, endpointAttempt{
			URL:        endpoint,
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Protocol:   "HTTP",
		})

		// P0 FIX: Continue to try next endpoint instead of breaking
		continue
	}

	// Try HTTPS if HTTP fails (service might be using TLS)
	logger.Debug("HTTP connection failed, trying HTTPS",
		zap.Int("http_attempts", len(attempts)))

	httpsEndpoints := []string{
		fmt.Sprintf("https://%s/", backend),
		fmt.Sprintf("https://%s%s", backend, hecate.BionicGPTHealthEndpoint),
	}

	for _, endpoint := range httpsEndpoints {
		logger.Debug("Trying HTTPS endpoint", zap.String("endpoint", endpoint))

		resp, err := httpsClient.Get(endpoint)
		if err != nil {
			logger.Debug("HTTPS connection failed",
				zap.String("endpoint", endpoint),
				zap.Error(err))
			attempts = append(attempts, endpointAttempt{
				URL:      endpoint,
				Error:    err.Error(),
				Protocol: "HTTPS",
			})
			continue
		}
		defer resp.Body.Close()

		logger.Debug("HTTPS response received",
			zap.String("endpoint", endpoint),
			zap.Int("status_code", resp.StatusCode),
			zap.String("status", resp.Status))

		// Accept all 2xx (success) and 3xx (redirect) status codes
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			logger.Info("    ✓ BionicGPT is responding correctly",
				zap.String("endpoint", endpoint),
				zap.String("protocol", "HTTPS"),
				zap.Int("status_code", resp.StatusCode))
			return nil
		}

		attempts = append(attempts, endpointAttempt{
			URL:        endpoint,
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Protocol:   "HTTPS",
		})

		// P0 FIX: Continue to try next endpoint instead of breaking
		continue
	}

	// All attempts failed - build detailed error message
	return b.buildValidationError(backend, attempts)
}

// buildValidationError creates a detailed error message showing all attempted endpoints
func (b *BionicGPTIntegrator) buildValidationError(backend string, attempts []endpointAttempt) error {
	var errorMsg strings.Builder

	errorMsg.WriteString(fmt.Sprintf("BionicGPT not responding at %s\n\n", backend))

	// Show HTTP attempts
	errorMsg.WriteString("Tried HTTP endpoints:\n")
	httpAttempts := 0
	for _, attempt := range attempts {
		if attempt.Protocol == "HTTP" {
			httpAttempts++
			if attempt.Error != "" {
				errorMsg.WriteString(fmt.Sprintf("  ✗ %s → %s\n", attempt.URL, attempt.Error))
			} else {
				errorMsg.WriteString(fmt.Sprintf("  ✗ %s → %d %s\n", attempt.URL, attempt.StatusCode, attempt.Status))
			}
		}
	}
	if httpAttempts == 0 {
		errorMsg.WriteString("  (none attempted)\n")
	}

	// Show HTTPS attempts
	errorMsg.WriteString("\nTried HTTPS endpoints:\n")
	httpsAttempts := 0
	for _, attempt := range attempts {
		if attempt.Protocol == "HTTPS" {
			httpsAttempts++
			if attempt.Error != "" {
				errorMsg.WriteString(fmt.Sprintf("  ✗ %s → %s\n", attempt.URL, attempt.Error))
			} else {
				errorMsg.WriteString(fmt.Sprintf("  ✗ %s → %d %s\n", attempt.URL, attempt.StatusCode, attempt.Status))
			}
		}
	}
	if httpsAttempts == 0 {
		errorMsg.WriteString("  (none attempted)\n")
	}

	errorMsg.WriteString("\nEnsure BionicGPT is running at the backend address.\n")
	errorMsg.WriteString(fmt.Sprintf("Expected: BionicGPT service listening on port %d (HTTP or HTTPS)\n", hecate.BionicGPTDefaultPort))
	errorMsg.WriteString("\nTroubleshooting:\n")
	errorMsg.WriteString("  1. Verify service is running: docker ps | grep bionicgpt\n")
	errorMsg.WriteString("  2. Check service logs: docker logs bionicgpt\n")
	errorMsg.WriteString(fmt.Sprintf("  3. Test connectivity: curl -v http://%s/\n", backend))

	return fmt.Errorf("%s", errorMsg.String())
}

// ConfigureAuthentication sets up Authentik proxy provider for BionicGPT (forward auth mode)
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
	logger.Info("    Getting Authentik credentials from /opt/bionicgpt/.env")
	authentikToken, authentikBaseURL, err := b.getAuthentikCredentials(rc.Ctx)
	if err != nil {
		logger.Warn("Authentik credentials not found, skipping proxy provider setup", zap.Error(err))
		logger.Warn("To enable authentication, add to /opt/bionicgpt/.env:")
		logger.Warn("  AUTHENTIK_TOKEN=your_authentik_api_token")
		logger.Warn("  AUTHENTIK_BASE_URL=http://localhost:9000")
		logger.Warn("Get API token from: https://hera.your-domain/if/admin/#/core/tokens")
		return nil // Non-fatal: generic route still works
	}

	// Step 2: Initialize Authentik API client
	logger.Info("    Initializing Authentik API client", zap.String("base_url", authentikBaseURL))
	authentikClient := authentik.NewClient(authentikBaseURL, authentikToken)

	// Step 3: Get default authorization flow UUID
	logger.Info("    Getting authorization flow")
	flowUUID, err := b.getDefaultAuthFlowUUID(rc.Ctx, authentikClient)
	if err != nil {
		logger.Warn("Failed to get auth flow, using default slug", zap.Error(err))
		flowUUID = "default-authentication-flow"
	}

	// Step 4: Create proxy provider
	logger.Info("    Creating proxy provider (forward auth mode)")
	providerPK, err := b.createProxyProvider(rc.Ctx, authentikClient, opts, flowUUID)
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
// TODO: Migrate to Vault once BionicGPT and Authentik are fully migrated to Vault-based secrets
func (b *BionicGPTIntegrator) getAuthentikCredentials(ctx context.Context) (string, string, error) {
	// TEMPORARY: Read from .env files until Vault migration is complete
	// BionicGPT stores Authentik token in /opt/bionicgpt/.env
	// Authentik base URL can be inferred from Hecate or use default

	bionicgptEnv, err := readEnvFile("/opt/bionicgpt/.env")
	if err != nil {
		return "", "", fmt.Errorf("failed to read /opt/bionicgpt/.env: %w\n"+
			"Ensure BionicGPT is installed with: eos create bionicgpt", err)
	}

	// Check for AUTHENTIK_TOKEN in BionicGPT .env
	apiKey := bionicgptEnv["AUTHENTIK_TOKEN"]
	if apiKey == "" {
		// Fallback: Try AUTHENTIK_API_KEY
		apiKey = bionicgptEnv["AUTHENTIK_API_KEY"]
	}

	if apiKey == "" {
		return "", "", fmt.Errorf("AUTHENTIK_TOKEN not found in /opt/bionicgpt/.env\n" +
			"Add to .env file:\n" +
			"  AUTHENTIK_TOKEN=your_authentik_api_token\n" +
			"Get token from: https://hera.your-domain/if/admin/#/core/tokens")
	}

	// Get base URL from env or use default
	baseURL := bionicgptEnv["AUTHENTIK_BASE_URL"]
	if baseURL == "" {
		// Default to localhost:9000 (Authentik default in Hecate stack)
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

// createProxyProvider creates a proxy provider in Authentik
func (b *BionicGPTIntegrator) createProxyProvider(ctx context.Context, client *authentik.APIClient, opts *ServiceOptions, flowUUID string) (int, error) {
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
					AuthorizationFlow: flowUUID,
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
		AuthorizationFlow: flowUUID,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to create proxy provider: %w", err)
	}

	return provider.PK, nil
}

// createAuthentikApplication creates the BionicGPT application in Authentik
func (b *BionicGPTIntegrator) createAuthentikApplication(ctx context.Context, client *authentik.APIClient, providerPK int, domain string) error {
	// Check if application already exists
	apps, err := client.ListApplications(ctx)
	if err != nil {
		return fmt.Errorf("failed to list applications: %w", err)
	}

	for _, app := range apps {
		if app.Slug == "bionicgpt" {
			return nil // Already exists
		}
	}

	// Create new application
	launchURL := fmt.Sprintf("https://%s", domain)
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
// Simple parser that handles KEY=VALUE format (no quotes, no multiline, no exports)
func readEnvFile(filepath string) (map[string]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	env := make(map[string]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse KEY=VALUE
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue // Skip malformed lines
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove surrounding quotes if present
		value = strings.Trim(value, `"'`)

		env[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return env, nil
}
