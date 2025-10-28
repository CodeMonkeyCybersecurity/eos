// pkg/hecate/add/bionicgpt.go - BionicGPT-specific integration

package add

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BionicGPTIntegrator implements service-specific integration for BionicGPT
type BionicGPTIntegrator struct{}

func init() {
	// Register BionicGPT integrator
	RegisterServiceIntegrator("bionicgpt", &BionicGPTIntegrator{})
}

// ValidateService checks if BionicGPT is running at the backend address
func (b *BionicGPTIntegrator) ValidateService(rc *eos_io.RuntimeContext, opts *ServiceOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("  [1/3] Validating BionicGPT is running at backend", zap.String("backend", opts.Backend))

	// Try to connect to BionicGPT
	// BionicGPT typically runs on port 7703
	backend := opts.Backend
	if !strings.Contains(backend, ":") {
		backend = fmt.Sprintf("%s:%d", backend, hecate.BionicGPTDefaultPort)
	}

	// Try root endpoint and health endpoint
	endpoints := []string{
		fmt.Sprintf("http://%s/", backend),
		fmt.Sprintf("http://%s%s", backend, hecate.BionicGPTHealthEndpoint),
	}

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	var lastErr error
	for _, endpoint := range endpoints {
		resp, err := httpClient.Get(endpoint)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()

		// BionicGPT should respond with 200 OK or redirect
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
			logger.Info("    ✓ BionicGPT is responding correctly", zap.String("endpoint", endpoint))
			return nil
		}

		lastErr = fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return fmt.Errorf("BionicGPT not responding at %s: %w\n\n"+
		"Ensure BionicGPT is running at the backend address.\n"+
		"Expected: BionicGPT service listening on port %d", backend, lastErr, hecate.BionicGPTDefaultPort)
}

// ConfigureAuthentication sets up Authentik OAuth2 for BionicGPT
func (b *BionicGPTIntegrator) ConfigureAuthentication(rc *eos_io.RuntimeContext, opts *ServiceOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("  [2/3] Configuring Authentik OAuth2 integration")

	// Step 1: Get Authentik credentials from Vault
	logger.Info("    Getting Authentik credentials from Vault")
	authentikToken, authentikBaseURL, err := b.getAuthentikCredentials(rc.Ctx)
	if err != nil {
		logger.Warn("Authentik credentials not found in Vault, skipping OAuth2 setup", zap.Error(err))
		logger.Warn("To enable OAuth2: vault kv put secret/bionicgpt/authentik api_key=... base_url=...")
		return nil // Non-fatal: generic route still works
	}

	// Step 2: Initialize Authentik API client
	logger.Info("    Initializing Authentik API client", zap.String("base_url", authentikBaseURL))
	authentikClient := authentik.NewClient(authentikBaseURL, authentikToken)

	// Step 3: Create OAuth2 provider
	logger.Info("    Creating OAuth2 provider")
	providerPK, clientID, clientSecret, err := b.createOAuth2Provider(rc.Ctx, authentikClient, opts.DNS)
	if err != nil {
		return fmt.Errorf("failed to create OAuth2 provider: %w", err)
	}
	logger.Info("    ✓ OAuth2 provider created", zap.Int("provider_pk", providerPK))

	// Step 4: Store OAuth2 credentials in Vault
	logger.Info("    Storing OAuth2 credentials in Vault")
	if err := b.storeOAuth2Credentials(rc.Ctx, clientID, clientSecret); err != nil {
		return fmt.Errorf("failed to store OAuth2 credentials: %w", err)
	}
	logger.Info("    ✓ Credentials stored at secret/bionicgpt/oauth")

	// Step 5: Create Authentik application
	logger.Info("    Creating Authentik application")
	if err := b.createAuthentikApplication(rc.Ctx, authentikClient, providerPK, opts.DNS); err != nil {
		return fmt.Errorf("failed to create application: %w", err)
	}
	logger.Info("    ✓ Application 'BionicGPT' created")

	// Step 6: Create groups
	logger.Info("    Creating Authentik groups (superadmin, demo)")
	if err := b.createAuthentikGroups(rc.Ctx, authentikClient); err != nil {
		return fmt.Errorf("failed to create groups: %w", err)
	}
	logger.Info("    ✓ Groups configured")

	logger.Info("  ✓ Authentik OAuth2 configuration complete")
	return nil
}

// HealthCheck verifies OAuth2 redirect flow is configured
func (b *BionicGPTIntegrator) HealthCheck(rc *eos_io.RuntimeContext, opts *ServiceOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("  [3/3] Verifying OAuth2 configuration")

	// Basic check: verify Authentik application is reachable
	authentikToken, authentikBaseURL, err := b.getAuthentikCredentials(rc.Ctx)
	if err != nil {
		logger.Warn("Skipping OAuth2 health check (Authentik not configured)")
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
			logger.Info("    ✓ OAuth2 redirect flow configured", zap.String("application", app.Name))
			return nil
		}
	}

	logger.Warn("BionicGPT application not found in Authentik")
	return nil // Non-fatal
}

// getAuthentikCredentials retrieves Authentik API credentials from Vault
func (b *BionicGPTIntegrator) getAuthentikCredentials(ctx context.Context) (string, string, error) {
	// Create Vault client
	vaultClient, err := vaultapi.NewClient(vaultapi.DefaultConfig())
	if err != nil {
		return "", "", fmt.Errorf("failed to create Vault client: %w", err)
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
}

// createOAuth2Provider creates an OAuth2 provider in Authentik
func (b *BionicGPTIntegrator) createOAuth2Provider(ctx context.Context, client *authentik.APIClient, domain string) (int, string, string, error) {
	// Check if provider already exists
	providers, err := client.ListOAuth2Providers(ctx)
	if err != nil {
		return 0, "", "", fmt.Errorf("failed to list providers: %w", err)
	}

	for _, provider := range providers {
		if provider.Name == "BionicGPT" {
			return provider.PK, provider.ClientID, provider.ClientSecret, nil
		}
	}

	// Create new provider
	redirectURI := fmt.Sprintf("https://%s%s", domain, hecate.BionicGPTOAuth2CallbackPath)
	provider, err := client.CreateOAuth2Provider(
		ctx,
		"BionicGPT",
		[]string{redirectURI},
		"default-authentication-flow", // TODO: Get actual flow UUID from Authentik
	)
	if err != nil {
		return 0, "", "", fmt.Errorf("failed to create provider: %w", err)
	}

	return provider.PK, provider.ClientID, provider.ClientSecret, nil
}

// storeOAuth2Credentials stores OAuth2 credentials in Vault
func (b *BionicGPTIntegrator) storeOAuth2Credentials(ctx context.Context, clientID, clientSecret string) error {
	// Create Vault client
	vaultClient, err := vaultapi.NewClient(vaultapi.DefaultConfig())
	if err != nil {
		return fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Generate cookie secret
	cookieSecret, err := crypto.GeneratePassword(32)
	if err != nil {
		return fmt.Errorf("failed to generate cookie secret: %w", err)
	}

	// Store credentials in Vault
	secretData := map[string]interface{}{
		"data": map[string]interface{}{
			"client_id":     clientID,
			"client_secret": clientSecret,
			"cookie_secret": cookieSecret,
		},
	}

	_, err = vaultClient.Logical().Write("secret/data/bionicgpt/oauth", secretData)
	if err != nil {
		return fmt.Errorf("failed to write to Vault: %w", err)
	}

	return nil
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
