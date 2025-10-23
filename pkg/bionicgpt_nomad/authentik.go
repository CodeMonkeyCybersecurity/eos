// pkg/bionicgpt_nomad/authentik.go - Phase 4: Authentik configuration

package bionicgpt_nomad

import (
	"context"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConfigureAuthentik configures Authentik OAuth2 provider, groups, and application
func (ei *EnterpriseInstaller) ConfigureAuthentik() error {
	logger := otelzap.Ctx(ei.rc.Ctx)

	logger.Info("Phase 4: Configuring Authentik OAuth2 provider")

	// Step 1: Get Authentik API token from Vault
	logger.Info("  [1/5] Retrieving Authentik credentials from Vault")
	authentikToken, authentikBaseURL, err := ei.getAuthentikCredentials()
	if err != nil {
		return fmt.Errorf("failed to get Authentik credentials: %w", err)
	}

	// Step 2: Initialize Authentik API client
	logger.Info("  [2/5] Initializing Authentik API client", zap.String("base_url", authentikBaseURL))
	authentikClient := authentik.NewClient(authentikBaseURL, authentikToken)

	// Step 3: Create OAuth2 provider
	logger.Info("  [3/5] Creating OAuth2 provider")
	providerPK, clientID, clientSecret, err := ei.createOAuth2Provider(ei.rc.Ctx, authentikClient)
	if err != nil {
		return fmt.Errorf("failed to create OAuth2 provider: %w", err)
	}
	logger.Info("    ✓ OAuth2 provider created", zap.Int("provider_pk", providerPK))

	// Step 4: Store OAuth2 credentials in Vault
	logger.Info("  [4/8] Storing OAuth2 credentials in Vault")
	if err := ei.storeOAuth2Credentials(clientID, clientSecret); err != nil {
		return fmt.Errorf("failed to store OAuth2 credentials: %w", err)
	}
	logger.Info("    ✓ Credentials stored at secret/bionicgpt/oauth")

	// Step 5: Generate and store PostgreSQL password
	logger.Info("  [5/8] Generating PostgreSQL password")
	if err := ei.storePostgreSQLPassword(); err != nil {
		return fmt.Errorf("failed to store PostgreSQL password: %w", err)
	}
	logger.Info("    ✓ PostgreSQL password stored at secret/bionicgpt/db")

	// Step 6: Generate and store LiteLLM master key
	logger.Info("  [6/8] Generating LiteLLM master key")
	if err := ei.storeLiteLLMMasterKey(); err != nil {
		return fmt.Errorf("failed to store LiteLLM master key: %w", err)
	}
	logger.Info("    ✓ LiteLLM master key stored at secret/bionicgpt/litellm")

	// Step 7: Create groups
	logger.Info("  [7/8] Creating Authentik groups")
	if err := ei.createAuthentikGroups(ei.rc.Ctx, authentikClient); err != nil {
		return fmt.Errorf("failed to create groups: %w", err)
	}
	logger.Info("    ✓ Groups created")

	// Step 8: Create Authentik application
	logger.Info("  [8/8] Creating Authentik application")
	if err := ei.createAuthentikApplication(ei.rc.Ctx, authentikClient, providerPK); err != nil {
		return fmt.Errorf("failed to create application: %w", err)
	}
	logger.Info("    ✓ Application created")

	logger.Info("✓ Authentik configuration complete")
	return nil
}

// getAuthentikCredentials retrieves Authentik API credentials from Vault
func (ei *EnterpriseInstaller) getAuthentikCredentials() (string, string, error) {
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
func (ei *EnterpriseInstaller) createOAuth2Provider(ctx context.Context, client *authentik.APIClient) (int, string, string, error) {
	logger := otelzap.Ctx(ei.rc.Ctx)

	// Check if provider already exists
	providers, err := client.ListOAuth2Providers(ctx)
	if err != nil {
		return 0, "", "", fmt.Errorf("failed to list providers: %w", err)
	}

	for _, provider := range providers {
		if provider.Name == "BionicGPT" {
			logger.Info("    OAuth2 provider already exists", zap.Int("provider_pk", provider.PK))
			return provider.PK, provider.ClientID, provider.ClientSecret, nil
		}
	}

	// Create new provider
	redirectURI := fmt.Sprintf("https://%s/oauth2/callback", ei.config.Domain)
	provider, err := client.CreateOAuth2Provider(
		ctx,
		"BionicGPT",
		[]string{redirectURI},
		"default-authentication-flow", // TODO: Get actual flow UUID from Authentik
	)
	if err != nil {
		return 0, "", "", fmt.Errorf("failed to create provider: %w", err)
	}

	logger.Info("    Created OAuth2 provider",
		zap.Int("provider_pk", provider.PK),
		zap.String("client_id", provider.ClientID),
		zap.String("redirect_uri", redirectURI))

	return provider.PK, provider.ClientID, provider.ClientSecret, nil
}

// storeOAuth2Credentials stores OAuth2 credentials in Vault
func (ei *EnterpriseInstaller) storeOAuth2Credentials(clientID, clientSecret string) error {
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

// createAuthentikGroups creates required groups in Authentik
func (ei *EnterpriseInstaller) createAuthentikGroups(ctx context.Context, client *authentik.APIClient) error {
	logger := otelzap.Ctx(ei.rc.Ctx)

	// Create superadmin group
	superadminAttrs := map[string]interface{}{
		"role":        "superadmin",
		"description": "BionicGPT superadministrators",
	}

	superadminGroup, err := client.CreateGroupIfNotExists(ctx, ei.config.SuperadminGroup, superadminAttrs)
	if err != nil {
		return fmt.Errorf("failed to create superadmin group: %w", err)
	}
	logger.Debug("    Superadmin group ready", zap.String("name", superadminGroup.Name))

	// Create demo tenant group
	demoAttrs := map[string]interface{}{
		"role":        "user",
		"tenant":      "demo",
		"description": "BionicGPT demo tenant users",
	}

	demoGroup, err := client.CreateGroupIfNotExists(ctx, ei.config.DemoGroup, demoAttrs)
	if err != nil {
		return fmt.Errorf("failed to create demo group: %w", err)
	}
	logger.Debug("    Demo group ready", zap.String("name", demoGroup.Name))

	return nil
}

// createAuthentikApplication creates the BionicGPT application in Authentik
func (ei *EnterpriseInstaller) createAuthentikApplication(ctx context.Context, client *authentik.APIClient, providerPK int) error {
	logger := otelzap.Ctx(ei.rc.Ctx)

	// Check if application already exists
	apps, err := client.ListApplications(ctx)
	if err != nil {
		return fmt.Errorf("failed to list applications: %w", err)
	}

	for _, app := range apps {
		if app.Slug == "bionicgpt" {
			logger.Info("    Application already exists", zap.String("slug", app.Slug))
			return nil
		}
	}

	// Create new application
	launchURL := fmt.Sprintf("https://%s", ei.config.Domain)
	app, err := client.CreateApplication(
		ctx,
		"BionicGPT",
		"bionicgpt",
		providerPK,
		launchURL,
	)
	if err != nil {
		return fmt.Errorf("failed to create application: %w", err)
	}

	logger.Info("    Created application",
		zap.String("name", app.Name),
		zap.String("slug", app.Slug),
		zap.String("launch_url", launchURL))

	return nil
}

// storePostgreSQLPassword generates and stores PostgreSQL password in Vault
func (ei *EnterpriseInstaller) storePostgreSQLPassword() error {
	// Create Vault client
	vaultClient, err := vaultapi.NewClient(vaultapi.DefaultConfig())
	if err != nil {
		return fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Generate strong password
	dbPassword, err := crypto.GeneratePassword(32)
	if err != nil {
		return fmt.Errorf("failed to generate DB password: %w", err)
	}

	// Store in Vault
	secretData := map[string]interface{}{
		"data": map[string]interface{}{
			"password": dbPassword,
		},
	}
	_, err = vaultClient.Logical().Write("secret/data/bionicgpt/db", secretData)
	if err != nil {
		return fmt.Errorf("failed to write to Vault: %w", err)
	}

	return nil
}

// storeLiteLLMMasterKey generates and stores LiteLLM master key in Vault
func (ei *EnterpriseInstaller) storeLiteLLMMasterKey() error {
	// Create Vault client
	vaultClient, err := vaultapi.NewClient(vaultapi.DefaultConfig())
	if err != nil {
		return fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Generate master key
	masterKey, err := crypto.GeneratePassword(32)
	if err != nil {
		return fmt.Errorf("failed to generate LiteLLM master key: %w", err)
	}

	// Store in Vault
	secretData := map[string]interface{}{
		"data": map[string]interface{}{
			"master_key": masterKey,
		},
	}
	_, err = vaultClient.Logical().Write("secret/data/bionicgpt/litellm", secretData)
	if err != nil {
		return fmt.Errorf("failed to write to Vault: %w", err)
	}

	return nil
}
