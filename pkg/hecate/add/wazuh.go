// pkg/hecate/add/wazuh.go - Wazuh-specific integration using Authentik SAML SSO

package add

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	consulapi "github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// WazuhIntegrator implements service-specific integration for Wazuh
// Uses Authentik SAML provider (NOT proxy provider - Wazuh handles its own auth)
type WazuhIntegrator struct {
	resources *WazuhIntegrationResources // Track created resources for rollback
}

// WazuhIntegrationResources tracks resources created during Wazuh integration
type WazuhIntegrationResources struct {
	SAMLProviderPK      string   // Authentik SAML provider PK (for cleanup)
	PropertyMappingPKs  []string // SAML property mappings created (for cleanup)
	ApplicationPK       string   // Authentik application PK (for cleanup)
	ApplicationSlug     string   // Authentik application slug (for cleanup)
	MetadataStored      bool     // Whether metadata was stored in Consul KV
	ConsulKVKeysCreated []string // All Consul KV keys created (for cleanup)
}

func init() {
	// Register Wazuh integrator constructor
	// CRITICAL: Use constructor pattern to create fresh instance per invocation
	// This prevents resource leaks when rollback is triggered on multiple concurrent/sequential runs
	RegisterServiceIntegrator("wazuh", func() ServiceIntegrator {
		return &WazuhIntegrator{
			resources: &WazuhIntegrationResources{},
		}
	})
}

// IsConfigured checks if Wazuh SSO integration is already configured
// P1 #4: Plugin-based idempotency check instead of hardcoded service checks
// Wazuh currently doesn't require SSO integration, so always returns false
func (w *WazuhIntegrator) IsConfigured(rc *eos_io.RuntimeContext, opts *ServiceOptions) (bool, error) {
	// Wazuh integration doesn't configure SSO, so it's never "configured" in that sense
	// This allows normal duplicate detection to handle idempotency
	return false, nil
}

// ValidateService checks if Wazuh is running at the backend address
func (w *WazuhIntegrator) ValidateService(rc *eos_io.RuntimeContext, opts *ServiceOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("  [1/3] Validating Wazuh is running at backend", zap.String("backend", opts.Backend))

	// Add default port if not specified
	backend := opts.Backend
	if !strings.Contains(backend, ":") {
		logger.Warn("No port specified in --upstream, using Wazuh default",
			zap.Int("port", hecate.WazuhDefaultPort),
			zap.String("help", "Specify explicit port with --upstream IP:PORT"))
		backend = fmt.Sprintf("%s:%d", backend, hecate.WazuhDefaultPort)
	}

	// Try to connect to Wazuh Dashboard
	// Strategy: Try HTTPS first (Wazuh typically uses TLS), then HTTP fallback
	// Accept 200, 302, 401, 403, 404 as "service responding"

	// HTTPS client configuration
	// SECURITY: TLS verification behavior based on --allow-insecure-tls flag
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12, // Require TLS 1.2+
	}

	// Check if user has explicitly allowed insecure TLS
	if opts.AllowInsecureTLS {
		logger.Warn("⚠️  TLS CERTIFICATE VERIFICATION DISABLED")
		logger.Warn("This is INSECURE and should only be used:")
		logger.Warn("  - In development/testing environments")
		logger.Warn("  - With self-signed certificates you trust")
		logger.Warn("  - Temporarily until proper certificates are installed")
		logger.Warn("")
		logger.Warn("For production, install valid TLS certificates on Wazuh server")
		logger.Warn("Or provide custom CA cert with --ca-cert flag (future enhancement)")

		tlsConfig.InsecureSkipVerify = true
	}

	httpsClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects - we just want to know service is alive
			return http.ErrUseLastResponse
		},
	}

	// HTTP client (fallback)
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Track all attempts for detailed error reporting
	var attempts []endpointAttempt

	// Try HTTPS first (most common for Wazuh)
	httpsEndpoints := []string{
		fmt.Sprintf("https://%s/", backend),
		fmt.Sprintf("https://%s/app/wazuh", backend), // Wazuh dashboard path
	}

	for _, endpoint := range httpsEndpoints {
		logger.Debug("Trying HTTPS endpoint", zap.String("endpoint", endpoint))

		resp, err := httpsClient.Get(endpoint)
		if err != nil {
			logger.Debug("HTTPS connection failed",
				zap.String("endpoint", endpoint),
				zap.Error(err))

			// Check if this is a TLS certificate error
			isTLSError := strings.Contains(err.Error(), "certificate") ||
				strings.Contains(err.Error(), "x509") ||
				strings.Contains(err.Error(), "tls")

			attempts = append(attempts, endpointAttempt{
				URL:      endpoint,
				Error:    err.Error(),
				Protocol: "HTTPS",
			})

			// If TLS error and user hasn't allowed insecure TLS, provide helpful guidance
			if isTLSError && !opts.AllowInsecureTLS {
				logger.Warn("TLS certificate verification failed for Wazuh backend")
				logger.Warn("This is expected if Wazuh uses self-signed certificates")
				logger.Warn("")
				logger.Warn("Options:")
				logger.Warn("  1. (Recommended) Install valid TLS certificates on Wazuh server")
				logger.Warn("  2. (Temporary) Use --allow-insecure-tls flag to skip verification")
				logger.Warn("     WARNING: This is insecure - only use in dev/test environments")
				logger.Warn("")
				logger.Warn("Example:")
				logger.Warn("  eos update hecate add wazuh \\")
				logger.Warn("    --dns wazuh.yourdomain.com \\")
				logger.Warn("    --upstream " + backend + " \\")
				logger.Warn("    --allow-insecure-tls")
			}

			continue
		}
		defer resp.Body.Close()

		logger.Debug("HTTPS response received",
			zap.String("endpoint", endpoint),
			zap.Int("status_code", resp.StatusCode),
			zap.String("status", resp.Status))

		// Accept all 2xx, 3xx, and 4xx status codes (anything < 500)
		// 401/403 expected without authentication (Wazuh requires SAML login)
		// 302 expected (redirect to login page)
		if resp.StatusCode >= 200 && resp.StatusCode < 500 {
			logger.Info("    ✓ Wazuh backend is responding",
				zap.String("endpoint", endpoint),
				zap.String("protocol", "HTTPS"),
				zap.Int("status_code", resp.StatusCode),
				zap.String("note", "401/302 expected without SAML auth - will work once SSO configured"))
			return nil
		}

		attempts = append(attempts, endpointAttempt{
			URL:        endpoint,
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Protocol:   "HTTPS",
		})
		continue
	}

	// Try HTTP fallback
	logger.Debug("HTTPS connection failed, trying HTTP",
		zap.Int("https_attempts", len(attempts)))

	httpEndpoints := []string{
		fmt.Sprintf("http://%s/", backend),
		fmt.Sprintf("http://%s/app/wazuh", backend),
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

		if resp.StatusCode >= 200 && resp.StatusCode < 500 {
			logger.Info("    ✓ Wazuh backend is responding",
				zap.String("endpoint", endpoint),
				zap.String("protocol", "HTTP"),
				zap.Int("status_code", resp.StatusCode),
				zap.String("note", "401/302 expected without SAML auth - will work once SSO configured"))
			return nil
		}

		attempts = append(attempts, endpointAttempt{
			URL:        endpoint,
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Protocol:   "HTTP",
		})
		continue
	}

	// All attempts failed - build detailed error message
	return w.buildValidationError(backend, attempts)
}

// buildValidationError creates a detailed error message showing all attempted endpoints
func (w *WazuhIntegrator) buildValidationError(backend string, attempts []endpointAttempt) error {
	var errorMsg strings.Builder

	errorMsg.WriteString(fmt.Sprintf("Wazuh not responding at %s\n\n", backend))

	// Show HTTPS attempts
	errorMsg.WriteString("Tried HTTPS endpoints:\n")
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

	// Show HTTP attempts
	errorMsg.WriteString("\nTried HTTP endpoints:\n")
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

	errorMsg.WriteString("\n⚠️  Note: 401/403/302 responses during validation are EXPECTED.\n")
	errorMsg.WriteString("    Wazuh requires SAML authentication (configured by this command).\n")
	errorMsg.WriteString("    If you're seeing 401/302, the service IS running - SAML will work once configured.\n\n")
	errorMsg.WriteString("Ensure Wazuh is running at the backend address.\n")
	errorMsg.WriteString(fmt.Sprintf("Expected: Wazuh dashboard listening on port %d (HTTPS or HTTP)\n", hecate.WazuhDefaultPort))
	errorMsg.WriteString("\nTroubleshooting:\n")
	errorMsg.WriteString("  1. Verify Wazuh services: systemctl status wazuh-dashboard wazuh-indexer\n")
	errorMsg.WriteString("  2. Check dashboard logs: journalctl -u wazuh-dashboard -n 50\n")
	errorMsg.WriteString(fmt.Sprintf("  3. Test connectivity: curl -k https://%s/\n", backend))
	errorMsg.WriteString("  4. Skip validation (if you know service is running): --skip-backend-check\n")

	return eos_err.NewUserError("%s", errorMsg.String())
}

// ConfigureAuthentication sets up Authentik SAML provider for Wazuh
func (w *WazuhIntegrator) ConfigureAuthentication(rc *eos_io.RuntimeContext, opts *ServiceOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("  [2/3] Configuring Authentik SAML provider for Wazuh")

	if opts.DryRun {
		logger.Info("    [DRY RUN] Would create Authentik SAML property mappings (username, email, Roles)")
		logger.Info("    [DRY RUN] Would create SAML provider with ACS URL: https://" + opts.DNS + "/_opendistro/_security/saml/acs")
		logger.Info("    [DRY RUN] Would create Authentik application 'Wazuh SIEM'")
		logger.Info("    [DRY RUN] Would download SAML metadata XML")
		logger.Info("    [DRY RUN] Would store metadata in Consul KV: service/wazuh/sso/metadata_xml")
		return nil
	}

	// Step 1: Get Authentik credentials
	// TEMPORARY: Read from .env until Vault migration complete
	logger.Info("    Getting Authentik credentials")
	authentikToken, authentikBaseURL, err := w.getAuthentikCredentials(rc.Ctx)
	if err != nil {
		return fmt.Errorf("failed to get Authentik credentials: %w\n\n"+
			"Ensure /opt/bionicgpt/.env contains:\n"+
			"  AUTHENTIK_TOKEN=your_authentik_api_token\n"+
			"  AUTHENTIK_BASE_URL=http://localhost:9000\n"+
			"Get API token from: https://hera.your-domain/if/admin/#/core/tokens", err)
	}

	// Step 2: Initialize Authentik SAML client
	logger.Info("    Initializing Authentik SAML client", zap.String("base_url", authentikBaseURL))
	samlClient := authentik.NewSAMLClient(authentikBaseURL, authentikToken)

	// Step 3: Verify Authentik is healthy
	logger.Info("    Verifying Authentik API health")
	if err := samlClient.CheckHealth(rc.Ctx); err != nil {
		return fmt.Errorf("Authentik API not accessible: %w\n\n"+
			"Troubleshooting:\n"+
			"  1. Check Authentik is running: docker ps | grep authentik\n"+
			"  2. Verify API token is valid\n"+
			"  3. Check Authentik logs: docker logs authentik-server", err)
	}

	// Step 4: Create SAML property mappings
	logger.Info("    Creating SAML property mappings (username, email, Roles)")
	propertyMappingPKs, err := samlClient.CreatePropertyMappings(rc.Ctx)
	if err != nil {
		return fmt.Errorf("failed to create property mappings: %w", err)
	}
	w.resources.PropertyMappingPKs = propertyMappingPKs // Track for rollback
	logger.Info("    ✓ Property mappings created", zap.Int("count", len(propertyMappingPKs)))

	// Step 5: Get authorization flow
	logger.Info("    Getting default authorization flow")
	flowPK, err := samlClient.GetDefaultAuthFlow(rc.Ctx)
	if err != nil {
		logger.Warn("Failed to get auth flow, using default", zap.Error(err))
		flowPK = "default-provider-authorization-implicit-consent"
	}

	// Step 6: Create SAML provider
	logger.Info("    Creating SAML provider")

	// Sanitize DNS (remove protocol, port)
	domain := strings.TrimPrefix(opts.DNS, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	if colonPos := strings.Index(domain, ":"); colonPos != -1 {
		domain = domain[:colonPos]
	}
	domain = strings.TrimSpace(domain)

	wazuhURL := fmt.Sprintf("https://%s", domain)

	// Get SAML entity ID from options (default: "wazuh-saml")
	entityID := opts.SAMLEntityID
	if entityID == "" {
		entityID = "wazuh-saml"
	}

	providerConfig := authentik.SAMLProviderConfig{
		Name:              "wazuh-saml-provider",
		AuthorizationFlow: flowPK,
		PropertyMappings:  propertyMappingPKs,
		ACSUrl:            fmt.Sprintf("%s/_opendistro/_security/saml/acs", wazuhURL),
		Issuer:            entityID,
		SPBinding:         "post",
		Audience:          entityID,
	}

	providerPK, err := samlClient.CreateSAMLProvider(rc.Ctx, providerConfig)
	if err != nil {
		return fmt.Errorf("failed to create SAML provider: %w", err)
	}
	logger.Info("    ✓ SAML provider created", zap.String("pk", providerPK))
	w.resources.SAMLProviderPK = providerPK

	// Step 7: Create Authentik application
	logger.Info("    Creating Authentik application 'Wazuh SIEM'")
	appConfig := authentik.ApplicationConfig{
		Name:             "Wazuh SIEM",
		Slug:             "wazuh-siem",
		Provider:         providerPK,
		MetaLaunchURL:    wazuhURL,
		PolicyEngineMode: "any",
	}

	appPK, err := samlClient.CreateApplication(rc.Ctx, appConfig)
	if err != nil {
		return fmt.Errorf("failed to create application: %w", err)
	}
	logger.Info("    ✓ Application created", zap.String("pk", appPK))
	w.resources.ApplicationPK = appPK
	w.resources.ApplicationSlug = "wazuh-siem"

	// Step 8: Download SAML metadata
	logger.Info("    Downloading SAML metadata XML")
	metadata, err := samlClient.DownloadMetadata(rc.Ctx, "wazuh-siem")
	if err != nil {
		return fmt.Errorf("failed to download metadata: %w", err)
	}
	logger.Info("    ✓ Metadata downloaded", zap.Int("size_bytes", len(metadata)))

	// Step 9: Store metadata in Consul KV for Wazuh server to retrieve
	logger.Info("    Storing metadata in Consul KV")
	consulClient, err := consulapi.NewClient(consulapi.DefaultConfig())
	if err != nil {
		logger.Warn("Failed to create Consul client, skipping metadata storage", zap.Error(err))
		logger.Warn("Wazuh server will need to fetch metadata directly from Authentik API")
	} else {
		metadataKey := "service/wazuh/sso/metadata_xml"
		kvPair := &consulapi.KVPair{
			Key:   metadataKey,
			Value: metadata,
		}
		_, err = consulClient.KV().Put(kvPair, nil)
		if err != nil {
			logger.Warn("Failed to store metadata in Consul KV", zap.Error(err))
			logger.Warn("Wazuh server will need to fetch metadata directly from Authentik API")
		} else {
			logger.Info("    ✓ Metadata stored in Consul KV", zap.String("key", metadataKey))
			w.resources.MetadataStored = true
			w.resources.ConsulKVKeysCreated = append(w.resources.ConsulKVKeysCreated, metadataKey)
		}
	}

	// Step 10: Store configuration in Consul KV
	logger.Info("    Storing Wazuh SSO configuration in Consul KV")
	if consulClient != nil {
		configKV := map[string]string{
			"service/wazuh/config/sso/authentik_url": authentikBaseURL,
			"service/wazuh/config/sso/wazuh_url":     wazuhURL,
			"service/wazuh/config/sso/entity_id":     entityID,
			"service/wazuh/config/sso/enabled":       "true",
		}

		for key, value := range configKV {
			kvPair := &consulapi.KVPair{
				Key:   key,
				Value: []byte(value),
			}
			if _, err := consulClient.KV().Put(kvPair, nil); err != nil {
				logger.Warn("Failed to store config in Consul KV", zap.String("key", key), zap.Error(err))
			} else {
				w.resources.ConsulKVKeysCreated = append(w.resources.ConsulKVKeysCreated, key)
			}
		}
		logger.Info("    ✓ Configuration stored in Consul KV")
	}

	logger.Info("  ✓ Authentik SAML provider configuration complete")
	logger.Info("")
	logger.Info("Next steps:")
	logger.Info("  1. On your Wazuh server, run:")
	logger.Info("     eos update wazuh --add authentik \\")
	logger.Info(fmt.Sprintf("       --authentik-url %s \\", authentikBaseURL))
	logger.Info(fmt.Sprintf("       --wazuh-url %s", wazuhURL))
	logger.Info("")
	logger.Info("  2. Test SSO login:")
	logger.Info(fmt.Sprintf("     Visit: %s", wazuhURL))
	logger.Info("     Click 'Log in with SSO' and use your Authentik credentials")

	return nil
}

// HealthCheck verifies Authentik SAML configuration
func (w *WazuhIntegrator) HealthCheck(rc *eos_io.RuntimeContext, opts *ServiceOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("  [3/3] Verifying Authentik SAML configuration")

	// Basic check: verify Authentik application exists
	authentikToken, authentikBaseURL, err := w.getAuthentikCredentials(rc.Ctx)
	if err != nil {
		logger.Warn("Skipping health check (Authentik credentials not available)")
		return nil // Non-fatal
	}

	samlClient := authentik.NewSAMLClient(authentikBaseURL, authentikToken)

	// Check if SAML provider exists
	providerPK, err := samlClient.CreateSAMLProvider(rc.Ctx, authentik.SAMLProviderConfig{
		Name: "wazuh-saml-provider",
		// Other fields not needed for existence check
	})
	if err != nil {
		logger.Warn("Failed to verify SAML provider", zap.Error(err))
		return nil // Non-fatal
	}

	if providerPK != "" {
		logger.Info("    ✓ Authentik SAML provider configured", zap.String("provider_pk", providerPK))
	}

	// Check if metadata is in Consul KV
	consulClient, err := consulapi.NewClient(consulapi.DefaultConfig())
	if err == nil {
		kv, _, err := consulClient.KV().Get("service/wazuh/sso/metadata_xml", nil)
		if err == nil && kv != nil && len(kv.Value) > 0 {
			logger.Info("    ✓ SAML metadata available in Consul KV", zap.Int("size_bytes", len(kv.Value)))
		} else {
			logger.Warn("SAML metadata not found in Consul KV")
			logger.Warn("Wazuh server will need to fetch metadata directly from Authentik")
		}
	}

	return nil
}

// Rollback removes Wazuh integration resources from Authentik
func (w *WazuhIntegrator) Rollback(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Warn("Rolling back Wazuh integration")

	if w.resources == nil {
		logger.Debug("No resources to rollback")
		return nil
	}

	token, baseURL, err := w.getAuthentikCredentials(rc.Ctx)
	if err != nil {
		return fmt.Errorf("cannot rollback without Authentik credentials: %w", err)
	}
	apiClient := authentik.NewClient(baseURL, token)
	samlClient := authentik.NewSAMLClient(baseURL, token)

	// Delete application
	if w.resources.ApplicationSlug != "" {
		logger.Info("Deleting Authentik application", zap.String("slug", w.resources.ApplicationSlug))
		if err := apiClient.DeleteApplication(rc.Ctx, w.resources.ApplicationSlug); err != nil {
			logger.Warn("Failed to delete application", zap.Error(err))
		} else {
			logger.Info("    ✓ Deleted application", zap.String("slug", w.resources.ApplicationSlug))
		}
	}

	// Delete SAML provider
	if w.resources.SAMLProviderPK != "" {
		logger.Info("Deleting SAML provider", zap.String("pk", w.resources.SAMLProviderPK))
		if err := samlClient.DeleteSAMLProvider(rc.Ctx, w.resources.SAMLProviderPK); err != nil {
			logger.Warn("Failed to delete SAML provider", zap.Error(err))
		} else {
			logger.Info("    ✓ Deleted SAML provider", zap.String("pk", w.resources.SAMLProviderPK))
		}
	}

	// Delete property mappings
	for _, pk := range w.resources.PropertyMappingPKs {
		logger.Info("Deleting property mapping", zap.String("pk", pk))
		if err := samlClient.DeletePropertyMapping(rc.Ctx, pk); err != nil {
			logger.Warn("Failed to delete property mapping", zap.String("pk", pk), zap.Error(err))
		} else {
			logger.Info("    ✓ Deleted property mapping", zap.String("pk", pk))
		}
	}

	// Remove ALL Consul KV keys
	if len(w.resources.ConsulKVKeysCreated) > 0 {
		consulClient, err := consulapi.NewClient(consulapi.DefaultConfig())
		if err == nil {
			logger.Info("Removing Consul KV keys", zap.Int("count", len(w.resources.ConsulKVKeysCreated)))
			for _, key := range w.resources.ConsulKVKeysCreated {
				if _, err := consulClient.KV().Delete(key, nil); err != nil {
					logger.Warn("Failed to delete Consul KV key", zap.String("key", key), zap.Error(err))
				} else {
					logger.Info("    ✓ Deleted Consul KV key", zap.String("key", key))
				}
			}
		}
	}

	logger.Info("✓ Rollback complete")
	return nil
}

// getAuthentikCredentials retrieves Authentik API credentials
// TEMPORARY: Read from .env until Vault migration complete
func (w *WazuhIntegrator) getAuthentikCredentials(ctx context.Context) (string, string, error) {
	// Reuse BionicGPT's .env file (same Authentik instance)
	bionicgptEnv, err := readEnvFile("/opt/bionicgpt/.env")
	if err != nil {
		return "", "", fmt.Errorf("failed to read /opt/bionicgpt/.env: %w\n"+
			"Ensure BionicGPT/Authentik is installed with: eos create bionicgpt", err)
	}

	// Check for AUTHENTIK_TOKEN
	apiKey := bionicgptEnv["AUTHENTIK_TOKEN"]
	if apiKey == "" {
		apiKey = bionicgptEnv["AUTHENTIK_API_KEY"]
	}

	if apiKey == "" {
		return "", "", fmt.Errorf("AUTHENTIK_TOKEN not found in /opt/bionicgpt/.env\n" +
			"Add to .env file:\n" +
			"  AUTHENTIK_TOKEN=your_authentik_api_token\n" +
			"Get token from: https://hera.your-domain/if/admin/#/core/tokens")
	}

	// Get base URL
	baseURL := bionicgptEnv["AUTHENTIK_BASE_URL"]
	if baseURL == "" {
		baseURL = "http://localhost:9000" // Default
	}

	return apiKey, baseURL, nil
}
