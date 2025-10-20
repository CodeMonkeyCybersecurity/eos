// Package connectors provides service connector implementations
package connectors

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/synctypes"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AuthentikWazuhConnector implements SAML SSO integration between Authentik (IdP) and Wazuh (SP)
type AuthentikWazuhConnector struct{}

// NewAuthentikWazuhConnector creates a new Authentik-Wazuh SSO connector
func NewAuthentikWazuhConnector() *AuthentikWazuhConnector {
	return &AuthentikWazuhConnector{}
}

// Name returns the connector name
func (c *AuthentikWazuhConnector) Name() string {
	return "AuthentikWazuhConnector"
}

// Description returns a human-readable description
func (c *AuthentikWazuhConnector) Description() string {
	return "Configures SAML SSO authentication between Authentik (Identity Provider) and Wazuh (Service Provider)"
}

// ServicePair returns the normalized service pair identifier
func (c *AuthentikWazuhConnector) ServicePair() string {
	return "authentik-wazuh"
}

// PreflightCheck verifies both Authentik and Wazuh are accessible
func (c *AuthentikWazuhConnector) PreflightCheck(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Running pre-flight checks for Authentik and Wazuh")

	// ASSESS - Detect server role to provide helpful guidance
	logger.Debug("Detecting server role")
	serverRole, err := environment.DetectServerRole(rc)
	if err != nil {
		logger.Warn("Server role detection failed, continuing with basic checks", zap.Error(err))
	}

	if serverRole != nil {
		logger.Info("Detected server configuration",
			zap.String("roles", serverRole.DescribeRoles()),
			zap.String("confidence", serverRole.Confidence))

		// Provide helpful error if running on wrong server
		if serverRole.IsHecateServer && !serverRole.IsWazuhServer {
			return eos_err.NewUserError(
				"This command must be run on the Wazuh backend server.\n\n" +
					"Current server: " + serverRole.Hostname + "\n" +
					"Detected as: Hecate reverse proxy server\n" +
					"Detected services: " + serverRole.DescribeRoles() + "\n\n" +
					"Wazuh SSO configuration requires:\n" +
					"  1. Direct access to Wazuh config files (/etc/wazuh-indexer/)\n" +
					"  2. Ability to restart Wazuh services\n" +
					"  3. Network access to Authentik API\n\n" +
					"Please SSH to your Wazuh backend server and run:\n" +
					"  export AUTHENTIK_URL=https://hera.yourdomain.com\n" +
					"  export AUTHENTIK_TOKEN=<your-token>\n" +
					"  export WAZUH_URL=https://wazuh.yourdomain.com\n" +
					"  eos sync --authentik --wazuh")
		}

		if !serverRole.IsWazuhServer {
			return eos_err.NewUserError(
				"Wazuh not detected on this server.\n\n" +
					"Current server: " + serverRole.Hostname + "\n" +
					"Detected services: " + serverRole.DescribeRoles() + "\n\n" +
					"This command requires Wazuh to be installed locally.\n" +
					"If Wazuh is on a different server, please SSH there first.\n\n" +
					"To install Wazuh: eos create wazuh")
		}
	}

	// Check for required environment variables
	authentikURL := os.Getenv("AUTHENTIK_URL")
	authentikToken := os.Getenv("AUTHENTIK_TOKEN")
	wazuhURL := os.Getenv("WAZUH_URL")

	if authentikURL == "" {
		return eos_err.NewUserError(
			"AUTHENTIK_URL environment variable required.\n" +
				"Example: export AUTHENTIK_URL=https://auth.example.com")
	}

	if authentikToken == "" {
		return eos_err.NewUserError(
			"AUTHENTIK_TOKEN environment variable required.\n" +
				"Get your API token from: " + authentikURL + "/if/admin/#/core/tokens")
	}

	if wazuhURL == "" {
		return eos_err.NewUserError(
			"WAZUH_URL environment variable required.\n" +
				"Example: export WAZUH_URL=https://wazuh.example.com")
	}

	logger.Debug("Environment variables validated",
		zap.String("authentik_url", authentikURL),
		zap.String("wazuh_url", wazuhURL))

	// Check Authentik API accessibility
	logger.Debug("Checking Authentik API accessibility")
	authentikClient := authentik.NewSAMLClient(authentikURL, authentikToken)

	if err := authentikClient.CheckHealth(rc.Ctx); err != nil {
		return eos_err.NewUserError(
			"Cannot connect to Authentik API: %v\n"+
				"Check that:\n"+
				"  1. AUTHENTIK_URL is correct: %s\n"+
				"  2. AUTHENTIK_TOKEN is valid\n"+
				"  3. Authentik is accessible from this server",
			err, authentikURL)
	}

	logger.Info("Authentik pre-flight check passed",
		zap.String("url", authentikURL))

	// Check Wazuh accessibility
	logger.Debug("Checking Wazuh accessibility")

	// Check if Wazuh indexer config exists
	wazuhConfigPath := "/etc/wazuh-indexer/opensearch-security/config.yml"
	if _, err := os.Stat(wazuhConfigPath); os.IsNotExist(err) {
		return eos_err.NewUserError(
			"Wazuh indexer not found. Please install Wazuh first:\n" +
				"  Expected config at: " + wazuhConfigPath + "\n" +
				"  Install guide: https://documentation.wazuh.com/current/installation-guide/")
	}

	logger.Info("Wazuh pre-flight check passed",
		zap.String("url", wazuhURL),
		zap.String("config_path", wazuhConfigPath))

	return nil
}

// CheckConnection returns the current SAML SSO connection state
func (c *AuthentikWazuhConnector) CheckConnection(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig) (*synctypes.SyncState, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Checking Authentik-Wazuh SSO connection state")

	state := &synctypes.SyncState{}

	// Check Authentik status
	authentikURL := os.Getenv("AUTHENTIK_URL")
	authentikToken := os.Getenv("AUTHENTIK_TOKEN")

	if authentikURL != "" && authentikToken != "" {
		authentikClient := authentik.NewSAMLClient(authentikURL, authentikToken)
		err := authentikClient.CheckHealth(rc.Ctx)
		state.Service1Installed = true
		state.Service1Running = (err == nil)
		state.Service1Healthy = (err == nil)
	}

	// Check Wazuh status
	wazuhConfigPath := "/etc/wazuh-indexer/opensearch-security/config.yml"
	_, err := os.Stat(wazuhConfigPath)
	state.Service2Installed = (err == nil)
	state.Service2Running = state.Service2Installed // Simplified check
	state.Service2Healthy = state.Service2Installed

	// Check if SAML is configured in Wazuh
	if state.Service2Installed {
		configContent, err := os.ReadFile(wazuhConfigPath)
		if err != nil {
			logger.Warn("Could not read Wazuh config",
				zap.String("path", wazuhConfigPath),
				zap.Error(err))
			state.ConfigurationComplete = false
			state.ConfigurationValid = false
			state.Connected = false
			state.Reason = "Cannot read Wazuh configuration"
			return state, nil
		}

		// Check for SAML authentication domain
		hasSAMLDomain := strings.Contains(string(configContent), "saml_auth_domain")
		hasAuthentikMetadata := false

		// Check if metadata file exists
		metadataPath := "/etc/wazuh-indexer/opensearch-security/authentik-metadata.xml"
		if _, err := os.Stat(metadataPath); err == nil {
			hasAuthentikMetadata = true
		}

		state.ConfigurationComplete = hasSAMLDomain && hasAuthentikMetadata
		state.ConfigurationValid = state.ConfigurationComplete
		state.Connected = state.ConfigurationComplete && state.Service1Healthy && state.Service2Healthy

		if state.Connected {
			state.Healthy = true
			state.Reason = "SAML SSO configured and operational"
		} else if hasSAMLDomain && !hasAuthentikMetadata {
			state.Reason = "SAML domain configured but Authentik metadata missing"
		} else if !hasSAMLDomain {
			state.Reason = "SAML authentication not configured in Wazuh"
		} else {
			state.Reason = "Configuration incomplete or services unhealthy"
		}
	} else {
		state.Reason = "Wazuh not installed"
	}

	logger.Info("Connection state checked",
		zap.Bool("connected", state.Connected),
		zap.Bool("healthy", state.Healthy),
		zap.String("reason", state.Reason))

	return state, nil
}

// Backup creates backups of Wazuh security configurations
func (c *AuthentikWazuhConnector) Backup(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig) (*synctypes.BackupMetadata, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating configuration backups")

	// Create backup directory
	timestamp := time.Now().Format("20060102-150405")
	backupDir := filepath.Join("/opt/eos/backups/sync", fmt.Sprintf("authentik-wazuh-%s", timestamp))

	if err := os.MkdirAll(backupDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	metadata := &synctypes.BackupMetadata{
		BackupDir:       backupDir,
		BackupTime:      timestamp,
		BackupFiles:     make(map[string]string),
		RestartRequired: true, // Wazuh services need restart after config changes
	}

	// Backup Wazuh security configs
	securityDir := "/etc/wazuh-indexer/opensearch-security"
	configFiles := []string{
		"config.yml",
		"roles_mapping.yml",
	}

	for _, file := range configFiles {
		sourcePath := filepath.Join(securityDir, file)
		if _, err := os.Stat(sourcePath); err == nil {
			backupPath := filepath.Join(backupDir, file+".backup")

			if err := copyFile(sourcePath, backupPath); err != nil {
				logger.Warn("Could not backup file (may not exist)",
					zap.String("source", sourcePath),
					zap.Error(err))
			} else {
				metadata.BackupFiles[sourcePath] = backupPath
				logger.Debug("Backed up config file",
					zap.String("file", file),
					zap.String("backup_path", backupPath))
			}
		}
	}

	// Backup dashboard config
	dashboardConfigPath := "/etc/wazuh-dashboard/opensearch_dashboards.yml"
	if _, err := os.Stat(dashboardConfigPath); err == nil {
		dashboardBackupPath := filepath.Join(backupDir, "opensearch_dashboards.yml.backup")
		if err := copyFile(dashboardConfigPath, dashboardBackupPath); err != nil {
			logger.Warn("Could not backup dashboard config", zap.Error(err))
		} else {
			metadata.BackupFiles[dashboardConfigPath] = dashboardBackupPath
			metadata.Service2ConfigPath = dashboardConfigPath
		}
	}

	logger.Info("Configuration backup completed",
		zap.String("backup_dir", backupDir),
		zap.Int("files_backed_up", len(metadata.BackupFiles)))

	return metadata, nil
}

// Connect establishes SAML SSO between Authentik and Wazuh
func (c *AuthentikWazuhConnector) Connect(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring SAML SSO between Authentik and Wazuh")

	// Get configuration from environment
	authentikURL := os.Getenv("AUTHENTIK_URL")
	authentikToken := os.Getenv("AUTHENTIK_TOKEN")
	wazuhURL := os.Getenv("WAZUH_URL")
	entityID := os.Getenv("SAML_ENTITY_ID")

	if entityID == "" {
		entityID = "wazuh-saml" // Default entity ID
		logger.Info("Using default SAML entity ID",
			zap.String("entity_id", entityID))
	}

	// Phase 1: Configure Authentik SAML Provider
	logger.Info("[1/5] Configuring Authentik SAML provider")

	authentikClient := authentik.NewSAMLClient(authentikURL, authentikToken)

	// Create property mappings
	logger.Debug("Creating SAML property mappings")
	mappingPKs, err := authentikClient.CreatePropertyMappings(rc.Ctx)
	if err != nil {
		return fmt.Errorf("failed to create property mappings: %w", err)
	}
	logger.Info("Property mappings configured",
		zap.Int("count", len(mappingPKs)))

	// Get authorization flow
	logger.Debug("Fetching authorization flow")
	authFlow, err := authentikClient.GetDefaultAuthFlow(rc.Ctx)
	if err != nil {
		return fmt.Errorf("failed to get authorization flow: %w", err)
	}
	logger.Debug("Using authorization flow",
		zap.String("flow_pk", authFlow))

	// Create SAML provider
	logger.Debug("Creating SAML provider")
	acsURL := fmt.Sprintf("%s/_opendistro/_security/saml/acs", wazuhURL)

	provider := authentik.SAMLProviderConfig{
		Name:              "wazuh-saml-provider",
		AuthorizationFlow: authFlow,
		PropertyMappings:  mappingPKs,
		ACSUrl:            acsURL,
		Issuer:            entityID,
		SPBinding:         "post",
		Audience:          entityID,
	}

	providerPK, err := authentikClient.CreateSAMLProvider(rc.Ctx, provider)
	if err != nil {
		return fmt.Errorf("failed to create SAML provider: %w", err)
	}
	logger.Info("SAML provider configured",
		zap.String("provider_pk", providerPK))

	// Create application
	logger.Debug("Creating Authentik application")
	app := authentik.ApplicationConfig{
		Name:             "Wazuh SIEM",
		Slug:             "wazuh-siem",
		Provider:         providerPK,
		MetaLaunchURL:    wazuhURL,
		PolicyEngineMode: "any",
	}

	appPK, err := authentikClient.CreateApplication(rc.Ctx, app)
	if err != nil {
		return fmt.Errorf("failed to create application: %w", err)
	}
	logger.Info("Application configured",
		zap.String("app_pk", appPK),
		zap.String("slug", app.Slug))

	// Phase 2: Download SAML metadata
	logger.Info("[2/5] Downloading SAML metadata from Authentik")

	metadata, err := authentikClient.DownloadMetadata(rc.Ctx, app.Slug)
	if err != nil {
		return fmt.Errorf("failed to download metadata: %w", err)
	}
	logger.Info("Downloaded SAML metadata",
		zap.Int("size_bytes", len(metadata)))

	// Phase 3: Configure Wazuh
	logger.Info("[3/5] Configuring Wazuh OpenSearch Security")

	// Save metadata to Wazuh
	metadataPath := "/etc/wazuh-indexer/opensearch-security/authentik-metadata.xml"
	if err := os.WriteFile(metadataPath, metadata, 0644); err != nil {
		return fmt.Errorf("failed to write metadata file: %w", err)
	}
	logger.Debug("Wrote metadata file",
		zap.String("path", metadataPath))

	// Generate exchange key
	exchangeKey, err := wazuh.GenerateExchangeKey()
	if err != nil {
		return fmt.Errorf("failed to generate exchange key: %w", err)
	}

	// Save exchange key
	exchangeKeyPath := "/etc/wazuh-indexer/opensearch-security/exchange.key"
	if err := os.WriteFile(exchangeKeyPath, []byte(exchangeKey), 0600); err != nil {
		return fmt.Errorf("failed to write exchange key: %w", err)
	}
	logger.Debug("Generated exchange key",
		zap.String("path", exchangeKeyPath))

	// Update Wazuh security config
	logger.Debug("Updating OpenSearch security config")
	if err := wazuh.UpdateSecurityConfig(rc, entityID, exchangeKey, wazuhURL); err != nil {
		return fmt.Errorf("failed to update security config: %w", err)
	}

	// Update roles mapping
	logger.Debug("Updating roles mapping")
	roleMappings := map[string]string{
		"wazuh-admins":   "all_access",
		"wazuh-analysts": "kibana_user",
		"wazuh-readonly": "readall",
	}

	if err := wazuh.UpdateRolesMapping(rc, roleMappings); err != nil {
		return fmt.Errorf("failed to update roles mapping: %w", err)
	}

	// Update dashboard config
	logger.Debug("Updating Wazuh dashboard config")
	if err := wazuh.UpdateDashboardConfig(rc); err != nil {
		return fmt.Errorf("failed to update dashboard config: %w", err)
	}

	// Phase 4: Apply security configuration
	logger.Info("[4/5] Applying OpenSearch security configuration")

	if err := wazuh.ApplySecurityConfig(rc); err != nil {
		return fmt.Errorf("failed to apply security config: %w", err)
	}

	logger.Info("Security configuration applied successfully")

	// Phase 5: Restart services (handled in Verify phase)
	logger.Info("[5/5] Configuration complete - services will be restarted in verification phase")

	return nil
}

// Verify validates the SAML SSO connection is working
func (c *AuthentikWazuhConnector) Verify(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying SAML SSO configuration")

	// Restart Wazuh services
	logger.Info("Restarting Wazuh services")
	if err := wazuh.RestartSSOServices(rc); err != nil {
		return fmt.Errorf("failed to restart services: %w", err)
	}

	// Wait for services to stabilize
	logger.Debug("Waiting for services to stabilize")
	time.Sleep(10 * time.Second)

	// Check service status
	logger.Debug("Checking service health")
	if err := wazuh.CheckServiceStatus(rc); err != nil {
		return fmt.Errorf("service health check failed: %w", err)
	}

	// Verify configuration files exist
	requiredFiles := []string{
		"/etc/wazuh-indexer/opensearch-security/authentik-metadata.xml",
		"/etc/wazuh-indexer/opensearch-security/exchange.key",
		"/etc/wazuh-indexer/opensearch-security/config.yml",
	}

	for _, file := range requiredFiles {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			return fmt.Errorf("required file missing: %s", file)
		}
	}

	// Verify config.yml contains SAML domain
	configContent, err := os.ReadFile("/etc/wazuh-indexer/opensearch-security/config.yml")
	if err != nil {
		return fmt.Errorf("failed to read config.yml: %w", err)
	}

	if !strings.Contains(string(configContent), "saml_auth_domain") {
		return fmt.Errorf("config.yml missing saml_auth_domain configuration")
	}

	logger.Info("SAML SSO verification complete",
		zap.String("status", "success"))

	logger.Info("\n" +
		"═══════════════════════════════════════════════════════\n" +
		"  SAML SSO Integration Complete!\n" +
		"═══════════════════════════════════════════════════════\n\n" +
		"Next steps:\n" +
		"  1. Navigate to: " + os.Getenv("WAZUH_URL") + "\n" +
		"  2. Click \"Sign in with SSO\"\n" +
		"  3. Authenticate with your Authentik credentials\n" +
		"  4. Verify you're redirected back to Wazuh dashboard\n\n" +
		"Troubleshooting:\n" +
		"  - Wazuh indexer logs:  journalctl -fu wazuh-indexer\n" +
		"  - Wazuh dashboard logs: journalctl -fu wazuh-dashboard\n" +
		"  - Metadata URL: " + os.Getenv("AUTHENTIK_URL") + "/application/saml/wazuh-siem/metadata/\n")

	return nil
}

// Rollback reverts SAML SSO configuration changes
func (c *AuthentikWazuhConnector) Rollback(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig, backup *synctypes.BackupMetadata) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Rolling back SAML SSO configuration changes",
		zap.String("backup_dir", backup.BackupDir))

	// Restore backed-up files
	for originalPath, backupPath := range backup.BackupFiles {
		logger.Debug("Restoring file",
			zap.String("original", originalPath),
			zap.String("backup", backupPath))

		if err := copyFile(backupPath, originalPath); err != nil {
			logger.Warn("Failed to restore file",
				zap.String("path", originalPath),
				zap.Error(err))
			// Continue with rollback even if some files fail
		}
	}

	// Restart services if required
	if backup.RestartRequired {
		logger.Info("Restarting Wazuh services after rollback")
		if err := wazuh.RestartSSOServices(rc); err != nil {
			logger.Warn("Failed to restart services after rollback", zap.Error(err))
			// Continue with rollback
		}
	}

	logger.Info("Rollback completed")
	return nil
}
