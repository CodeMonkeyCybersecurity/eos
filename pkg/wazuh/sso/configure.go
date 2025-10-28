// pkg/wazuh/sso/configure.go - Business logic for configuring Wazuh SSO with Authentik
// This code runs ON THE WAZUH SERVER to configure the Service Provider (SP) side

package sso

import (
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh"
	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConfigureOptions contains options for configuring Wazuh SSO
type ConfigureOptions struct {
	AuthentikURL string // URL to Authentik instance (e.g., https://hera.codemonkey.ai)
	WazuhURL     string // Public Wazuh dashboard URL (e.g., https://wazuh.codemonkey.ai)
	EntityID     string // SAML entity ID (default: "wazuh-saml")
	DryRun       bool   // Show what would be done without making changes
}

// Configure configures Wazuh SSO with Authentik SAML
// Follows Assess → Intervene → Evaluate pattern
func Configure(rc *eos_io.RuntimeContext, opts *ConfigureOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Set defaults
	if opts.EntityID == "" {
		opts.EntityID = "wazuh-saml"
	}

	logger.Info("Configuring Wazuh SSO with Authentik",
		zap.String("authentik_url", opts.AuthentikURL),
		zap.String("wazuh_url", opts.WazuhURL),
		zap.String("entity_id", opts.EntityID),
		zap.Bool("dry_run", opts.DryRun))

	// ========================================================================
	// ASSESS: Check current state
	// ========================================================================
	logger.Info("📋 ASSESS: Checking current Wazuh configuration")

	if err := assessWazuhInstallation(rc); err != nil {
		return fmt.Errorf("Wazuh assessment failed: %w", err)
	}

	metadata, err := assessMetadataAvailability(rc, opts)
	if err != nil {
		return fmt.Errorf("metadata assessment failed: %w", err)
	}

	backupDir, err := createBackup(rc, opts)
	if err != nil {
		return fmt.Errorf("backup creation failed: %w", err)
	}
	logger.Info("Backup created", zap.String("backup_dir", backupDir))

	// ========================================================================
	// INTERVENE: Apply configuration changes
	// ========================================================================
	logger.Info("🔧 INTERVENE: Applying SSO configuration")

	if opts.DryRun {
		logger.Info("  [DRY RUN] Would retrieve/generate SAML exchange key from Vault")
		logger.Info("  [DRY RUN] Would write " + wazuh.OpenSearchSAMLMetadataFile)
		logger.Info("  [DRY RUN] Would write " + wazuh.OpenSearchSAMLExchangeKey)
		logger.Info("  [DRY RUN] Would update " + wazuh.OpenSearchConfig)
		logger.Info("  [DRY RUN] Would update " + wazuh.OpenSearchRoleMappings)
		logger.Info("  [DRY RUN] Would update " + wazuh.OpenSearchDashboardYml)
		logger.Info("  [DRY RUN] Would apply security config via " + wazuh.SecurityAdminTool)
		logger.Info("  [DRY RUN] Would restart wazuh-indexer and wazuh-dashboard")
		logger.Info("✓ Dry run complete - no changes made")
		return nil
	}

	// Get/generate SAML exchange key
	exchangeKey, err := getOrGenerateExchangeKey(rc)
	if err != nil {
		return fmt.Errorf("failed to get exchange key: %w", err)
	}
	logger.Info("✓ Exchange key retrieved")

	// Write metadata file
	if err := os.WriteFile(wazuh.OpenSearchSAMLMetadataFile, metadata, wazuh.SAMLMetadataFilePerm); err != nil {
		return fmt.Errorf("failed to write metadata file: %w", err)
	}
	logger.Info("✓ Metadata file written", zap.String("path", wazuh.OpenSearchSAMLMetadataFile))

	// Write exchange key file
	if err := os.WriteFile(wazuh.OpenSearchSAMLExchangeKey, []byte(exchangeKey), wazuh.SAMLExchangeKeyPerm); err != nil {
		return fmt.Errorf("failed to write exchange key file: %w", err)
	}
	logger.Info("✓ Exchange key file written", zap.String("path", wazuh.OpenSearchSAMLExchangeKey))

	// Update OpenSearch Security config
	if err := wazuh.UpdateSecurityConfig(rc, opts.EntityID, exchangeKey, opts.WazuhURL); err != nil {
		return fmt.Errorf("failed to update security config: %w", err)
	}
	logger.Info("✓ OpenSearch security config updated")

	// Update roles mapping
	roleMappings := map[string]string{
		"wazuh-admin":    "all_access",
		"wazuh-analysts": "kibana_user",
		"wazuh-readonly": "readall",
	}
	if err := wazuh.UpdateRolesMapping(rc, roleMappings); err != nil {
		return fmt.Errorf("failed to update roles mapping: %w", err)
	}
	logger.Info("✓ Roles mapping updated", zap.Int("mappings", len(roleMappings)))

	// Update dashboard config
	if err := wazuh.UpdateDashboardConfig(rc); err != nil {
		return fmt.Errorf("failed to update dashboard config: %w", err)
	}
	logger.Info("✓ Dashboard config updated")

	// Apply security config
	if err := wazuh.ApplySecurityConfig(rc); err != nil {
		return fmt.Errorf("failed to apply security config: %w\n\n"+
			"Troubleshooting:\n"+
			"  1. Check OpenSearch indexer is running: systemctl status wazuh-indexer\n"+
			"  2. Check certificates: ls -l %s\n"+
			"  3. Review security config: cat %s\n"+
			"  4. Restore from backup if needed: %s", err, wazuh.OpenSearchCertsDir, wazuh.OpenSearchSAMLMetadataFile, backupDir)
	}
	logger.Info("✓ Security configuration applied")

	// Restart services
	if err := wazuh.RestartSSOServices(rc); err != nil {
		return fmt.Errorf("failed to restart services: %w\n\n"+
			"Services may be in inconsistent state. Restore from backup:\n"+
			"  Backup location: %s\n"+
			"  Run: eos update wazuh --restore %s", err, backupDir, backupDir)
	}
	logger.Info("✓ Services restarted")

	// ========================================================================
	// EVALUATE: Verify configuration
	// ========================================================================
	logger.Info("✅ EVALUATE: Verifying SSO configuration")

	if err := wazuh.CheckServiceStatus(rc); err != nil {
		return fmt.Errorf("service health check failed: %w\n\n"+
			"Services may not have started correctly. Check logs:\n"+
			"  journalctl -u wazuh-indexer -n 50\n"+
			"  journalctl -u wazuh-dashboard -n 50\n\n"+
			"Restore from backup if needed: %s", err, backupDir)
	}
	logger.Info("✓ All services are healthy")

	// Verify metadata file exists and is readable
	if _, err := os.Stat(wazuh.OpenSearchSAMLMetadataFile); err != nil {
		return fmt.Errorf("metadata file verification failed: %w", err)
	}

	// Verify exchange key file exists with correct permissions
	info, err := os.Stat(wazuh.OpenSearchSAMLExchangeKey)
	if err != nil {
		return fmt.Errorf("exchange key file verification failed: %w", err)
	}
	if info.Mode().Perm() != wazuh.SAMLExchangeKeyPerm {
		logger.Warn("Exchange key file has incorrect permissions",
			zap.String("current", info.Mode().Perm().String()),
			zap.String("expected", "0600"))
	}

	logger.Info("✓ File verification complete")

	// ========================================================================
	// SUCCESS: Provide next steps
	// ========================================================================
	logger.Info("")
	logger.Info("🎉 Wazuh SSO configuration complete!")
	logger.Info("")
	logger.Info("Next steps:")
	logger.Info(fmt.Sprintf("  1. Visit: %s", opts.WazuhURL))
	logger.Info("  2. Click 'Log in with SSO' or you may be redirected automatically")
	logger.Info("  3. Authenticate with your Authentik credentials")
	logger.Info("")
	logger.Info("Role mappings configured:")
	logger.Info("  - wazuh-admin → all_access (full administrator)")
	logger.Info("  - wazuh-analysts → kibana_user (read/analyze)")
	logger.Info("  - wazuh-readonly → readall (read-only access)")
	logger.Info("")
	logger.Info("Backup saved to:", zap.String("location", backupDir))
	logger.Info("To revert: eos update wazuh --restore " + backupDir)

	return nil
}

// assessWazuhInstallation verifies Wazuh is installed and required files exist
func assessWazuhInstallation(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check required files exist
	requiredFiles := []string{
		wazuh.OpenSearchConfig,
		wazuh.OpenSearchRoleMappings,
		wazuh.OpenSearchDashboardYml,
		wazuh.SecurityAdminTool,
		wazuh.OpenSearchRootCA,
		wazuh.OpenSearchAdminCert,
		wazuh.OpenSearchAdminKey,
	}

	for _, file := range requiredFiles {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			return fmt.Errorf("required file not found: %s\n\n"+
				"Wazuh may not be properly installed. Install with:\n"+
				"  eos create wazuh\n"+
				"Or follow: https://documentation.wazuh.com/current/installation-guide/", file)
		}
	}

	logger.Info("✓ Wazuh installation verified")

	// Check services are running
	if err := wazuh.CheckServiceStatus(rc); err != nil {
		return fmt.Errorf("Wazuh services not running: %w\n\n"+
			"Start services:\n"+
			"  systemctl start wazuh-indexer wazuh-dashboard", err)
	}

	logger.Info("✓ Wazuh services are running")

	return nil
}

// assessMetadataAvailability retrieves SAML metadata from Consul KV or Authentik API
func assessMetadataAvailability(rc *eos_io.RuntimeContext, opts *ConfigureOptions) ([]byte, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Strategy 1: Try Consul KV first (set by Hecate integrator)
	logger.Info("Checking for metadata in Consul KV")
	consulClient, err := api.NewClient(api.DefaultConfig())
	if err == nil {
		kv, _, err := consulClient.KV().Get("service/wazuh/sso/metadata_xml", nil)
		if err == nil && kv != nil && len(kv.Value) > 0 {
			logger.Info("✓ Metadata found in Consul KV", zap.Int("size_bytes", len(kv.Value)))
			return kv.Value, nil
		}
	}

	logger.Warn("Metadata not found in Consul KV, trying direct Authentik API")

	// Strategy 2: Fetch directly from Authentik API
	if opts.AuthentikURL == "" {
		return nil, fmt.Errorf("SAML metadata not available\n\n" +
			"Metadata not found in Consul KV and --authentik-url not provided.\n\n" +
			"Options:\n" +
			"  1. Run 'eos update hecate add wazuh' first (recommended)\n" +
			"  2. Provide --authentik-url to fetch metadata directly\n" +
			"  3. Store metadata manually in Consul KV:\n" +
			"     consul kv put service/wazuh/sso/metadata_xml @metadata.xml")
	}

	// Get Authentik API token (from environment or prompt)
	// TODO: Use interaction.GetRequiredString() with fallback chain
	authentikToken := os.Getenv("AUTHENTIK_TOKEN")
	if authentikToken == "" {
		return nil, fmt.Errorf("AUTHENTIK_TOKEN not set\n\n"+
			"Set environment variable:\n"+
			"  export AUTHENTIK_TOKEN=your_token\n\n"+
			"Get token from: %s/if/admin/#/core/tokens", opts.AuthentikURL)
	}

	samlClient := authentik.NewSAMLClient(opts.AuthentikURL, authentikToken)

	// Verify Authentik is accessible
	if err := samlClient.CheckHealth(rc.Ctx); err != nil {
		return nil, fmt.Errorf("Authentik API not accessible: %w\n\n"+
			"Troubleshooting:\n"+
			"  1. Verify Authentik URL: %s\n"+
			"  2. Check API token is valid\n"+
			"  3. Ensure network connectivity to Authentik server", err, opts.AuthentikURL)
	}

	// Download metadata
	logger.Info("Downloading metadata from Authentik", zap.String("url", opts.AuthentikURL))
	metadata, err := samlClient.DownloadMetadata(rc.Ctx, "wazuh-siem")
	if err != nil {
		return nil, fmt.Errorf("failed to download metadata: %w\n\n"+
			"Ensure Wazuh SAML provider exists in Authentik:\n"+
			"  1. Run 'eos update hecate add wazuh' to create provider\n"+
			"  2. Or manually create SAML provider in Authentik UI", err)
	}

	logger.Info("✓ Metadata downloaded from Authentik", zap.Int("size_bytes", len(metadata)))

	return metadata, nil
}

// createBackup creates a backup of current configuration files
func createBackup(rc *eos_io.RuntimeContext, opts *ConfigureOptions) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	if opts.DryRun {
		return "/tmp/dry-run-backup", nil
	}

	timestamp := time.Now().Format("20060102-150405")
	backupDir := fmt.Sprintf("%swazuh-sso-%s", wazuh.WazuhBackupDir, timestamp)

	if err := os.MkdirAll(backupDir, wazuh.BackupDirPerm); err != nil {
		return "", fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Backup config files
	filesToBackup := map[string]string{
		wazuh.OpenSearchConfig:        "config.yml",
		wazuh.OpenSearchRoleMappings:  "roles_mapping.yml",
		wazuh.OpenSearchDashboardYml: "opensearch_dashboards.yml",
	}

	for src, dst := range filesToBackup {
		data, err := os.ReadFile(src)
		if err != nil {
			logger.Warn("Failed to read file for backup", zap.String("file", src), zap.Error(err))
			continue
		}

		dstPath := fmt.Sprintf("%s/%s", backupDir, dst)
		if err := os.WriteFile(dstPath, data, wazuh.SecurityConfigPerm); err != nil {
			return "", fmt.Errorf("failed to write backup file %s: %w", dst, err)
		}
	}

	logger.Info("✓ Configuration backed up", zap.String("dir", backupDir))

	return backupDir, nil
}

// getOrGenerateExchangeKey retrieves exchange key from Vault or generates new one
func getOrGenerateExchangeKey(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Try to get from Vault
	// TODO: Use secrets.SecretManager once Vault is properly integrated
	// For now, generate a new key each time (idempotent - same key will be used)

	// Check if key already exists in file
	if data, err := os.ReadFile(wazuh.OpenSearchSAMLExchangeKey); err == nil && len(data) > 0 {
		logger.Info("Using existing exchange key from file")
		return string(data), nil
	}

	// Generate new key
	logger.Info("Generating new SAML exchange key")
	key, err := wazuh.GenerateExchangeKey()
	if err != nil {
		return "", fmt.Errorf("failed to generate exchange key: %w", err)
	}

	// TODO: Store in Vault
	// secretManager, err := secrets.NewSecretManager(rc, envConfig)
	// secretManager.StoreSecret("wazuh/sso/exchange_key", key)

	logger.Info("✓ Exchange key generated")

	return key, nil
}
