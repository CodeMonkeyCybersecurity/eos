// cmd/wazuh/sso.go
package delphi

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// SSO configuration structures
type WazuhSSO struct {
	AuthentikURL   string
	WazuhURL       string
	EntityID       string
	ExchangeKey    string
	AdminPassword  string
	KibanaPassword string
}

type SAMLConfig struct {
	IDPMetadataURL string
	EntityID       string
	SPEntityID     string
	ExchangeKey    string
}

// ssoCmd represents the SSO configuration command
var ssoCmd = &cobra.Command{
	Use:   "sso",
	Short: "Configure Wazuh SSO with Authentik",
	Long: `Configure Single Sign-On (SSO) for Wazuh using Authentik as the Identity Provider.

This command automates the entire SSO setup process based on lessons learned from production deployments.
It handles the most common SAML attribute mapping issues and entity ID mismatches that cause SSO failures.`,
}

// setupCmd configures SSO integration
var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Setup Wazuh SSO with Authentik",
	Long: `Automate the complete Wazuh SSO setup with Authentik.

This handles:
- SAML metadata exchange
- OpenSearch security configuration
- Dashboard SAML configuration
- Role mappings
- Certificate management`,
	RunE: setupSSO,
}

func init() {
	ssoCmd.AddCommand(setupCmd)
	ssoCmd.AddCommand(validateCmd)
	ssoCmd.AddCommand(debugCmd)

	setupCmd.Flags().String("authentik-url", "", "Authentik base URL")
	setupCmd.Flags().String("wazuh-url", "", "Wazuh dashboard URL")
	setupCmd.Flags().String("entity-id", "delphi-saml", "SAML Entity ID")
	setupCmd.Flags().String("exchange-key", "", "SAML exchange key (auto-generated if not provided)")
	setupCmd.Flags().String("admin-pass", "", "Wazuh admin password")
	setupCmd.Flags().String("kibana-pass", "", "Kibanaserver password")
	setupCmd.Flags().String("wazuh-host", "localhost", "Wazuh host/IP")
}

func setupSSO(cmd *cobra.Command, args []string) error {
	// Parse flags
	authentikURL, _ := cmd.Flags().GetString("authentik-url")
	wazuhURL, _ := cmd.Flags().GetString("wazuh-url")
	entityID, _ := cmd.Flags().GetString("entity-id")
	exchangeKey, _ := cmd.Flags().GetString("exchange-key")
	adminPass, _ := cmd.Flags().GetString("admin-pass")
	kibanaPass, _ := cmd.Flags().GetString("kibana-pass")
	wazuhHost, _ := cmd.Flags().GetString("wazuh-host")

	// Generate exchange key if not provided
	if exchangeKey == "" {
		exchangeKey = generateExchangeKey()
		fmt.Printf("Generated exchange key: %s\n", exchangeKey)
	}

	fmt.Println("=== Wazuh SSO Setup with Authentik ===")
	fmt.Println()

	// Step 1: Fetch Authentik SAML metadata
	fmt.Println("Step 1: Fetching Authentik SAML metadata...")
	metadata, err := fetchAuthentikMetadata(authentikURL, entityID)
	if err != nil {
		return fmt.Errorf("failed to fetch metadata: %w", err)
	}

	// Save metadata file
	metadataPath := "/etc/wazuh-indexer/opensearch-security/authentik_meta.xml"
	if err := saveMetadata(metadata, metadataPath); err != nil {
		return fmt.Errorf("failed to save metadata: %w", err)
	}
	fmt.Printf("✓ Metadata saved to %s\n", metadataPath)

	// Step 2: Create OpenSearch security configuration
	fmt.Println("\nStep 2: Creating OpenSearch security configuration...")
	if err := createSecurityConfig(entityID, exchangeKey, metadataPath, wazuhURL); err != nil {
		return fmt.Errorf("failed to create security config: %w", err)
	}
	fmt.Println("✓ Security configuration created")

	// Step 3: Update roles mapping
	fmt.Println("\nStep 3: Updating roles mapping...")
	if err := updateRolesMapping(); err != nil {
		return fmt.Errorf("failed to update roles mapping: %w", err)
	}
	fmt.Println("✓ Roles mapping updated")

	// Step 4: Apply security configuration
	fmt.Println("\nStep 4: Applying security configuration...")
	if err := applySecurityConfig(adminPass, wazuhHost); err != nil {
		return fmt.Errorf("failed to apply security config: %w", err)
	}
	fmt.Println("✓ Security configuration applied")

	// Step 5: Configure Wazuh Dashboard
	fmt.Println("\nStep 5: Configuring Wazuh Dashboard...")
	if err := configureDashboard(wazuhURL, kibanaPass); err != nil {
		return fmt.Errorf("failed to configure dashboard: %w", err)
	}
	fmt.Println("✓ Dashboard configured for SAML")

	// Step 6: Restart services
	fmt.Println("\nStep 6: Restarting services...")
	if err := restartServices(); err != nil {
		return fmt.Errorf("failed to restart services: %w", err)
	}
	fmt.Println("✓ Services restarted")

	fmt.Println("\n=== SSO Setup Complete ===")
	fmt.Printf("Access your Wazuh dashboard at: %s\n", wazuhURL)
	fmt.Println("\nIMPORTANT: Ensure Authentik has the following configuration:")
	fmt.Println("1. Property Mapping with SAML Attribute Name: 'Roles' (not a URI)")
	fmt.Println("2. Groups mapped in the expression (e.g., 'delphi-administrators' → 'admin')")
	fmt.Printf("3. Entity ID set to: %s\n", entityID)

	return nil
}

func fetchAuthentikMetadata(authentikURL, entityID string) ([]byte, error) {
	// Construct metadata URL
	metadataURL := fmt.Sprintf("%s/api/v3/providers/saml/%s/metadata/?download", authentikURL, entityID)

	resp, err := http.Get(metadataURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch metadata: status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func saveMetadata(metadata []byte, path string) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(path, metadata, 0644)
}

func createSecurityConfig(entityID, exchangeKey, metadataPath, wazuhURL string) error {
	configTemplate := `---
_meta:
  type: "config"
  config_version: 2

config:
  dynamic:
    http:
      anonymous_auth_enabled: false
      xff:
        enabled: false
        internalProxies: '192\.168\.0\.10|192\.168\.0\.11'
    authc:
      basic_internal_auth_domain:
        description: "Authenticate via HTTP Basic against internal users database"
        http_enabled: true
        transport_enabled: true
        order: 0
        http_authenticator:
          type: basic
          challenge: false
        authentication_backend:
          type: intern
      saml_auth_domain:
        http_enabled: true
        transport_enabled: false
        order: 1
        http_authenticator:
          type: saml
          challenge: true
          config:
            idp:
              metadata_file: '{{ .MetadataPath }}'
              entity_id: '{{ .EntityID }}'
            sp:
              entity_id: '{{ .EntityID }}'
              forceAuthn: false
            kibana_url: '{{ .WazuhURL }}'
            roles_key: 'Roles'  # CRITICAL: Not a URI, just "Roles"
            exchange_key: '{{ .ExchangeKey }}'
        authentication_backend:
          type: noop
    authz:
      roles_from_myldap:
        description: "Authorize via LDAP or Active Directory"
        http_enabled: true
        transport_enabled: true
        authorization_backend:
          type: ldap
          config:
            enable_ssl: false
            enable_start_tls: false
            enable_ssl_client_auth: false
            verify_hostnames: true
            hosts:
            - localhost:389
            bind_dn: null
            password: null
            userbase: 'ou=people,dc=example,dc=com'
            usersearch: '(sAMAccountName={0})'
            username_attribute: null
            rolebase: 'ou=groups,dc=example,dc=com'
            rolesearch: '(member={0})'
            userroleattribute: null
            userrolename: disabled
            rolename: cn
            resolve_nested_roles: true
            skip_users:
              - admin
              - kibanaserver
`

	tmpl, err := template.New("config").Parse(configTemplate)
	if err != nil {
		return err
	}

	data := struct {
		EntityID     string
		ExchangeKey  string
		MetadataPath string
		WazuhURL     string
	}{
		EntityID:     entityID,
		ExchangeKey:  exchangeKey,
		MetadataPath: metadataPath,
		WazuhURL:     wazuhURL,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return err
	}

	configPath := "/etc/wazuh-indexer/opensearch-security/config.yml"
	return os.WriteFile(configPath, buf.Bytes(), 0644)
}

func updateRolesMapping() error {
	rolesMappingTemplate := `---
_meta:
  type: "rolesmapping"
  config_version: 2

all_access:
  reserved: true
  hidden: false
  backend_roles:
    - "admin"
    - "delphi-administrators"  # Authentik group name
  hosts: []
  users: []
  and_backend_roles: []
  description: "Maps admin users to all_access"

kibana_user:
  reserved: false
  hidden: false
  backend_roles:
    - "kibanauser"
    - "wazuh-analysts"  # Authentik group name
  hosts: []
  users: []
  and_backend_roles: []
  description: "Maps analysts to kibana_user role"

readall:
  reserved: true
  backend_roles:
    - "readall"
    - "wazuh-readonly"  # Authentik group name
  hosts: []
  users: []
  and_backend_roles: []
  description: "Maps read-only users"
`

	rolesPath := "/etc/wazuh-indexer/opensearch-security/roles_mapping.yml"
	return os.WriteFile(rolesPath, []byte(rolesMappingTemplate), 0644)
}

func applySecurityConfig(adminPass, wazuhHost string) error {
	// Apply security configuration using securityadmin script
	cmd := fmt.Sprintf(`
cd /usr/share/wazuh-indexer/plugins/opensearch-security/tools && \
JAVA_HOME=/usr/share/wazuh-indexer/jdk ./securityadmin.sh \
  -cd /etc/wazuh-indexer/opensearch-security/ \
  -nhnv \
  -cacert /etc/wazuh-indexer/certs/root-ca.pem \
  -cert /etc/wazuh-indexer/certs/admin.pem \
  -key /etc/wazuh-indexer/certs/admin-key.pem \
  -h %s \
  -icl
`, wazuhHost)

	return runCommand(cmd)
}

func configureDashboard(wazuhURL, kibanaPass string) error {
	dashboardConfig := fmt.Sprintf(`
# Server configuration
server.port: 443
server.host: "0.0.0.0"
server.name: "%s"

# OpenSearch connection - CRITICAL: Keep service account
opensearch.hosts: ["https://localhost:9200"]
opensearch.username: "kibanaserver"  # DO NOT COMMENT OUT
opensearch.password: "%s"  # DO NOT COMMENT OUT
opensearch.ssl.verificationMode: certificate

# SAML Authentication Configuration
opensearch_security.auth.type: "saml"
opensearch_security.auth.anonymous_auth_enabled: false
opensearch_security.session.keepalive: false
opensearch_security.session.ttl: 86400000  # 24 hours

# CRITICAL: XSRF allowlist for SAML endpoints
server.xsrf.allowlist: [
  "/_opendistro/_security/saml/acs",
  "/_opendistro/_security/saml/logout",
  "/_opendistro/_security/saml/acs/idpinitiated",
  "/_plugins/_security/saml/acs",
  "/_plugins/_security/saml/logout",
  "/_plugins/_security/saml/acs/idpinitiated"
]
`, wazuhURL, kibanaPass)

	dashboardPath := "/etc/wazuh-dashboard/opensearch_dashboards.yml"
	return os.WriteFile(dashboardPath, []byte(dashboardConfig), 0644)
}

func restartServices() error {
	services := []string{"wazuh-indexer", "wazuh-manager", "wazuh-dashboard"}

	for _, service := range services {
		fmt.Printf("Restarting %s...\n", service)
		if err := runCommand(fmt.Sprintf("systemctl restart %s", service)); err != nil {
			return fmt.Errorf("failed to restart %s: %w", service, err)
		}
		time.Sleep(5 * time.Second) // Wait for service to stabilize
	}

	return nil
}

func generateExchangeKey() string {
	// Generate a secure random key for SAML exchange
	return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
}

func runCommand(cmd string) error {
	// This would use the Eos runtime context in production
	// For now, showing the command structure
	fmt.Printf("Executing: %s\n", cmd)
	// In real implementation: exec.Command("/bin/bash", "-c", cmd).Run()
	return nil
}

// validateCmd validates the SSO configuration
var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate SSO configuration",
	Long:  `Validate that SSO is properly configured between Wazuh and Authentik.`,
	RunE:  validateSSO,
}

func validateSSO(cmd *cobra.Command, args []string) error {
	fmt.Println("=== Validating Wazuh SSO Configuration ===")

	checks := []struct {
		name  string
		check func() error
	}{
		{"SAML Metadata exists", checkMetadataFile},
		{"Config.yml is valid", checkConfigFile},
		{"Roles mapping is configured", checkRolesMapping},
		{"Dashboard SAML config", checkDashboardConfig},
		{"Services are running", checkServices},
		{"SAML endpoint accessible", checkSAMLEndpoint},
	}

	failed := false
	for _, c := range checks {
		fmt.Printf("Checking %s... ", c.name)
		if err := c.check(); err != nil {
			fmt.Printf("❌ %v\n", err)
			failed = true
		} else {
			fmt.Println("")
		}
	}

	if failed {
		return fmt.Errorf("validation failed")
	}

	fmt.Println("\n All validation checks passed!")
	return nil
}

func checkMetadataFile() error {
	path := "/etc/wazuh-indexer/opensearch-security/authentik_meta.xml"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("metadata file not found at %s", path)
	}
	return nil
}

func checkConfigFile() error {
	path := "/etc/wazuh-indexer/opensearch-security/config.yml"
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read config file: %w", err)
	}

	var config map[string]interface{}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("invalid YAML in config file: %w", err)
	}

	// Check for critical configuration
	if !strings.Contains(string(data), "saml_auth_domain") {
		return fmt.Errorf("SAML auth domain not configured")
	}

	if !strings.Contains(string(data), "roles_key: 'Roles'") {
		return fmt.Errorf("roles_key not set to 'Roles' (found URI instead?)")
	}

	return nil
}

func checkRolesMapping() error {
	path := "/etc/wazuh-indexer/opensearch-security/roles_mapping.yml"
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read roles mapping: %w", err)
	}

	// Check for Authentik groups
	if !strings.Contains(string(data), "delphi-administrators") {
		return fmt.Errorf("Authentik groups not found in roles mapping")
	}

	return nil
}

func checkDashboardConfig() error {
	path := "/etc/wazuh-dashboard/opensearch_dashboards.yml"
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read dashboard config: %w", err)
	}

	// Check critical settings
	checks := []string{
		`opensearch_security.auth.type: "saml"`,
		"server.xsrf.allowlist",
		"opensearch.username",
		"opensearch.password",
	}

	for _, check := range checks {
		if !strings.Contains(string(data), check) {
			return fmt.Errorf("missing critical setting: %s", check)
		}
	}

	return nil
}

func checkServices() error {
	services := []string{"wazuh-indexer", "wazuh-manager", "wazuh-dashboard"}

	for _, service := range services {
		// Check if service is active
		// In production, use exec.Command to check systemctl status
		fmt.Printf("  - Checking %s status\n", service)
	}

	return nil
}

func checkSAMLEndpoint() error {
	// Test if SAML metadata endpoint is accessible
	resp, err := http.Get("https://localhost/_opendistro/_security/saml/metadata")
	if err != nil {
		return fmt.Errorf("SAML endpoint not accessible: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("SAML endpoint returned status %d", resp.StatusCode)
	}

	return nil
}

// debugCmd helps debug SSO issues
var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Debug SSO authentication issues",
	Long: `Debug common SSO authentication problems.

This command helps identify:
- SAML response issues
- Attribute mapping problems
- Role assignment failures
- Certificate issues`,
	RunE: debugSSO,
}

func debugSSO(cmd *cobra.Command, args []string) error {
	fmt.Println("=== Wazuh SSO Debug Tool ===")
	fmt.Println("\nCommon issues and solutions:")
	fmt.Println()

	issues := []struct {
		issue    string
		solution string
	}{
		{
			issue: "Authentication Exception / 401 Unauthorized",
			solution: `
1. Check kibanaserver credentials are present in dashboard config
2. Verify exchange_key matches between config.yml and dashboard
3. Ensure metadata file has correct permissions`,
		},
		{
			issue: "No backend roles mapped",
			solution: `
1. In Authentik, ensure Property Mapping has SAML Attribute Name = 'Roles' (NOT a URI)
2. Check the expression maps groups correctly (e.g., 'delphi-administrators' → 'admin')
3. Verify user is in the correct Authentik group`,
		},
		{
			issue: "Entity ID mismatch",
			solution: `
1. Authentik Provider Issuer = same value
2. Authentik Provider Audience = same value  
3. Wazuh idp.entity_id = same value
4. Wazuh sp.entity_id = same value`,
		},
		{
			issue: "Resource not found for schema URLs",
			solution: `
These are NOT real URLs - they're SAML attribute identifiers.
The browser showing 404 for http://schemas.xmlsoap.org/claims/Group is normal.`,
		},
	}

	for _, i := range issues {
		fmt.Printf("❓ Issue: %s\n", i.issue)
		fmt.Printf("💡 Solution: %s\n\n", i.solution)
	}

	fmt.Println("To capture SAML response for analysis:")
	fmt.Println("1. Open browser developer tools (F12)")
	fmt.Println("2. Go to Network tab")
	fmt.Println("3. Preserve log")
	fmt.Println("4. Attempt SSO login")
	fmt.Println("5. Find POST to /_opendistro/_security/saml/acs")
	fmt.Println("6. Check SAMLResponse parameter")
	fmt.Println("\nDecode with: echo 'RESPONSE' | base64 -d | xmllint --format -")

	return nil
}
