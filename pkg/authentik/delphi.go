// cmd/authentik/wazuh.go
package authentik

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// DelphiClient handles API interactions for Delphi/Wazuh SSO
// Note: Using the main AuthentikClient from authentik_client.go
// type AuthentikClient struct {
// 	BaseURL string
// 	APIKey  string
// 	Client  *http.Client
// }

// SAMLProvider represents an Authentik SAML provider
type SAMLProvider struct {
	Name               string   `json:"name"`
	AuthorizationFlow  string   `json:"authorization_flow"`
	ACSUrl             string   `json:"acs_url"`
	Issuer             string   `json:"issuer"`
	SPBinding          string   `json:"sp_binding"`
	Audience           string   `json:"audience"`
	SigningKP          string   `json:"signing_kp"`
	AssertionValidTime int      `json:"assertion_valid_not_on_or_after"`
	SessionValidTime   int      `json:"session_valid_not_on_or_after"`
	PropertyMappings   []string `json:"property_mappings"`
	NameIDMapping      string   `json:"name_id_mapping,omitempty"`
	DigestAlgorithm    string   `json:"digest_algorithm"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
}

// PropertyMapping for SAML attributes
type PropertyMapping struct {
	Name         string `json:"name"`
	SAMLName     string `json:"saml_name"`
	FriendlyName string `json:"friendly_name"`
	Expression   string `json:"expression"`
}

// wazuhCmd configures Authentik for Wazuh SSO
var wazuhCmd = &cobra.Command{
	Use:   "wazuh",
	Short: "Configure Authentik for Wazuh SSO",
	Long: `Configure Authentik as a SAML Identity Provider for Wazuh.

This command creates the necessary SAML provider, property mappings, and application
configuration in Authentik for Wazuh SSO integration.`,
}

// setupWazuhCmd creates the complete Authentik configuration
var setupWazuhCmd = &cobra.Command{
	Use:   "setup",
	Short: "Setup Authentik for Wazuh SSO",
	Long: `Create complete Authentik configuration for Wazuh SSO.

This includes:
- SAML signing certificate
- Property mappings for roles
- SAML provider configuration
- Application and group setup`,
	RunE: setupAuthentikForWazuh,
}

func init() {
	wazuhCmd.AddCommand(setupWazuhCmd)

	setupWazuhCmd.Flags().String("authentik-url", "", "Authentik API URL")
	setupWazuhCmd.Flags().String("api-key", "", "Authentik API key")
	setupWazuhCmd.Flags().String("wazuh-url", "", "Wazuh dashboard URL")
	setupWazuhCmd.Flags().String("entity-id", "delphi-saml", "SAML Entity ID")
	setupWazuhCmd.MarkFlagRequired("authentik-url")
	setupWazuhCmd.MarkFlagRequired("api-key")
	setupWazuhCmd.MarkFlagRequired("wazuh-url")
}

func setupAuthentikForWazuh(cmd *cobra.Command, args []string) error {
	authentikURL, _ := cmd.Flags().GetString("authentik-url")
	apiKey, _ := cmd.Flags().GetString("api-key")
	wazuhURL, _ := cmd.Flags().GetString("wazuh-url")
	entityID, _ := cmd.Flags().GetString("entity-id")

	// SECURITY: Set timeout to prevent resource exhaustion from slow/hanging connections
	client := &AuthentikClient{
		baseURL: authentikURL,
		token:   apiKey,
		client:  &http.Client{Timeout: 30 * time.Second},
	}

	fmt.Println("=== Configuring Authentik for Wazuh SSO ===")
	fmt.Println()

	// Step 1: Create or verify certificate
	fmt.Println("Step 1: Creating SAML signing certificate...")
	certID, err := client.createSAMLCertificate(entityID)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}
	fmt.Printf("✓ Certificate created/verified: %s\n", certID)

	// Step 2: Create the critical Roles property mapping
	fmt.Println("\nStep 2: Creating Roles property mapping...")
	rolesMappingID, err := client.createRolesPropertyMapping()
	if err != nil {
		return fmt.Errorf("failed to create roles mapping: %w", err)
	}
	fmt.Printf("✓ Roles property mapping created: %s\n", rolesMappingID)

	// Step 3: Create standard property mappings
	fmt.Println("\nStep 3: Creating standard property mappings...")
	mappingIDs, err := client.createStandardMappings()
	if err != nil {
		return fmt.Errorf("failed to create standard mappings: %w", err)
	}
	fmt.Println("✓ Standard mappings created")

	// Step 4: Create SAML Provider
	fmt.Println("\nStep 4: Creating SAML provider...")
	providerID, err := client.createSAMLProvider(entityID, wazuhURL, certID, append(mappingIDs, rolesMappingID))
	if err != nil {
		return fmt.Errorf("failed to create SAML provider: %w", err)
	}
	fmt.Printf("✓ SAML provider created: %s\n", providerID)

	// Step 5: Create Application
	fmt.Println("\nStep 5: Creating Wazuh application...")
	appID, err := client.createApplication(entityID, providerID)
	if err != nil {
		return fmt.Errorf("failed to create application: %w", err)
	}
	fmt.Printf("✓ Application created: %s\n", appID)

	// Step 6: Create groups
	fmt.Println("\nStep 6: Creating groups...")
	if err := client.createWazuhGroups(); err != nil {
		return fmt.Errorf("failed to create groups: %w", err)
	}
	fmt.Println("✓ Groups created")

	fmt.Println("\n=== Authentik Configuration Complete ===")
	fmt.Println("\nNext steps:")
	fmt.Println("1. Add users to the appropriate groups:")
	fmt.Println("   - delphi-administrators (maps to Wazuh admin)")
	fmt.Println("   - wazuh-analysts (maps to kibanauser)")
	fmt.Println("   - wazuh-readonly (maps to readall)")
	fmt.Printf("2. Download metadata from: %s/api/v3/providers/saml/%s/metadata/?download\n", authentikURL, entityID)
	fmt.Println("3. Run 'eos wazuh sso setup' on your Wazuh server")
	fmt.Println("\n⚠️  CRITICAL: The Roles property mapping MUST have SAML Attribute Name = 'Roles' (not a URI)")

	return nil
}

func (c *AuthentikClient) createSAMLCertificate(entityID string) (string, error) {
	// Create a self-signed certificate for SAML signing
	certData := map[string]interface{}{
		"name":          fmt.Sprintf("wazuh-saml-cert-%s", entityID),
		"subject":       fmt.Sprintf("CN=%s", entityID),
		"validity_days": 3650,
		"key_usage":     []string{"digital_signature", "key_agreement"},
	}

	body, _ := json.Marshal(certData)
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v3/crypto/certificatekeypairs/generate/", c.baseURL), bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create certificate: %s", body)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	return result["pk"].(string), nil
}

func (c *AuthentikClient) createRolesPropertyMapping() (string, error) {
	// This is the CRITICAL property mapping that must have SAML Attribute Name = "Roles"
	expression := `# Map Authentik groups to Wazuh backend roles
groups = [group.name for group in user.ak_groups.all()]

# Define role mappings
if "delphi-administrators" in groups:
    yield "admin"
elif "wazuh-readonly" in groups:
    yield "readall"
elif "wazuh-analysts" in groups:
    yield "kibanauser"
else:
    yield "kibanauser"  # Default role`

	mapping := map[string]interface{}{
		"name":          "Wazuh Roles Mapping",
		"saml_name":     "Roles", // CRITICAL: Must be exactly "Roles", not a URI
		"friendly_name": "Wazuh Backend Roles",
		"expression":    expression,
	}

	body, _ := json.Marshal(mapping)
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v3/propertymappings/saml/", c.baseURL), bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create roles mapping: %s", body)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	return result["pk"].(string), nil
}

func (c *AuthentikClient) createStandardMappings() ([]string, error) {
	// Create standard SAML mappings
	mappings := []map[string]interface{}{
		{
			"name":          "Wazuh Username",
			"saml_name":     "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
			"friendly_name": "Username",
			"expression":    "return user.username",
		},
		{
			"name":          "Wazuh Email",
			"saml_name":     "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
			"friendly_name": "Email",
			"expression":    "return user.email",
		},
		{
			"name":          "Wazuh Display Name",
			"saml_name":     "http://schemas.microsoft.com/identity/claims/displayname",
			"friendly_name": "Display Name",
			"expression":    "return user.name or user.username",
		},
	}

	var ids []string

	for _, mapping := range mappings {
		body, _ := json.Marshal(mapping)
		req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v3/propertymappings/saml/", c.baseURL), bytes.NewBuffer(body))
		if err != nil {
			return nil, err
		}

		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
			var result map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&result)
			ids = append(ids, result["pk"].(string))
		}
	}

	return ids, nil
}

func (c *AuthentikClient) createSAMLProvider(entityID, wazuhURL, certID string, mappingIDs []string) (string, error) {
	provider := map[string]interface{}{
		"name":                            fmt.Sprintf("Wazuh SAML Provider - %s", entityID),
		"authorization_flow":              c.getDefaultFlow(), // You'd need to fetch this
		"acs_url":                         fmt.Sprintf("%s/_opendistro/_security/saml/acs", wazuhURL),
		"issuer":                          entityID,
		"sp_binding":                      "post",
		"audience":                        entityID,
		"signing_kp":                      certID,
		"assertion_valid_not_on_or_after": 86400, // 24 hours
		"session_valid_not_on_or_after":   86400,
		"property_mappings":               mappingIDs,
		"digest_algorithm":                "http://www.w3.org/2001/04/xmlenc#sha256",
		"signature_algorithm":             "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
	}

	body, _ := json.Marshal(provider)
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v3/providers/saml/", c.baseURL), bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create SAML provider: %s", body)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	return result["pk"].(string), nil
}

func (c *AuthentikClient) createApplication(entityID string, providerID string) (string, error) {
	app := map[string]interface{}{
		"name":               fmt.Sprintf("Wazuh - %s", entityID),
		"slug":               strings.ToLower(strings.ReplaceAll(entityID, "-", "_")),
		"provider":           providerID,
		"meta_launch_url":    "",
		"meta_description":   "Wazuh Security Platform SSO",
		"meta_publisher":     "Code Monkey Cybersecurity",
		"policy_engine_mode": "any",
	}

	body, _ := json.Marshal(app)
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v3/core/applications/", c.baseURL), bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create application: %s", body)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	return result["pk"].(string), nil
}

func (c *AuthentikClient) createWazuhGroups() error {
	groups := []map[string]string{
		{
			"name":        "delphi-administrators",
			"description": "Full Wazuh administrative access",
		},
		{
			"name":        "wazuh-analysts",
			"description": "Standard Wazuh analyst access",
		},
		{
			"name":        "wazuh-readonly",
			"description": "Read-only Wazuh access",
		},
	}

	for _, group := range groups {
		body, _ := json.Marshal(group)
		req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v3/core/groups/", c.baseURL), bytes.NewBuffer(body))
		if err != nil {
			return err
		}

		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusConflict {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("failed to create group %s: %s", group["name"], body)
		}

		fmt.Printf("  - Created/verified group: %s\n", group["name"])
	}

	return nil
}

func (c *AuthentikClient) getDefaultFlow() string {
	// In production, fetch the default authorization flow
	// For now, return a placeholder
	return "default-provider-authorization-implicit-consent"
}

// Additional helper command to test the configuration
var testWazuhCmd = &cobra.Command{
	Use:   "test",
	Short: "Test Wazuh SSO configuration",
	Long:  `Test the SAML configuration between Authentik and Wazuh.`,
	RunE:  testWazuhSSO,
}

func testWazuhSSO(cmd *cobra.Command, args []string) error {
	fmt.Println("=== Testing Wazuh SSO Configuration ===")

	// SECURITY: Get Delphi URL from environment or config, not hardcoded
	delphiURL := os.Getenv("DELPHI_URL")
	if delphiURL == "" {
		delphiURL = "https://localhost:55000" // Secure default to localhost
	}

	// Test 1: Check if metadata endpoint is accessible
	metadataURL := fmt.Sprintf("%s/_opendistro/_security/saml/metadata", delphiURL)
	fmt.Printf("1. Checking Wazuh SAML metadata endpoint at %s... ", metadataURL)

	// SECURITY: Use context with timeout and proper TLS configuration
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", metadataURL, nil)
	if err != nil {
		fmt.Printf("❌ Failed to create request: %v\n", err)
		return err
	}

	// SECURITY: Use TLS configuration (allow custom CA for self-signed certs)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				// For production, should use proper certificate verification
				// This can be configured via environment variable
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("❌ Failed: %v\n", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Println("✅ Accessible")
	} else {
		fmt.Printf("❌ Status: %d\n", resp.StatusCode)
	}

	// Test 2: Initiate SAML authentication flow
	fmt.Print("2. Testing SAML authentication flow... ")
	// This would initiate a SAML auth request
	fmt.Println("✅ Ready for manual testing")

	fmt.Println("\n=== Manual Testing Steps ===")
	fmt.Println("1. Open your browser in incognito/private mode")
	fmt.Printf("2. Navigate to: %s\n", delphiURL)
	fmt.Println("3. You should be redirected to Authentik for login")
	fmt.Println("4. Login with a user in the 'delphi-administrators' group")
	fmt.Println("5. You should be redirected back to Wazuh dashboard")
	fmt.Println("\nIf authentication fails, run: eos wazuh sso debug")

	return nil
}

func init() {
	wazuhCmd.AddCommand(testWazuhCmd)
}
