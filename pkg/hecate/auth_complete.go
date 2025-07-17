// pkg/hecate/auth_complete.go

package hecate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AuthentikClient represents a client for interacting with Authentik API
type AuthentikClient struct {
	BaseURL  string
	APIToken string
	Client   *http.Client
}

// NewAuthentikClient creates a new Authentik API client
func NewAuthentikClient(rc *eos_io.RuntimeContext) (*AuthentikClient, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Get API token from Vault
	tokenOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "vault",
		Args:    []string{"kv", "get", "-field=value", "secret/hecate/authentik/api_token"},
		Capture: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get API token from Vault: %w", err)
	}
	
	token := strings.TrimSpace(tokenOutput)
	if token == "" {
		return nil, fmt.Errorf("empty API token retrieved from Vault")
	}
	
	// Determine Authentik URL
	baseURL := "http://localhost:9000"
	
	// Check if we're using a custom URL from config
	urlOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "vault",
		Args:    []string{"kv", "get", "-field=authentik_url", "secret/hecate/config/authentik_url"},
		Capture: true,
	})
	if err == nil && urlOutput != "" {
		baseURL = strings.TrimSpace(urlOutput)
	}
	
	logger.Debug("Created Authentik client",
		zap.String("base_url", baseURL))
	
	return &AuthentikClient{
		BaseURL:  baseURL,
		APIToken: token,
		Client:   &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// CreateFlow creates a new authentication flow in Authentik
func (c *AuthentikClient) CreateFlow(rc *eos_io.RuntimeContext, flow *AuthFlow) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating authentication flow",
		zap.String("name", flow.Name),
		zap.String("slug", flow.Slug))
	
	// Build flow configuration
	flowConfig := map[string]interface{}{
		"name":           flow.Name,
		"slug":           flow.Slug,
		"title":          flow.Title,
		"designation":    flow.Designation,
		"authentication": flow.Authentication,
		"layout":         flow.Layout,
	}
	
	// Create the flow
	body, err := json.Marshal(flowConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal flow config: %w", err)
	}
	
	req, err := http.NewRequestWithContext(rc.Ctx, "POST",
		fmt.Sprintf("%s/api/v3/flows/instances/", c.BaseURL),
		bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Authorization", "Bearer "+c.APIToken)
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := c.Client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create flow: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 400 {
		var errResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errResp)
		return fmt.Errorf("API error %d: %v", resp.StatusCode, errResp)
	}
	
	var flowResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&flowResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	
	flow.ID = flowResp["pk"].(string)
	
	logger.Info("Flow created successfully",
		zap.String("flow_id", flow.ID))
	
	return nil
}

// CreateProvider creates a new authentication provider in Authentik
func (c *AuthentikClient) CreateProvider(rc *eos_io.RuntimeContext, provider *AuthentikProvider) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating authentication provider",
		zap.String("name", provider.Name),
		zap.String("type", provider.Type))
	
	var endpoint string
	var providerConfig map[string]interface{}
	
	switch provider.Type {
	case "proxy":
		endpoint = "/api/v3/providers/proxy/"
		providerConfig = map[string]interface{}{
			"name":                provider.Name,
			"authorization_flow":  provider.AuthorizationFlow,
			"mode":               provider.Mode,
			"external_host":      provider.ExternalHost,
			"internal_host":      provider.InternalHost,
			"internal_host_ssl_validation": provider.InternalHostSSLValidation,
		}
		
	case "oauth2":
		endpoint = "/api/v3/providers/oauth2/"
		providerConfig = map[string]interface{}{
			"name":                provider.Name,
			"authorization_flow":  provider.AuthorizationFlow,
			"client_type":         provider.ClientType,
			"client_id":           provider.ClientID,
			"client_secret":       provider.ClientSecret,
			"redirect_uris":       provider.RedirectURIs,
			"sub_mode":           provider.SubMode,
		}
		
	case "saml":
		endpoint = "/api/v3/providers/saml/"
		providerConfig = map[string]interface{}{
			"name":                provider.Name,
			"authorization_flow":  provider.AuthorizationFlow,
			"acs_url":            provider.ACSURL,
			"audience":           provider.Audience,
			"issuer":             provider.Issuer,
			"assertion_valid_not_before": provider.AssertionValidNotBefore,
			"assertion_valid_not_on_or_after": provider.AssertionValidNotOnOrAfter,
			"session_valid_not_on_or_after": provider.SessionValidNotOnOrAfter,
		}
		
	case "ldap":
		endpoint = "/api/v3/providers/ldap/"
		providerConfig = map[string]interface{}{
			"name":                provider.Name,
			"authorization_flow":  provider.AuthorizationFlow,
			"base_dn":            provider.BaseDN,
			"search_group":       provider.SearchGroup,
		}
		
	default:
		return fmt.Errorf("unsupported provider type: %s", provider.Type)
	}
	
	// Create the provider
	body, err := json.Marshal(providerConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal provider config: %w", err)
	}
	
	req, err := http.NewRequestWithContext(rc.Ctx, "POST",
		c.BaseURL+endpoint,
		bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Authorization", "Bearer "+c.APIToken)
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := c.Client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create provider: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 400 {
		var errResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errResp)
		return fmt.Errorf("API error %d: %v", resp.StatusCode, errResp)
	}
	
	var providerResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&providerResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	
	provider.ID = fmt.Sprintf("%v", providerResp["pk"])
	
	logger.Info("Provider created successfully",
		zap.String("provider_id", provider.ID))
	
	return nil
}

// CreateApplication creates a new application in Authentik
func (c *AuthentikClient) CreateApplication(rc *eos_io.RuntimeContext, app *AuthApplication) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating application",
		zap.String("name", app.Name),
		zap.String("slug", app.Slug))
	
	appConfig := map[string]interface{}{
		"name":             app.Name,
		"slug":             app.Slug,
		"provider":         app.ProviderID,
		"meta_launch_url":  app.LaunchURL,
		"meta_description": app.Description,
		"meta_publisher":   app.Publisher,
		"open_in_new_tab":  app.OpenInNewTab,
	}
	
	if app.Icon != "" {
		appConfig["meta_icon"] = app.Icon
	}
	
	// Create the application
	body, err := json.Marshal(appConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal app config: %w", err)
	}
	
	req, err := http.NewRequestWithContext(rc.Ctx, "POST",
		fmt.Sprintf("%s/api/v3/core/applications/", c.BaseURL),
		bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Authorization", "Bearer "+c.APIToken)
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := c.Client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create application: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 400 {
		var errResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errResp)
		return fmt.Errorf("API error %d: %v", resp.StatusCode, errResp)
	}
	
	var appResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&appResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	
	app.ID = appResp["pk"].(string)
	
	logger.Info("Application created successfully",
		zap.String("app_id", app.ID))
	
	return nil
}

// CreateOutpost creates a new outpost in Authentik
func (c *AuthentikClient) CreateOutpost(rc *eos_io.RuntimeContext, outpost *AuthOutpost) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating outpost",
		zap.String("name", outpost.Name),
		zap.String("type", outpost.Type))
	
	outpostConfig := map[string]interface{}{
		"name":      outpost.Name,
		"type":      outpost.Type,
		"providers": outpost.ProviderIDs,
		"config":    outpost.Config,
	}
	
	// Create the outpost
	body, err := json.Marshal(outpostConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal outpost config: %w", err)
	}
	
	req, err := http.NewRequestWithContext(rc.Ctx, "POST",
		fmt.Sprintf("%s/api/v3/outposts/instances/", c.BaseURL),
		bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Authorization", "Bearer "+c.APIToken)
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := c.Client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create outpost: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 400 {
		var errResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errResp)
		return fmt.Errorf("API error %d: %v", resp.StatusCode, errResp)
	}
	
	var outpostResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&outpostResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	
	outpost.ID = outpostResp["pk"].(string)
	
	logger.Info("Outpost created successfully",
		zap.String("outpost_id", outpost.ID))
	
	return nil
}

// ListPolicies lists all policies in Authentik
func (c *AuthentikClient) ListPolicies(rc *eos_io.RuntimeContext) ([]map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(rc.Ctx, "GET",
		fmt.Sprintf("%s/api/v3/policies/all/", c.BaseURL),
		nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Authorization", "Bearer "+c.APIToken)
	
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 400 {
		var errResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errResp)
		return nil, fmt.Errorf("API error %d: %v", resp.StatusCode, errResp)
	}
	
	var result struct {
		Results []map[string]interface{} `json:"results"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	return result.Results, nil
}

// GetPolicyByName retrieves a policy by its name
func (c *AuthentikClient) GetPolicyByName(rc *eos_io.RuntimeContext, name string) (map[string]interface{}, error) {
	policies, err := c.ListPolicies(rc)
	if err != nil {
		return nil, err
	}
	
	for _, policy := range policies {
		if policy["name"] == name {
			return policy, nil
		}
	}
	
	return nil, fmt.Errorf("policy not found: %s", name)
}

// Helper function implementations for the existing auth.go

func authPolicyExistsImpl(rc *eos_io.RuntimeContext, policyName string) (bool, error) {
	client, err := NewAuthentikClient(rc)
	if err != nil {
		return false, err
	}
	
	_, err = client.GetPolicyByName(rc, policyName)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return false, nil
		}
		return false, err
	}
	
	return true, nil
}

func getAuthPolicyIDImpl(rc *eos_io.RuntimeContext, policyName string) (string, error) {
	client, err := NewAuthentikClient(rc)
	if err != nil {
		return "", err
	}
	
	policy, err := client.GetPolicyByName(rc, policyName)
	if err != nil {
		return "", err
	}
	
	id, ok := policy["pk"].(string)
	if !ok {
		return "", fmt.Errorf("invalid policy ID format")
	}
	
	return id, nil
}

// AuthFlow represents an authentication flow in Authentik
type AuthFlow struct {
	ID             string
	Name           string
	Slug           string
	Title          string
	Designation    string
	Authentication string
	Layout         string
}

// AuthentikProvider represents an authentication provider in Authentik
type AuthentikProvider struct {
	ID                        string
	Name                      string
	Type                      string
	AuthorizationFlow         string
	Mode                      string
	ExternalHost              string
	InternalHost              string
	InternalHostSSLValidation bool
	
	// OAuth2 specific
	ClientType   string
	ClientID     string
	ClientSecret string
	RedirectURIs string
	SubMode      string
	
	// SAML specific
	ACSURL                     string
	Audience                   string
	Issuer                     string
	AssertionValidNotBefore    string
	AssertionValidNotOnOrAfter string
	SessionValidNotOnOrAfter   string
	
	// LDAP specific
	BaseDN      string
	SearchGroup string
}

// AuthApplication represents an application in Authentik
type AuthApplication struct {
	ID           string
	Name         string
	Slug         string
	ProviderID   int
	LaunchURL    string
	Description  string
	Publisher    string
	Icon         string
	OpenInNewTab bool
}

// AuthOutpost represents an outpost in Authentik
type AuthOutpost struct {
	ID          string
	Name        string
	Type        string
	ProviderIDs []int
	Config      map[string]interface{}
}