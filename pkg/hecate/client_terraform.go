package hecate

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/consul/api"
	nomad "github.com/hashicorp/nomad/api"
	vault "github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// HecateClient is the main Hecate client that coordinates all components
type HecateClient struct {
	caddy     *CaddyAPIClient
	authentik *ExtendedAuthentikClient
	consul    *api.Client
	vault     *vault.Client
	nginx     *NginxClient
	nomad     *nomad.Client
	terraform *TerraformClient
	rc        *eos_io.RuntimeContext
}

// ClientConfig holds the configuration for Terraform-based Hecate client
type ClientConfig struct {
	CaddyAdminAddr     string
	AuthentikURL       string
	AuthentikToken     string
	ConsulAddr         string
	VaultAddr          string
	VaultToken         string
	NginxConfigPath    string
	NomadAddr          string
	TerraformWorkspace string
}

// NewHecateClient creates a new Hecate client
func NewHecateClient(rc *eos_io.RuntimeContext, config *ClientConfig) (*HecateClient, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating new Hecate client",
		zap.String("consul_addr", config.ConsulAddr),
		zap.String("vault_addr", config.VaultAddr))

	// Initialize Consul client
	consulConfig := api.DefaultConfig()
	if config.ConsulAddr != "" {
		consulConfig.Address = config.ConsulAddr
	}
	consulClient, err := api.NewClient(consulConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create consul client: %w", err)
	}

	// Initialize Vault client
	vaultConfig := vault.DefaultConfig()
	if config.VaultAddr != "" {
		vaultConfig.Address = config.VaultAddr
	}
	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}
	if config.VaultToken != "" {
		vaultClient.SetToken(config.VaultToken)
	}

	// Initialize extended Authentik client
	extendedAuth, err := NewExtendedAuthentikClient(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to create authentik client: %w", err)
	}

	return &HecateClient{
		caddy:     NewCaddyAPIClient(config.CaddyAdminAddr),
		authentik: extendedAuth,
		consul:    consulClient,
		vault:     vaultClient,
		nginx:     NewNginxClient(config.NginxConfigPath),
		nomad:     createNomadClient(config.NomadAddr),
		terraform: NewTerraformClient(rc, config.TerraformWorkspace),
		rc:        rc,
	}, nil
}

// createNomadClient creates a Nomad client for HashiCorp integration
func createNomadClient(nomadAddr string) *nomad.Client {
	config := nomad.DefaultConfig()
	if nomadAddr != "" {
		config.Address = nomadAddr
	}

	client, err := nomad.NewClient(config)
	if err != nil {
		// Return nil client if creation fails - operations will handle gracefully
		return nil
	}

	return client
}

// CaddyAPIClient handles Caddy API operations
type CaddyAPIClient struct {
	baseURL string
	client  *resty.Client
}

// NewCaddyAPIClient creates a new Caddy API client
func NewCaddyAPIClient(baseURL string) *CaddyAPIClient {
	if baseURL == "" {
		baseURL = "http://localhost:2019"
	}
	return &CaddyAPIClient{
		baseURL: baseURL,
		client:  resty.New().SetTimeout(30 * time.Second),
	}
}

// AddRoute adds a route to Caddy
func (c *CaddyAPIClient) AddRoute(ctx context.Context, route *CaddyRoute) error {
	resp, err := c.client.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetBody(route).
		Post(c.baseURL + "/config/apps/http/servers/srv0/routes")

	if err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}

	if resp.StatusCode() >= 400 {
		return fmt.Errorf("caddy API error: %s", resp.String())
	}

	return nil
}

// UpdateRoute updates an existing route in Caddy
func (c *CaddyAPIClient) UpdateRoute(ctx context.Context, route *CaddyRoute) error {
	// Caddy uses PUT to update specific routes by ID
	resp, err := c.client.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetBody(route).
		Put(c.baseURL + "/config/apps/http/servers/srv0/routes/" + route.ID)

	if err != nil {
		return fmt.Errorf("failed to update route: %w", err)
	}

	if resp.StatusCode() >= 400 {
		return fmt.Errorf("caddy API error: %s", resp.String())
	}

	return nil
}

// DeleteRoute removes a route from Caddy
func (c *CaddyAPIClient) DeleteRoute(ctx context.Context, domain string) error {
	resp, err := c.client.R().
		SetContext(ctx).
		Delete(c.baseURL + "/config/apps/http/servers/srv0/routes/" + domain)

	if err != nil {
		return fmt.Errorf("failed to delete route: %w", err)
	}

	if resp.StatusCode() >= 400 && resp.StatusCode() != 404 {
		return fmt.Errorf("caddy API error: %s", resp.String())
	}

	return nil
}

// GetRoutes retrieves all routes from Caddy
func (c *CaddyAPIClient) GetRoutes(ctx context.Context) ([]*CaddyRoute, error) {
	resp, err := c.client.R().
		SetContext(ctx).
		SetResult([]*CaddyRoute{}).
		Get(c.baseURL + "/config/apps/http/servers/srv0/routes")

	if err != nil {
		return nil, fmt.Errorf("failed to get routes: %w", err)
	}

	if resp.StatusCode() >= 400 {
		return nil, fmt.Errorf("caddy API error: %s", resp.String())
	}

	routes, ok := resp.Result().(*[]*CaddyRoute)
	if !ok {
		return nil, fmt.Errorf("unexpected response type")
	}

	return *routes, nil
}

// ExtendedAuthentikClient extends the existing AuthentikClient with additional methods
type ExtendedAuthentikClient struct {
	*AuthentikClient
	resty *resty.Client
}

// NewExtendedAuthentikClient creates an extended Authentik client
func NewExtendedAuthentikClient(rc *eos_io.RuntimeContext) (*ExtendedAuthentikClient, error) {
	base, err := NewAuthentikClient(rc)
	if err != nil {
		return nil, err
	}

	return &ExtendedAuthentikClient{
		AuthentikClient: base,
		resty: resty.New().
			SetTimeout(30 * time.Second).
			SetAuthToken(base.APIToken),
	}, nil
}

// CreatePolicy creates a new authentication policy in Authentik
func (a *ExtendedAuthentikClient) CreatePolicy(ctx context.Context, policy *AuthentikPolicy) error {
	resp, err := a.resty.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetBody(policy).
		Post(a.BaseURL + "/api/v3/policies/all/")

	if err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}

	if resp.StatusCode() >= 400 {
		return fmt.Errorf("authentik API error: %s", resp.String())
	}

	return nil
}

// UpdatePolicy updates an existing policy in Authentik
func (a *ExtendedAuthentikClient) UpdatePolicy(ctx context.Context, policy *AuthentikPolicy) error {
	resp, err := a.resty.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetBody(policy).
		Put(a.BaseURL + "/api/v3/policies/all/" + policy.Slug + "/")

	if err != nil {
		return fmt.Errorf("failed to update policy: %w", err)
	}

	if resp.StatusCode() >= 400 {
		return fmt.Errorf("authentik API error: %s", resp.String())
	}

	return nil
}

// DeletePolicy deletes a policy from Authentik
func (a *ExtendedAuthentikClient) DeletePolicy(ctx context.Context, name string) error {
	resp, err := a.resty.R().
		SetContext(ctx).
		Delete(a.BaseURL + "/api/v3/policies/all/" + name + "/")

	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	if resp.StatusCode() >= 400 && resp.StatusCode() != 404 {
		return fmt.Errorf("authentik API error: %s", resp.String())
	}

	return nil
}

// GetPolicies retrieves all policies from Authentik
func (a *ExtendedAuthentikClient) GetPolicies(ctx context.Context) ([]*AuthentikPolicy, error) {
	resp, err := a.resty.R().
		SetContext(ctx).
		SetResult(&AuthentikPolicyResponse{}).
		Get(a.BaseURL + "/api/v3/policies/all/")

	if err != nil {
		return nil, fmt.Errorf("failed to get policies: %w", err)
	}

	if resp.StatusCode() >= 400 {
		return nil, fmt.Errorf("authentik API error: %s", resp.String())
	}

	result, ok := resp.Result().(*AuthentikPolicyResponse)
	if !ok {
		return nil, fmt.Errorf("unexpected response type")
	}

	return result.Results, nil
}

// NginxClient handles Nginx configuration operations
type NginxClient struct {
	configPath string
}

// NewNginxClient creates a new Nginx client
func NewNginxClient(configPath string) *NginxClient {
	if configPath == "" {
		configPath = "/etc/nginx"
	}
	return &NginxClient{
		configPath: configPath,
	}
}

// TerraformClient handles Terraform operations
type TerraformClient struct {
	rc        *eos_io.RuntimeContext
	workspace string
}

// NewTerraformClient creates a new Terraform client
func NewTerraformClient(rc *eos_io.RuntimeContext, workspace string) *TerraformClient {
	if workspace == "" {
		workspace = "/var/lib/hecate/terraform"
	}
	return &TerraformClient{
		rc:        rc,
		workspace: workspace,
	}
}

// Apply applies a Terraform configuration
func (t *TerraformClient) Apply(ctx context.Context, module string, config string) error {
	logger := otelzap.Ctx(t.rc.Ctx)
	logger.Info("Applying Terraform configuration",
		zap.String("module", module))

	// Ensure workspace exists
	if err := os.MkdirAll(t.workspace, shared.ServiceDirPerm); err != nil {
		return fmt.Errorf("failed to create terraform workspace: %w", err)
	}

	// Write the configuration
	configPath := filepath.Join(t.workspace, fmt.Sprintf("%s.tf", module))
	if err := os.WriteFile(configPath, []byte(config), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write terraform config: %w", err)
	}

	// Run terraform init
	_, err := execute.Run(t.rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    []string{"init"},
		Dir:     t.workspace,
		Capture: false,
	})
	if err != nil {
		return fmt.Errorf("terraform init failed: %w", err)
	}

	// Run terraform apply
	_, err = execute.Run(t.rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    []string{"apply", "-auto-approve"},
		Dir:     t.workspace,
		Capture: false,
	})
	if err != nil {
		return fmt.Errorf("terraform apply failed: %w", err)
	}

	return nil
}

// Destroy destroys Terraform resources
func (t *TerraformClient) Destroy(ctx context.Context, module string) error {
	logger := otelzap.Ctx(t.rc.Ctx)
	logger.Info("Destroying Terraform resources",
		zap.String("module", module))

	// Run terraform destroy
	_, err := execute.Run(t.rc.Ctx, execute.Options{
		Command: "terraform",
		Args:    []string{"destroy", "-auto-approve"},
		Dir:     t.workspace,
		Capture: false,
	})
	if err != nil {
		return fmt.Errorf("terraform destroy failed: %w", err)
	}

	return nil
}

// CaddyRoute represents a Caddy route configuration
type CaddyRoute struct {
	ID     string         `json:"@id,omitempty"`
	Match  []CaddyMatcher `json:"match"`
	Handle []CaddyHandler `json:"handle"`
}

// CaddyMatcher represents a Caddy matcher
type CaddyMatcher struct {
	Host []string `json:"host,omitempty"`
	Path []string `json:"path,omitempty"`
}

// CaddyHandler represents a Caddy handler
type CaddyHandler interface{}

// CaddyReverseProxy represents a reverse proxy handler
type CaddyReverseProxy struct {
	Handler   string          `json:"handler"`
	Upstreams []CaddyUpstream `json:"upstreams"`
	Headers   *CaddyHeaders   `json:"headers,omitempty"`
}

// CaddyUpstream represents an upstream configuration
type CaddyUpstream struct {
	Dial string `json:"dial"`
}

// CaddyHeaders represents header manipulation
type CaddyHeaders struct {
	Request  *CaddyHeaderOps `json:"request,omitempty"`
	Response *CaddyHeaderOps `json:"response,omitempty"`
}

// CaddyHeaderOps represents header operations
type CaddyHeaderOps struct {
	Set    map[string]string   `json:"set,omitempty"`
	Add    map[string][]string `json:"add,omitempty"`
	Delete []string            `json:"delete,omitempty"`
}

// CaddyForwardAuth represents forward authentication handler
type CaddyForwardAuth struct {
	Handler string              `json:"handler"`
	URI     string              `json:"uri"`
	Headers map[string][]string `json:"headers,omitempty"`
}

// AuthentikPolicyResponse represents the API response for policies
type AuthentikPolicyResponse struct {
	Count    int                `json:"count"`
	Next     string             `json:"next"`
	Previous string             `json:"previous"`
	Results  []*AuthentikPolicy `json:"results"`
}
