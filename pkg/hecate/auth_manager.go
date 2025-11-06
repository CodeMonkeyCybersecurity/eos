package hecate

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/consul/api"
	// "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TODO: refactor
// AuthManager handles authentication policy operations
type AuthManager struct {
	client *HecateClient
}

// TODO: refactor
// NewAuthManager creates a new auth manager
func NewAuthManager(client *HecateClient) *AuthManager {
	return &AuthManager{client: client}
}

// TODO: refactor
// AuthentikPolicy represents an Authentik authentication policy
type AuthentikPolicy struct {
	Name       string            `json:"name"`
	Provider   string            `json:"provider"`
	Groups     []string          `json:"groups"`
	RequireMFA bool              `json:"require_mfa"`
	Metadata   map[string]string `json:"metadata"`
	Flow       string            `json:"flow"`
	Enabled    bool              `json:"enabled"`
	Slug       string            `json:"slug"`
	Expression string            `json:"expression"`
	Attributes map[string]string `json:"attributes"`
}

// TODO: refactor
// AuthPolicyCreateRequest represents a request to create an auth policy
type AuthPolicyCreateRequest struct {
	Name       string            `json:"name"`
	Provider   string            `json:"provider"`
	Flow       string            `json:"flow"`
	Groups     []string          `json:"groups"`
	RequireMFA bool              `json:"require_mfa"`
	Metadata   map[string]string `json:"metadata"`
}

// TODO: refactor
// UpdateAuthPolicyRequest represents a request to update an auth policy
type UpdateAuthPolicyRequest struct {
	Groups     []string          `json:"groups,omitempty"`
	RequireMFA *bool             `json:"require_mfa,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// TODO: refactor
// AuthPolicyInfo represents extended auth policy information
type AuthPolicyInfo struct {
	Name       string            `json:"name"`
	Provider   string            `json:"provider"`
	Flow       string            `json:"flow"`
	Groups     []string          `json:"groups"`
	RequireMFA bool              `json:"require_mfa"`
	Metadata   map[string]string `json:"metadata"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

// TODO: refactor
// CreateAuthPolicy creates a new authentication policy
func (am *AuthManager) CreateAuthPolicy(ctx context.Context, req *AuthPolicyCreateRequest) (*AuthPolicyInfo, error) {
	logger := otelzap.Ctx(am.client.rc.Ctx)
	logger.Info("Creating authentication policy",
		zap.String("name", req.Name),
		zap.String("provider", req.Provider))

	policy := &AuthPolicyInfo{
		Name:       req.Name,
		Provider:   req.Provider,
		Flow:       req.Flow,
		Groups:     req.Groups,
		RequireMFA: req.RequireMFA,
		Metadata:   req.Metadata,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	// Create in Authentik
	authentikPolicy := am.buildAuthentikPolicy(policy)
	if err := am.client.authentik.CreatePolicy(ctx, authentikPolicy); err != nil {
		return nil, fmt.Errorf("failed to create policy in Authentik: %w", err)
	}

	// Store in Consul
	if err := am.storePolicy(ctx, policy); err != nil {
		// Rollback Authentik
		logger.Warn("Failed to store policy in Consul, rolling back Authentik",
			zap.String("name", policy.Name),
			zap.Error(err))
		_ = am.client.authentik.DeletePolicy(ctx, policy.Name)
		return nil, fmt.Errorf("failed to store policy: %w", err)
	}

	// Apply  state
	if err := am.applyState(ctx, policy); err != nil {
		logger.Warn("Failed to apply  state for auth policy",
			zap.String("name", policy.Name),
			zap.Error(err))
	}

	logger.Info("Authentication policy created successfully",
		zap.String("name", policy.Name))

	return policy, nil
}

// TODO: refactor
// UpdateAuthPolicy updates an existing policy
func (am *AuthManager) UpdateAuthPolicy(ctx context.Context, name string, updates *UpdateAuthPolicyRequest) (*AuthPolicyInfo, error) {
	logger := otelzap.Ctx(am.client.rc.Ctx)
	logger.Info("Updating authentication policy",
		zap.String("name", name))

	policy, err := am.GetAuthPolicy(ctx, name)
	if err != nil {
		return nil, err
	}

	// Apply updates
	if updates.Groups != nil {
		policy.Groups = updates.Groups
	}
	if updates.RequireMFA != nil {
		policy.RequireMFA = *updates.RequireMFA
	}
	if updates.Metadata != nil {
		policy.Metadata = updates.Metadata
	}

	policy.UpdatedAt = time.Now()

	// Update in Authentik
	authentikPolicy := am.buildAuthentikPolicy(policy)
	if err := am.client.authentik.UpdatePolicy(ctx, authentikPolicy); err != nil {
		return nil, fmt.Errorf("failed to update policy in Authentik: %w", err)
	}

	// Update in Consul
	if err := am.storePolicy(ctx, policy); err != nil {
		logger.Warn("Failed to update policy in Consul",
			zap.String("name", name),
			zap.Error(err))
	}

	logger.Info("Authentication policy updated successfully",
		zap.String("name", policy.Name))

	return policy, nil
}

// TODO: refactor
// DeleteAuthPolicy deletes an authentication policy
func (am *AuthManager) DeleteAuthPolicy(ctx context.Context, name string) error {
	logger := otelzap.Ctx(am.client.rc.Ctx)
	logger.Info("Deleting authentication policy",
		zap.String("name", name))

	// Check if policy is in use
	routes, err := NewRouteManager(am.client).ListRoutes(ctx, &RouteFilter{AuthPolicy: name})
	if err == nil && len(routes) > 0 {
		return fmt.Errorf("policy is in use by %d routes", len(routes))
	}

	// Delete from Authentik
	if err := am.client.authentik.DeletePolicy(ctx, name); err != nil {
		return fmt.Errorf("failed to delete policy from Authentik: %w", err)
	}

	// Delete from Consul
	if err := am.deletePolicyFromConsul(ctx, name); err != nil {
		logger.Warn("Failed to delete policy from Consul",
			zap.String("name", name),
			zap.Error(err))
	}

	logger.Info("Authentication policy deleted successfully",
		zap.String("name", name))

	return nil
}

// TODO: refactor
// GetAuthPolicy retrieves a policy by name
func (am *AuthManager) GetAuthPolicy(ctx context.Context, name string) (*AuthPolicyInfo, error) {
	logger := otelzap.Ctx(am.client.rc.Ctx)
	logger.Debug("Getting authentication policy",
		zap.String("name", name))

	data, _, err := am.client.consul.KV().Get(fmt.Sprintf("hecate/auth-policies/%s", name), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}

	if data == nil {
		return nil, fmt.Errorf("policy not found")
	}

	var policy AuthPolicyInfo
	if err := json.Unmarshal(data.Value, &policy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy: %w", err)
	}

	return &policy, nil
}

// TODO: refactor
// ListAuthPolicies lists all authentication policies
func (am *AuthManager) ListAuthPolicies(ctx context.Context) ([]*AuthPolicyInfo, error) {
	logger := otelzap.Ctx(am.client.rc.Ctx)
	logger.Debug("Listing authentication policies")

	keys, _, err := am.client.consul.KV().Keys("hecate/auth-policies/", "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
	}

	policies := make([]*AuthPolicyInfo, 0, len(keys))
	for _, key := range keys {
		name := strings.TrimPrefix(key, "hecate/auth-policies/")
		if name == "" {
			continue
		}

		policy, err := am.GetAuthPolicy(ctx, name)
		if err != nil {
			logger.Warn("Failed to get policy",
				zap.String("name", name),
				zap.Error(err))
			continue
		}

		policies = append(policies, policy)
	}

	logger.Debug("Listed authentication policies",
		zap.Int("count", len(policies)))

	return policies, nil
}

// TODO: refactor
// CreateOIDCProvider creates an OIDC provider configuration
func (am *AuthManager) CreateOIDCProvider(ctx context.Context, req *CreateOIDCProviderRequest) error {
	logger := otelzap.Ctx(am.client.rc.Ctx)
	logger.Info("Creating OIDC provider",
		zap.String("name", req.Name),
		zap.String("issuer", req.Issuer))

	// Store OIDC configuration in Vault
	oidcPath := fmt.Sprintf("secret/hecate/oidc-providers/%s", req.Name)
	_, err := am.client.vault.Logical().Write(oidcPath, map[string]interface{}{
		"issuer":        req.Issuer,
		"client_id":     req.ClientID,
		"client_secret": req.ClientSecret,
		"scopes":        strings.Join(req.Scopes, ","),
	})

	if err != nil {
		return fmt.Errorf("failed to store OIDC provider config: %w", err)
	}

	// Configure in Authentik
	// TODO: Implement Authentik OIDC provider creation

	return nil
}

// Helper methods
// TODO: refactor
func (am *AuthManager) buildAuthentikPolicy(policy *AuthPolicyInfo) *AuthentikPolicy {
	// Build expression based on groups and MFA requirements
	expressions := []string{}

	if len(policy.Groups) > 0 {
		groupList := strings.Join(policy.Groups, "', '")
		expressions = append(expressions, fmt.Sprintf("request.user.groups.filter(name__in=['%s']).exists()", groupList))
	}

	if policy.RequireMFA {
		expressions = append(expressions, "request.user.mfa_devices.exists()")
	}

	expression := "return True"
	if len(expressions) > 0 {
		expression = fmt.Sprintf("return %s", strings.Join(expressions, " and "))
	}

	return &AuthentikPolicy{
		Name:       policy.Name,
		Slug:       strings.ToLower(strings.ReplaceAll(policy.Name, " ", "-")),
		Enabled:    true,
		Expression: expression,
		Attributes: policy.Metadata,
	}
}

// TODO: refactor
func (am *AuthManager) storePolicy(_ context.Context, policy *AuthPolicyInfo) error {
	data, err := json.Marshal(policy)
	if err != nil {
		return err
	}

	_, err = am.client.consul.KV().Put(&api.KVPair{
		Key:   fmt.Sprintf("hecate/auth-policies/%s", policy.Name),
		Value: data,
	}, nil)

	return err
}

// TODO: refactor
func (am *AuthManager) deletePolicyFromConsul(_ context.Context, name string) error {
	_, err := am.client.consul.KV().Delete(fmt.Sprintf("hecate/auth-policies/%s", name), nil)
	return err
}

// TODO: refactor
func (am *AuthManager) applyState(ctx context.Context, policy *AuthPolicyInfo) error {
	logger := otelzap.Ctx(ctx)
	logger.Info("Applying auth policy via HashiCorp Vault",
		zap.String("policy_name", policy.Name),
		zap.String("provider", policy.Provider))

	// Store policy in Consul KV for service discovery
	if err := am.storePolicy(ctx, policy); err != nil {
		return fmt.Errorf("failed to store policy in Consul: %w", err)
	}

	// Create Vault policy for the authentication provider
	vaultPolicyName := fmt.Sprintf("hecate-auth-%s", policy.Name)
	vaultPolicy := am.generateVaultPolicy(policy)

	// Apply the policy via Vault API (using Consul service discovery to find Vault)
	if err := am.applyVaultPolicy(ctx, vaultPolicyName, vaultPolicy); err != nil {
		logger.Warn("Failed to apply Vault policy, policy stored in Consul for manual application",
			zap.String("vault_policy", vaultPolicyName),
			zap.Error(err))
		// Don't fail completely - policy is stored in Consul for manual application
	}

	logger.Info("Auth policy applied successfully",
		zap.String("policy_name", policy.Name),
		zap.String("vault_policy", vaultPolicyName))

	return nil
}

// TODO: refactor
// generateVaultPolicy creates a Vault policy based on the auth policy
func (am *AuthManager) generateVaultPolicy(policy *AuthPolicyInfo) string {
	// Generate Vault policy HCL based on the authentication policy
	policyHCL := fmt.Sprintf(`# Hecate Auth Policy: %s
# Provider: %s
# Generated by Eos HashiCorp integration

# Allow access to Hecate secrets for this auth provider
path "secret/data/hecate/%s/*" {
  capabilities = ["read", "list"]
}

# Allow access to authentication configuration
path "auth/%s/*" {
  capabilities = ["read", "list"]
}

# Allow reading own token information
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# Allow renewing own token
path "auth/token/renew-self" {
  capabilities = ["update"]
}
`, policy.Name, policy.Provider, policy.Name, policy.Provider)

	return policyHCL
}

// TODO: refactor
// applyVaultPolicy applies the policy to HashiCorp Vault
func (am *AuthManager) applyVaultPolicy(ctx context.Context, policyName, policyHCL string) error {
	logger := otelzap.Ctx(ctx)

	// Use Consul service discovery to find Vault
	vaultServices, _, err := am.client.consul.Health().Service("vault", "", true, nil)
	if err != nil {
		return fmt.Errorf("failed to discover Vault service via Consul: %w", err)
	}

	if len(vaultServices) == 0 {
		return fmt.Errorf("no healthy Vault services found via Consul service discovery")
	}

	// Use the first healthy Vault service
	vaultAddr := fmt.Sprintf("http://%s:%d",
		vaultServices[0].Service.Address,
		vaultServices[0].Service.Port)

	logger.Info("Discovered Vault service via Consul",
		zap.String("vault_addr", vaultAddr),
		zap.String("policy_name", policyName))

	// Store policy configuration in Consul for administrator review
	policyConfig := map[string]interface{}{
		"name":       policyName,
		"policy_hcl": policyHCL,
		"vault_addr": vaultAddr,
		"created_at": time.Now().UTC(),
		"status":     "pending_admin_review",
	}

	configData, err := json.Marshal(policyConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal policy config: %w", err)
	}

	_, err = am.client.consul.KV().Put(&api.KVPair{
		Key:   fmt.Sprintf("hecate/vault-policies/%s", policyName),
		Value: configData,
	}, nil)

	if err != nil {
		return fmt.Errorf("failed to store Vault policy config in Consul: %w", err)
	}

	logger.Info("Vault policy configuration stored in Consul for administrator review",
		zap.String("consul_key", fmt.Sprintf("hecate/vault-policies/%s", policyName)))

	return nil
}

// TODO: refactor
// CreateOIDCProviderRequest represents a request to create an OIDC provider
type CreateOIDCProviderRequest struct {
	Name         string   `json:"name"`
	Issuer       string   `json:"issuer"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scopes       []string `json:"scopes"`
}

// TODO: refactor
// CreateSAMLProviderRequest represents a request to create a SAML provider
type CreateSAMLProviderRequest struct {
	Name        string `json:"name"`
	EntityID    string `json:"entity_id"`
	SSOUrl      string `json:"sso_url"`
	Certificate string `json:"certificate"`
}

// TODO: refactor
// CreateLDAPProviderRequest represents a request to create an LDAP provider
type CreateLDAPProviderRequest struct {
	Name         string `json:"name"`
	ServerURL    string `json:"server_url"`
	BindDN       string `json:"bind_dn"`
	BindPassword string `json:"bind_password"`
	BaseDN       string `json:"base_dn"`
	UserFilter   string `json:"user_filter"`
	GroupFilter  string `json:"group_filter"`
}
