// pkg/consul/acl/token_manager.go
//
// ACL token management with policy attachment
//
// Last Updated: 2025-10-23

package acl

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TokenManager provides ACL token management operations
type TokenManager interface {
	// Token CRUD
	CreateToken(ctx context.Context, token *Token) (*Token, error)
	ReadToken(ctx context.Context, accessorID string) (*Token, error)
	UpdateToken(ctx context.Context, accessorID string, token *Token) (*Token, error)
	DeleteToken(ctx context.Context, accessorID string) error
	ListTokens(ctx context.Context) ([]*Token, error)

	// Token cloning
	CloneToken(ctx context.Context, accessorID string, description string) (*Token, error)

	// Token-policy management
	AttachPolicy(ctx context.Context, accessorID, policyID string) error
	DetachPolicy(ctx context.Context, accessorID, policyID string) error
	ListTokenPolicies(ctx context.Context, accessorID string) ([]*Policy, error)
}

// Token represents a Consul ACL token
type Token struct {
	AccessorID  string    `json:"AccessorID,omitempty"`
	SecretID    string    `json:"SecretID,omitempty"`
	Description string    `json:"Description,omitempty"`
	Policies    []string  `json:"Policies,omitempty"`   // Policy IDs
	PolicyNames []string  `json:"PolicyNames,omitempty"` // Policy names
	Local       bool      `json:"Local,omitempty"`
	ExpirationTTL time.Duration `json:"ExpirationTTL,omitempty"`
	ExpirationTime *time.Time  `json:"ExpirationTime,omitempty"`

	// Read-only fields
	CreateIndex uint64    `json:"CreateIndex,omitempty"`
	ModifyIndex uint64    `json:"ModifyIndex,omitempty"`
	CreateTime  time.Time `json:"CreateTime,omitempty"`
	Hash        []byte    `json:"Hash,omitempty"`
}

// ConsulTokenManager implements TokenManager
type ConsulTokenManager struct {
	client *api.Client
	acl    *api.ACL
	logger otelzap.LoggerWithCtx
}

// NewTokenManager creates a new ACL token manager
func NewTokenManager(ctx context.Context, consulAddress, aclToken string) (TokenManager, error) {
	logger := otelzap.Ctx(ctx)

	if consulAddress == "" {
		consulAddress = "127.0.0.1:8500"
	}

	logger.Info("Creating Consul ACL token manager",
		zap.String("consul_address", consulAddress))

	config := api.DefaultConfig()
	config.Address = consulAddress
	if aclToken != "" {
		config.Token = aclToken
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	acl := client.ACL()
	if _, _, err := acl.TokenList(nil); err != nil {
		logger.Warn("Failed to verify ACL access - ACLs may be disabled",
			zap.Error(err))
	}

	return &ConsulTokenManager{
		client: client,
		acl:    acl,
		logger: logger,
	}, nil
}

// CreateToken creates a new ACL token
func (tm *ConsulTokenManager) CreateToken(ctx context.Context, token *Token) (*Token, error) {
	tm.logger.Info("ASSESS: Creating ACL token",
		zap.String("description", token.Description),
		zap.Int("policy_count", len(token.Policies)))

	// Build policy link structures
	var policies []*api.ACLTokenPolicyLink
	for _, policyID := range token.Policies {
		policies = append(policies, &api.ACLTokenPolicyLink{
			ID: policyID,
		})
	}

	for _, policyName := range token.PolicyNames {
		policies = append(policies, &api.ACLTokenPolicyLink{
			Name: policyName,
		})
	}

	// INTERVENE - Create token
	consulToken := &api.ACLToken{
		Description: token.Description,
		Policies:    policies,
		Local:       token.Local,
	}

	if token.ExpirationTTL > 0 {
		consulToken.ExpirationTTL = token.ExpirationTTL
	}
	if token.ExpirationTime != nil {
		consulToken.ExpirationTime = token.ExpirationTime
	}

	created, _, err := tm.acl.TokenCreate(consulToken, nil)
	if err != nil {
		tm.logger.Error("INTERVENE FAILED: Token creation failed",
			zap.Error(err))
		return nil, fmt.Errorf("failed to create token: %w", err)
	}

	// EVALUATE - Verify token
	retrieved, _, err := tm.acl.TokenRead(created.AccessorID, nil)
	if err != nil {
		tm.logger.Warn("EVALUATE: Failed to verify token creation",
			zap.String("accessor_id", created.AccessorID),
			zap.Error(err))
	} else if retrieved == nil {
		tm.logger.Error("EVALUATE FAILED: Token not found after creation",
			zap.String("accessor_id", created.AccessorID))
		return nil, fmt.Errorf("token not found after creation")
	}

	tm.logger.Info("EVALUATE SUCCESS: Token created successfully",
		zap.String("accessor_id", created.AccessorID))

	return convertFromConsulToken(created), nil
}

// ReadToken retrieves a token by accessor ID
func (tm *ConsulTokenManager) ReadToken(ctx context.Context, accessorID string) (*Token, error) {
	token, _, err := tm.acl.TokenRead(accessorID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to read token %s: %w", accessorID, err)
	}

	if token == nil {
		return nil, fmt.Errorf("token %s not found", accessorID)
	}

	return convertFromConsulToken(token), nil
}

// UpdateToken updates an existing ACL token
func (tm *ConsulTokenManager) UpdateToken(ctx context.Context, accessorID string, token *Token) (*Token, error) {
	tm.logger.Info("ASSESS: Updating ACL token",
		zap.String("accessor_id", accessorID))

	// ASSESS - Verify token exists
	existing, _, err := tm.acl.TokenRead(accessorID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to read existing token: %w", err)
	}
	if existing == nil {
		return nil, fmt.Errorf("token %s not found", accessorID)
	}

	// Build policy links
	var policies []*api.ACLTokenPolicyLink
	for _, policyID := range token.Policies {
		policies = append(policies, &api.ACLTokenPolicyLink{ID: policyID})
	}
	for _, policyName := range token.PolicyNames {
		policies = append(policies, &api.ACLTokenPolicyLink{Name: policyName})
	}

	// INTERVENE - Update token
	consulToken := &api.ACLToken{
		AccessorID:  accessorID,
		Description: token.Description,
		Policies:    policies,
		Local:       token.Local,
	}

	updated, _, err := tm.acl.TokenUpdate(consulToken, nil)
	if err != nil {
		tm.logger.Error("INTERVENE FAILED: Token update failed",
			zap.String("accessor_id", accessorID),
			zap.Error(err))
		return nil, fmt.Errorf("failed to update token: %w", err)
	}

	tm.logger.Info("EVALUATE SUCCESS: Token updated successfully",
		zap.String("accessor_id", accessorID))

	return convertFromConsulToken(updated), nil
}

// DeleteToken deletes an ACL token
func (tm *ConsulTokenManager) DeleteToken(ctx context.Context, accessorID string) error {
	tm.logger.Info("ASSESS: Deleting ACL token",
		zap.String("accessor_id", accessorID))

	// ASSESS - Check if token exists
	existing, _, err := tm.acl.TokenRead(accessorID, nil)
	if err != nil || existing == nil {
		tm.logger.Info("Token not found, nothing to delete",
			zap.String("accessor_id", accessorID))
		return nil // Idempotent
	}

	// INTERVENE - Delete token
	_, err = tm.acl.TokenDelete(accessorID, nil)
	if err != nil {
		tm.logger.Error("INTERVENE FAILED: Token deletion failed",
			zap.String("accessor_id", accessorID),
			zap.Error(err))
		return fmt.Errorf("failed to delete token: %w", err)
	}

	// EVALUATE - Verify deletion
	retrieved, _, _ := tm.acl.TokenRead(accessorID, nil)
	if retrieved != nil {
		tm.logger.Error("EVALUATE FAILED: Token still exists after deletion",
			zap.String("accessor_id", accessorID))
		return fmt.Errorf("token still exists after deletion")
	}

	tm.logger.Info("EVALUATE SUCCESS: Token deleted successfully",
		zap.String("accessor_id", accessorID))

	return nil
}

// ListTokens lists all ACL tokens
func (tm *ConsulTokenManager) ListTokens(ctx context.Context) ([]*Token, error) {
	tokens, _, err := tm.acl.TokenList(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list tokens: %w", err)
	}

	result := make([]*Token, 0, len(tokens))
	for _, t := range tokens {
		// TokenList returns ACLTokenListEntry, need to read full token
		fullToken, _, err := tm.acl.TokenRead(t.AccessorID, nil)
		if err != nil {
			tm.logger.Warn("Failed to read token details",
				zap.String("accessor_id", t.AccessorID),
				zap.Error(err))
			continue
		}
		result = append(result, convertFromConsulToken(fullToken))
	}

	return result, nil
}

// CloneToken creates a copy of an existing token
func (tm *ConsulTokenManager) CloneToken(ctx context.Context, accessorID string, description string) (*Token, error) {
	tm.logger.Info("Cloning ACL token",
		zap.String("source_accessor_id", accessorID),
		zap.String("new_description", description))

	// Read the source token
	source, err := tm.ReadToken(ctx, accessorID)
	if err != nil {
		return nil, fmt.Errorf("failed to read source token: %w", err)
	}

	// Create a new token with same policies
	newToken := &Token{
		Description: description,
		Policies:    source.Policies,
		PolicyNames: source.PolicyNames,
		Local:       source.Local,
	}

	return tm.CreateToken(ctx, newToken)
}

// AttachPolicy attaches a policy to a token
func (tm *ConsulTokenManager) AttachPolicy(ctx context.Context, accessorID, policyID string) error {
	// Read current token
	token, err := tm.ReadToken(ctx, accessorID)
	if err != nil {
		return err
	}

	// Check if policy already attached
	for _, id := range token.Policies {
		if id == policyID {
			tm.logger.Info("Policy already attached to token",
				zap.String("accessor_id", accessorID),
				zap.String("policy_id", policyID))
			return nil // Idempotent
		}
	}

	// Add policy
	token.Policies = append(token.Policies, policyID)

	// Update token
	_, err = tm.UpdateToken(ctx, accessorID, token)
	if err != nil {
		return fmt.Errorf("failed to attach policy: %w", err)
	}

	tm.logger.Info("Policy attached to token",
		zap.String("accessor_id", accessorID),
		zap.String("policy_id", policyID))

	return nil
}

// DetachPolicy removes a policy from a token
func (tm *ConsulTokenManager) DetachPolicy(ctx context.Context, accessorID, policyID string) error {
	// Read current token
	token, err := tm.ReadToken(ctx, accessorID)
	if err != nil {
		return err
	}

	// Remove policy
	newPolicies := make([]string, 0)
	found := false
	for _, id := range token.Policies {
		if id != policyID {
			newPolicies = append(newPolicies, id)
		} else {
			found = true
		}
	}

	if !found {
		tm.logger.Info("Policy not attached to token",
			zap.String("accessor_id", accessorID),
			zap.String("policy_id", policyID))
		return nil // Idempotent
	}

	token.Policies = newPolicies

	// Update token
	_, err = tm.UpdateToken(ctx, accessorID, token)
	if err != nil {
		return fmt.Errorf("failed to detach policy: %w", err)
	}

	tm.logger.Info("Policy detached from token",
		zap.String("accessor_id", accessorID),
		zap.String("policy_id", policyID))

	return nil
}

// ListTokenPolicies lists all policies attached to a token
func (tm *ConsulTokenManager) ListTokenPolicies(ctx context.Context, accessorID string) ([]*Policy, error) {
	token, err := tm.ReadToken(ctx, accessorID)
	if err != nil {
		return nil, err
	}

	// Read full policy details for each policy ID
	policies := make([]*Policy, 0, len(token.Policies))
	for _, policyID := range token.Policies {
		policy, _, err := tm.acl.PolicyRead(policyID, nil)
		if err != nil {
			tm.logger.Warn("Failed to read policy",
				zap.String("policy_id", policyID),
				zap.Error(err))
			continue
		}
		policies = append(policies, convertFromConsulPolicy(policy))
	}

	return policies, nil
}

// Helper functions

func convertFromConsulToken(t *api.ACLToken) *Token {
	if t == nil {
		return nil
	}

	policies := make([]string, len(t.Policies))
	policyNames := make([]string, len(t.Policies))
	for i, p := range t.Policies {
		policies[i] = p.ID
		policyNames[i] = p.Name
	}

	return &Token{
		AccessorID:     t.AccessorID,
		SecretID:       t.SecretID,
		Description:    t.Description,
		Policies:       policies,
		PolicyNames:    policyNames,
		Local:          t.Local,
		ExpirationTTL:  t.ExpirationTTL,
		ExpirationTime: t.ExpirationTime,
		CreateIndex:    t.CreateIndex,
		ModifyIndex:    t.ModifyIndex,
		CreateTime:     t.CreateTime,
		Hash:           t.Hash,
	}
}
