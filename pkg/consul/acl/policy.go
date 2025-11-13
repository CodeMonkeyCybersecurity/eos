// pkg/consul/acl/policy.go
//
// ACL policy management for Consul
// Provides programmatic creation, update, deletion, and querying of ACL policies
//
// Last Updated: 2025-10-23

package acl

import (
	"context"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PolicyManager provides ACL policy management operations
type PolicyManager interface {
	// Policy CRUD
	CreatePolicy(ctx context.Context, policy *Policy) (*Policy, error)
	ReadPolicy(ctx context.Context, policyID string) (*Policy, error)
	ReadPolicyByName(ctx context.Context, name string) (*Policy, error)
	UpdatePolicy(ctx context.Context, policyID string, policy *Policy) (*Policy, error)
	DeletePolicy(ctx context.Context, policyID string) error
	ListPolicies(ctx context.Context) ([]*Policy, error)

	// Template rendering
	RenderPolicyTemplate(ctx context.Context, template PolicyTemplate, vars map[string]string) (*Policy, error)

	// Policy validation
	ValidatePolicy(ctx context.Context, policy *Policy) error
}

// Policy represents a Consul ACL policy
type Policy struct {
	ID          string            `json:"ID,omitempty"`
	Name        string            `json:"Name"`
	Description string            `json:"Description,omitempty"`
	Rules       string            `json:"Rules"`
	Datacenters []string          `json:"Datacenters,omitempty"`
	Meta        map[string]string `json:"Meta,omitempty"`

	// Read-only fields returned by Consul
	CreateIndex uint64 `json:"CreateIndex,omitempty"`
	ModifyIndex uint64 `json:"ModifyIndex,omitempty"`
	Hash        []byte `json:"Hash,omitempty"`
}

// PolicyTemplate provides common policy templates
type PolicyTemplate string

const (
	// Service policies
	PolicyTemplateServiceRead  PolicyTemplate = "service-read"
	PolicyTemplateServiceWrite PolicyTemplate = "service-write"

	// KV store policies
	PolicyTemplateKVRead  PolicyTemplate = "kv-read"
	PolicyTemplateKVWrite PolicyTemplate = "kv-write"

	// Node policies
	PolicyTemplateNodeRead  PolicyTemplate = "node-read"
	PolicyTemplateNodeWrite PolicyTemplate = "node-write"

	// Operator policies
	PolicyTemplateOperator PolicyTemplate = "operator"

	// Custom application policies
	PolicyTemplateVaultAccess     PolicyTemplate = "vault-access"
	PolicyTemplateMonitoringAgent PolicyTemplate = "monitoring-agent"
)

// ConsulPolicyManager implements PolicyManager using Consul API
type ConsulPolicyManager struct {
	client *api.Client
	acl    *api.ACL
	logger otelzap.LoggerWithCtx
}

// NewPolicyManager creates a new ACL policy manager
func NewPolicyManager(ctx context.Context, consulAddress, aclToken string) (PolicyManager, error) {
	logger := otelzap.Ctx(ctx)

	// ASSESS - Validate parameters
	if consulAddress == "" {
		consulAddress = fmt.Sprintf("%s:8500", shared.GetInternalHostname())
	}

	logger.Info("Creating Consul ACL policy manager",
		zap.String("consul_address", consulAddress),
		zap.Bool("token_provided", aclToken != ""))

	// INTERVENE - Create Consul client with ACL token
	config := api.DefaultConfig()
	config.Address = consulAddress
	if aclToken != "" {
		config.Token = aclToken
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	// EVALUATE - Verify ACL access (list policies to test)
	acl := client.ACL()
	if _, _, err := acl.PolicyList(nil); err != nil {
		logger.Warn("Failed to verify ACL access - ACLs may be disabled or token invalid",
			zap.Error(err))
		// Don't fail - allow operation in non-ACL mode
	}

	manager := &ConsulPolicyManager{
		client: client,
		acl:    acl,
		logger: logger,
	}

	logger.Info("Consul ACL policy manager created successfully")

	return manager, nil
}

// CreatePolicy creates a new ACL policy
func (pm *ConsulPolicyManager) CreatePolicy(ctx context.Context, policy *Policy) (*Policy, error) {
	pm.logger.Info("ASSESS: Creating ACL policy",
		zap.String("policy_name", policy.Name),
		zap.Int("rules_length", len(policy.Rules)))

	// Validate policy
	if err := pm.ValidatePolicy(ctx, policy); err != nil {
		return nil, fmt.Errorf("policy validation failed: %w", err)
	}

	// INTERVENE - Create policy via API
	consulPolicy := &api.ACLPolicy{
		Name:        policy.Name,
		Description: policy.Description,
		Rules:       policy.Rules,
		Datacenters: policy.Datacenters,
		// Note: Meta field not supported in current Consul API version
	}

	created, _, err := pm.acl.PolicyCreate(consulPolicy, nil)
	if err != nil {
		pm.logger.Error("INTERVENE FAILED: Policy creation failed",
			zap.String("policy_name", policy.Name),
			zap.Error(err))
		return nil, fmt.Errorf("failed to create policy %s: %w", policy.Name, err)
	}

	// EVALUATE - Verify policy was created
	retrieved, _, err := pm.acl.PolicyRead(created.ID, nil)
	if err != nil {
		pm.logger.Warn("EVALUATE: Failed to verify policy creation",
			zap.String("policy_id", created.ID),
			zap.Error(err))
		// Don't fail - creation succeeded
	} else if retrieved == nil {
		pm.logger.Error("EVALUATE FAILED: Policy not found after creation",
			zap.String("policy_id", created.ID))
		return nil, fmt.Errorf("policy %s not found after creation", created.ID)
	}

	pm.logger.Info("EVALUATE SUCCESS: Policy created successfully",
		zap.String("policy_id", created.ID),
		zap.String("policy_name", created.Name))

	return convertFromConsulPolicy(created), nil
}

// ReadPolicy retrieves a policy by ID
func (pm *ConsulPolicyManager) ReadPolicy(ctx context.Context, policyID string) (*Policy, error) {
	pm.logger.Debug("Reading ACL policy",
		zap.String("policy_id", policyID))

	policy, _, err := pm.acl.PolicyRead(policyID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy %s: %w", policyID, err)
	}

	if policy == nil {
		return nil, fmt.Errorf("policy %s not found", policyID)
	}

	return convertFromConsulPolicy(policy), nil
}

// ReadPolicyByName retrieves a policy by name
func (pm *ConsulPolicyManager) ReadPolicyByName(ctx context.Context, name string) (*Policy, error) {
	pm.logger.Debug("Reading ACL policy by name",
		zap.String("policy_name", name))

	policy, _, err := pm.acl.PolicyReadByName(name, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy %s: %w", name, err)
	}

	if policy == nil {
		return nil, fmt.Errorf("policy %s not found", name)
	}

	return convertFromConsulPolicy(policy), nil
}

// UpdatePolicy updates an existing ACL policy
func (pm *ConsulPolicyManager) UpdatePolicy(ctx context.Context, policyID string, policy *Policy) (*Policy, error) {
	pm.logger.Info("ASSESS: Updating ACL policy",
		zap.String("policy_id", policyID),
		zap.String("policy_name", policy.Name))

	// Validate policy
	if err := pm.ValidatePolicy(ctx, policy); err != nil {
		return nil, fmt.Errorf("policy validation failed: %w", err)
	}

	// ASSESS - Ensure policy exists
	existing, _, err := pm.acl.PolicyRead(policyID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to read existing policy %s: %w", policyID, err)
	}
	if existing == nil {
		return nil, fmt.Errorf("policy %s not found", policyID)
	}

	// INTERVENE - Update policy
	consulPolicy := &api.ACLPolicy{
		ID:          policyID,
		Name:        policy.Name,
		Description: policy.Description,
		Rules:       policy.Rules,
		Datacenters: policy.Datacenters,
		// Note: Meta field not supported in current Consul API version
	}

	updated, _, err := pm.acl.PolicyUpdate(consulPolicy, nil)
	if err != nil {
		pm.logger.Error("INTERVENE FAILED: Policy update failed",
			zap.String("policy_id", policyID),
			zap.Error(err))
		return nil, fmt.Errorf("failed to update policy %s: %w", policyID, err)
	}

	// EVALUATE - Verify update
	retrieved, _, err := pm.acl.PolicyRead(policyID, nil)
	if err != nil {
		pm.logger.Warn("EVALUATE: Failed to verify policy update",
			zap.String("policy_id", policyID),
			zap.Error(err))
	} else if retrieved.ModifyIndex <= existing.ModifyIndex {
		pm.logger.Warn("EVALUATE: Policy ModifyIndex did not increase",
			zap.String("policy_id", policyID),
			zap.Uint64("old_index", existing.ModifyIndex),
			zap.Uint64("new_index", retrieved.ModifyIndex))
	}

	pm.logger.Info("EVALUATE SUCCESS: Policy updated successfully",
		zap.String("policy_id", policyID),
		zap.String("policy_name", updated.Name))

	return convertFromConsulPolicy(updated), nil
}

// DeletePolicy deletes an ACL policy
func (pm *ConsulPolicyManager) DeletePolicy(ctx context.Context, policyID string) error {
	pm.logger.Info("ASSESS: Deleting ACL policy",
		zap.String("policy_id", policyID))

	// ASSESS - Check if policy exists
	existing, _, err := pm.acl.PolicyRead(policyID, nil)
	if err != nil {
		pm.logger.Warn("ASSESS: Failed to check policy existence",
			zap.String("policy_id", policyID),
			zap.Error(err))
		// Continue anyway
	} else if existing == nil {
		pm.logger.Info("ASSESS: Policy not found, nothing to delete",
			zap.String("policy_id", policyID))
		return nil // Idempotent
	}

	// INTERVENE - Delete policy
	_, err = pm.acl.PolicyDelete(policyID, nil)
	if err != nil {
		pm.logger.Error("INTERVENE FAILED: Policy deletion failed",
			zap.String("policy_id", policyID),
			zap.Error(err))
		return fmt.Errorf("failed to delete policy %s: %w", policyID, err)
	}

	// EVALUATE - Verify deletion
	retrieved, _, err := pm.acl.PolicyRead(policyID, nil)
	if err == nil && retrieved != nil {
		pm.logger.Error("EVALUATE FAILED: Policy still exists after deletion",
			zap.String("policy_id", policyID))
		return fmt.Errorf("policy %s still exists after deletion", policyID)
	}

	pm.logger.Info("EVALUATE SUCCESS: Policy deleted successfully",
		zap.String("policy_id", policyID))

	return nil
}

// ListPolicies lists all ACL policies
func (pm *ConsulPolicyManager) ListPolicies(ctx context.Context) ([]*Policy, error) {
	pm.logger.Debug("Listing ACL policies")

	policies, _, err := pm.acl.PolicyList(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
	}

	result := make([]*Policy, len(policies))
	for i, p := range policies {
		// For list, we get summary data - need full read for Rules
		fullPolicy, _, err := pm.acl.PolicyRead(p.ID, nil)
		if err != nil {
			pm.logger.Warn("Failed to read policy details",
				zap.String("policy_id", p.ID),
				zap.Error(err))
			// Use summary data
			result[i] = &Policy{
				ID:          p.ID,
				Name:        p.Name,
				Description: p.Description,
				CreateIndex: p.CreateIndex,
				ModifyIndex: p.ModifyIndex,
			}
		} else {
			result[i] = convertFromConsulPolicy(fullPolicy)
		}
	}

	pm.logger.Debug("Policies listed successfully",
		zap.Int("count", len(result)))

	return result, nil
}

// ValidatePolicy validates a policy structure
func (pm *ConsulPolicyManager) ValidatePolicy(ctx context.Context, policy *Policy) error {
	if policy.Name == "" {
		return fmt.Errorf("policy name is required")
	}

	if policy.Rules == "" {
		return fmt.Errorf("policy rules are required")
	}

	// Basic HCL syntax validation (check for common errors)
	if !isValidHCL(policy.Rules) {
		return fmt.Errorf("policy rules contain invalid HCL syntax")
	}

	return nil
}

// Helper functions

func convertFromConsulPolicy(p *api.ACLPolicy) *Policy {
	return &Policy{
		ID:          p.ID,
		Name:        p.Name,
		Description: p.Description,
		Rules:       p.Rules,
		Datacenters: p.Datacenters,
		Meta:        nil, // Meta not supported in current API version
		CreateIndex: p.CreateIndex,
		ModifyIndex: p.ModifyIndex,
		Hash:        p.Hash,
	}
}

func isValidHCL(rules string) bool {
	// Basic validation - check for balanced braces
	braceCount := 0
	for _, ch := range rules {
		switch ch {
		case '{':
			braceCount++
		case '}':
			braceCount--
			if braceCount < 0 {
				return false
			}
		}
	}
	return braceCount == 0
}
