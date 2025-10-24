// pkg/consul/acl/tokens.go
//
// Consul ACL Token Management
//
// This module provides helpers for creating and managing Consul ACL tokens.
// Used to create the management token that Vault will use to generate dynamic tokens.

package acl

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	consulapi "github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TokenInfo contains information about a Consul ACL token
type TokenInfo struct {
	Token       string   // The actual token (SecretID)
	Accessor    string   // Token accessor ID (for revocation)
	Description string   // Human-readable description
	Policies    []string // Attached policy names
	Local       bool     // Whether token is local to this datacenter
}

// CreateManagementToken creates a long-lived management token for Vault
//
// This token will be used by Vault's Consul secrets engine to create
// dynamic short-lived tokens for applications.
//
// Parameters:
//   - rc: Runtime context
//   - consulClient: Consul client (must have ACL write permissions)
//   - description: Description for the token (e.g., "Vault Consul secrets engine")
//   - policyNames: Policies to attach (e.g., ["vault-mgmt-policy"])
//
// Returns:
//   - TokenInfo with token and metadata
//   - Error if creation fails
//
// Example:
//
//	tokenInfo, err := acl.CreateManagementToken(rc, consulClient,
//	    "Vault Consul secrets engine management token",
//	    []string{"vault-mgmt-policy"})
//	if err != nil {
//	    return err
//	}
//	// Store tokenInfo.Token in Vault: vault write consul/config/access token=...
func CreateManagementToken(
	rc *eos_io.RuntimeContext,
	consulClient *consulapi.Client,
	description string,
	policyNames []string,
) (*TokenInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Creating Consul management token",
		zap.String("description", description),
		zap.Strings("policies", policyNames))

	// ASSESS - Verify all policies exist
	for _, policyName := range policyNames {
		exists, err := PolicyExists(rc, consulClient, policyName)
		if err != nil {
			return nil, fmt.Errorf("failed to check if policy exists: %w", err)
		}
		if !exists {
			return nil, fmt.Errorf("policy %s does not exist - create it first with acl.CreatePolicy()", policyName)
		}
	}

	// INTERVENE - Create the token
	token := &consulapi.ACLToken{
		Description: description,
		Policies: func() []*consulapi.ACLTokenPolicyLink {
			var links []*consulapi.ACLTokenPolicyLink
			for _, name := range policyNames {
				links = append(links, &consulapi.ACLTokenPolicyLink{Name: name})
			}
			return links
		}(),
		Local: false, // Global token (works in all datacenters)
	}

	createdToken, _, err := consulClient.ACL().TokenCreate(token, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul token: %w\n"+
			"Remediation:\n"+
			"  - Check Consul token has ACL write permissions\n"+
			"  - Verify all policies exist: %v\n"+
			"  - Check Consul logs: journalctl -u consul -n 50",
			err, policyNames)
	}

	tokenInfo := &TokenInfo{
		Token:       createdToken.SecretID,
		Accessor:    createdToken.AccessorID,
		Description: createdToken.Description,
		Policies:    policyNames,
		Local:       createdToken.Local,
	}

	logger.Info("Consul management token created",
		zap.String("accessor", tokenInfo.Accessor),
		zap.Strings("policies", tokenInfo.Policies))

	return tokenInfo, nil
}

// RevokeToken revokes a Consul ACL token
//
// Parameters:
//   - rc: Runtime context
//   - consulClient: Consul client (must have ACL write permissions)
//   - accessor: Token accessor ID (NOT the token itself)
//
// Example:
//
//	err := acl.RevokeToken(rc, consulClient, tokenInfo.Accessor)
//	if err != nil {
//	    logger.Warn("Failed to revoke token", zap.Error(err))
//	}
func RevokeToken(rc *eos_io.RuntimeContext, consulClient *consulapi.Client, accessor string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Revoking Consul token",
		zap.String("accessor", accessor))

	_, err := consulClient.ACL().TokenDelete(accessor, nil)
	if err != nil {
		return fmt.Errorf("failed to revoke Consul token: %w", err)
	}

	logger.Info("Consul token revoked",
		zap.String("accessor", accessor))

	return nil
}

// ListTokens lists all ACL tokens in Consul
//
// Parameters:
//   - rc: Runtime context
//   - consulClient: Consul client (must have ACL read permissions)
//
// Returns:
//   - List of token metadata (tokens themselves are not returned for security)
//   - Error if listing fails
//
// Example:
//
//	tokens, err := acl.ListTokens(rc, consulClient)
//	if err != nil {
//	    return err
//	}
//	for _, token := range tokens {
//	    logger.Info("Token", zap.String("description", token.Description))
//	}
func ListTokens(rc *eos_io.RuntimeContext, consulClient *consulapi.Client) ([]*TokenInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Listing Consul ACL tokens")

	tokens, _, err := consulClient.ACL().TokenList(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list Consul tokens: %w", err)
	}

	var result []*TokenInfo
	for _, token := range tokens {
		policyNames := make([]string, 0, len(token.Policies))
		for _, policy := range token.Policies {
			policyNames = append(policyNames, policy.Name)
		}

		result = append(result, &TokenInfo{
			Token:       "", // Don't expose the actual token
			Accessor:    token.AccessorID,
			Description: token.Description,
			Policies:    policyNames,
			Local:       token.Local,
		})
	}

	logger.Info("Listed Consul ACL tokens",
		zap.Int("count", len(result)))

	return result, nil
}
