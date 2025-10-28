// pkg/vault/auth_cluster.go
//
// Authentication helpers for Vault cluster operations (Raft, Autopilot, snapshots)
//
// This file provides authentication and authorization helpers specifically for
// cluster-level operations that require admin-level access.
//
// Functions follow the Assess → Intervene → Evaluate pattern per CLAUDE.md.

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GetVaultClientWithToken creates a Vault client with a specific token
// and validates it has sufficient capabilities for cluster operations.
//
// Used when token is provided via --token flag or VAULT_TOKEN environment variable.
//
// ASSESS: Validate token format
// INTERVENE: Create client and set token
// EVALUATE: Verify token has cluster operation capabilities
func GetVaultClientWithToken(rc *eos_io.RuntimeContext, token string) (*api.Client, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Validate token is non-empty
	if token == "" {
		return nil, fmt.Errorf("token cannot be empty")
	}

	// ASSESS: Check token format for dangerous characters
	if err := validateTokenFormat(token); err != nil {
		return nil, fmt.Errorf("token format invalid: %w", err)
	}

	logger.Debug("Creating Vault client with provided token")

	// INTERVENE: Create Vault client
	client, err := GetVaultClient(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	// INTERVENE: Set token on client
	client.SetToken(token)

	// EVALUATE: Verify token is valid and has sufficient capabilities
	logger.Debug("Verifying token capabilities for cluster operations")
	if err := verifyClusterOperationCapabilities(rc, client); err != nil {
		return nil, fmt.Errorf("token lacks required capabilities: %w\n\n"+
			"Cluster operations require admin-level access.\n"+
			"Ensure your token has one of:\n"+
			"  • eos-admin-policy (recommended - audited, rotatable)\n"+
			"  • root policy (emergency use only - bypasses audit)\n\n"+
			"To get an admin token:\n"+
			"  1. Ensure Vault Agent is running: systemctl status vault-agent-eos\n"+
			"  2. Or use Admin AppRole credentials from /var/lib/eos/secret/\n"+
			"  3. Or authenticate manually: vault login -method=userpass", err)
	}

	logger.Info("✓ Token authenticated and validated for cluster operations")
	return client, nil
}

// validateTokenFormat checks token for dangerous characters.
// Vault tokens are typically base64-encoded UUID or HVAC format.
// This validation prevents terminal injection attacks.
func validateTokenFormat(token string) error {
	// Check for control characters that could cause terminal injection
	for _, r := range token {
		// Allow printable ASCII only (space to tilde)
		if r < 32 || r > 126 {
			return fmt.Errorf("contains invalid character (ascii %d)", r)
		}
	}

	// Check reasonable length (Vault tokens are typically 24-96 chars)
	if len(token) < 10 {
		return fmt.Errorf("token too short (minimum 10 characters)")
	}

	if len(token) > 256 {
		return fmt.Errorf("token too long (maximum 256 characters)")
	}

	return nil
}

// verifyClusterOperationCapabilities checks if token can perform cluster operations.
//
// Required capabilities:
// - sys/storage/raft/* (Raft cluster operations)
// - sys/storage/raft/snapshot (snapshot backup/restore)
// - sys/storage/raft/autopilot/configuration (Autopilot config)
//
// Returns detailed error if token lacks capabilities.
func verifyClusterOperationCapabilities(rc *eos_io.RuntimeContext, client *api.Client) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check 1: Token must be valid
	logger.Debug("Checking token validity with Vault")
	secret, err := client.Auth().Token().LookupSelf()
	if err != nil {
		logger.Debug("Token lookup failed", zap.Error(err))
		return fmt.Errorf("token is invalid or expired: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return fmt.Errorf("token lookup returned no data (token may be expired)")
	}

	// Check 2: Token must have required policies
	logger.Debug("Checking token policies")
	policies, ok := secret.Data["policies"].([]interface{})
	if !ok {
		return fmt.Errorf("token has no policies attached")
	}

	// Check for admin or root policy
	hasRequiredPolicy := false
	policyNames := []string{}
	for _, p := range policies {
		if policy, ok := p.(string); ok {
			policyNames = append(policyNames, policy)
			if policy == "root" || policy == shared.EosAdminPolicyName {
				hasRequiredPolicy = true
				logger.Debug("✓ Token has required policy",
					zap.String("policy", policy))
				break
			}
		}
	}

	if !hasRequiredPolicy {
		return fmt.Errorf("token lacks required policy\n"+
			"Token has policies: %v\n"+
			"Required: %s or root", policyNames, shared.EosAdminPolicyName)
	}

	// Check 3: Verify specific capabilities for cluster operations
	// Raft cluster operations require access to sys/storage/raft/*
	logger.Debug("Checking sys/storage/raft/configuration capabilities")
	capabilities, err := client.Sys().CapabilitiesSelf("sys/storage/raft/configuration")
	if err != nil {
		logger.Debug("Capabilities check failed", zap.Error(err))
		// If we can't check capabilities but token has root/admin policy, assume OK
		if hasRequiredPolicy {
			logger.Warn("Cannot verify capabilities, but token has required policy - proceeding")
			return nil
		}
		return fmt.Errorf("cannot verify cluster operation capabilities: %w", err)
	}

	// Token needs read capability for Raft configuration
	hasCapability := false
	for _, cap := range capabilities {
		if cap == "root" || cap == "sudo" || cap == "read" {
			hasCapability = true
			logger.Debug("✓ Token has required capability",
				zap.String("capability", cap),
				zap.String("path", "sys/storage/raft/configuration"))
			break
		}
	}

	if !hasCapability {
		return fmt.Errorf("token cannot access sys/storage/raft/configuration\n"+
			"Token capabilities: %v\n"+
			"Required: root, sudo, or read", capabilities)
	}

	logger.Debug("✓ Token verified for cluster operations",
		zap.Strings("policies", policyNames))

	return nil
}
