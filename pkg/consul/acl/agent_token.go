// pkg/consul/acl/agent_token.go
//
// Consul Agent Token Management
//
// Creates and configures agent tokens for the Consul daemon itself.
// This prevents "Coordinate update blocked by ACLs" errors when ACLs are enabled.
//
// Last Updated: 2025-01-25

package acl

import (
	"fmt"
	"os"
	"regexp"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	consulapi "github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AgentTokenResult holds the result of agent token creation
type AgentTokenResult struct {
	TokenID     string
	AccessorID  string
	Description string
	NodeName    string
	Configured  bool // Whether token was set via consul acl set-agent-token
}

// CreateAgentToken creates an ACL token for the Consul agent/daemon.
//
// This token allows the Consul daemon itself to perform necessary operations
// like coordinate updates, autopilot, and anti-entropy sync when ACLs are enabled.
//
// CRITICAL: Without an agent token, the daemon will log errors like:
//   - "Coordinate update blocked by ACLs"
//   - "Permission denied" for internal operations
//
// The token is created with node-identity permissions for the local node,
// which grants the minimum required permissions for daemon operations.
//
// Parameters:
//   - rc: Runtime context for logging
//   - bootstrapToken: The bootstrap/management token to use for creating the agent token
//   - nodeName: Name of the Consul node (hostname if empty)
//
// Returns:
//   - AgentTokenResult with token details
//   - Error if creation fails
//
// Example:
//
//	result, err := acl.CreateAgentToken(rc, bootstrapToken, "consul-server-1")
//	if err != nil {
//	    return fmt.Errorf("failed to create agent token: %w", err)
//	}
//	logger.Info("Agent token created", zap.String("accessor", result.AccessorID))
func CreateAgentToken(rc *eos_io.RuntimeContext, bootstrapToken string, nodeName string) (*AgentTokenResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Creating agent token for Consul daemon")

	// ASSESS - Get node name if not provided
	if nodeName == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("failed to get hostname: %w\n"+
				"Specify node name explicitly if hostname detection fails",
				err)
		}
		nodeName = hostname
		logger.Info("Using hostname as node name", zap.String("node_name", nodeName))
	}

	// ASSESS - Create Consul client with bootstrap token
	consulConfig := consulapi.DefaultConfig()
	consulConfig.Token = bootstrapToken
	consulClient, err := consulapi.NewClient(consulConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w\n"+
			"Remediation:\n"+
			"  - Check Consul is running: systemctl status consul\n"+
			"  - Verify token is valid: consul acl token read -self",
			err)
	}

	// ASSESS - Check if agent token already exists for this node
	logger.Info("Checking for existing agent token")
	existingTokens, _, err := consulClient.ACL().TokenList(nil)
	if err == nil {
		for _, token := range existingTokens {
			if token.Description == fmt.Sprintf("Agent token for %s", nodeName) {
				logger.Info("Agent token already exists for this node",
					zap.String("accessor", token.AccessorID),
					zap.String("node", nodeName))

				return &AgentTokenResult{
					TokenID:     token.SecretID,
					AccessorID:  token.AccessorID,
					Description: token.Description,
					NodeName:    nodeName,
					Configured:  false, // Don't know if it's configured yet
				}, nil
			}
		}
	}

	// INTERVENE - Create agent token
	logger.Info("Creating new agent token", zap.String("node", nodeName))

	// Create token with node-identity for this node
	// Node identity grants minimal permissions required for agent operations:
	//   - node:write (for coordinate updates, service registration)
	//   - service:read (for anti-entropy sync)
	//   - session:write (for session management)
	agentToken := &consulapi.ACLToken{
		Description: fmt.Sprintf("Agent token for %s", nodeName),
		NodeIdentities: []*consulapi.ACLNodeIdentity{
			{
				NodeName:   nodeName,
				Datacenter: "dc1", // TODO: Make datacenter configurable
			},
		},
	}

	createdToken, _, err := consulClient.ACL().TokenCreate(agentToken, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create agent token: %w\n"+
			"Remediation:\n"+
			"  - Verify bootstrap token has management permissions\n"+
			"  - Check ACL system is bootstrapped: consul acl bootstrap\n"+
			"  - Ensure node name matches Consul node: consul members",
			err)
	}

	logger.Info("Agent token created successfully",
		zap.String("accessor", createdToken.AccessorID),
		zap.String("node", nodeName))

	return &AgentTokenResult{
		TokenID:     createdToken.SecretID,
		AccessorID:  createdToken.AccessorID,
		Description: createdToken.Description,
		NodeName:    nodeName,
		Configured:  false,
	}, nil
}

// ConfigureAgentToken configures the Consul daemon to use the agent token.
//
// This sets the agent token in the running Consul daemon so it can perform
// internal operations without being blocked by ACLs.
//
// The token is set via `consul acl set-agent-token agent <token>` which:
//   - Configures the running daemon immediately (no restart required)
//   - Stores the token in the agent's memory
//   - Persists to disk if token_persistence is enabled in config
//
// IMPORTANT: This does NOT modify the config file. To make the token
// persistent across restarts, use PersistAgentTokenToConfig().
//
// Parameters:
//   - rc: Runtime context
//   - tokenID: The SecretID of the agent token
//
// Returns:
//   - Error if configuration fails
//
// Example:
//
//	if err := acl.ConfigureAgentToken(rc, agentTokenResult.TokenID); err != nil {
//	    return fmt.Errorf("failed to configure agent token: %w", err)
//	}
func ConfigureAgentToken(rc *eos_io.RuntimeContext, tokenID string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Configuring Consul daemon to use agent token")

	// INTERVENE - Set agent token via CLI (uses SDK under the hood)
	// This is the recommended way per Consul docs:
	// https://developer.hashicorp.com/consul/commands/acl/set-agent-token
	cmd := execute.Options{
		Command: "consul",
		Args:    []string{"acl", "set-agent-token", "agent", tokenID},
		Capture: true,
	}

	output, err := execute.Run(rc.Ctx, cmd)
	if err != nil {
		return fmt.Errorf("failed to set agent token: %w\n"+
			"Command output: %s\n"+
			"Remediation:\n"+
			"  - Check Consul is running: systemctl status consul\n"+
			"  - Verify token is valid: consul acl token read -id %s\n"+
			"  - Try manual: consul acl set-agent-token agent <token>",
			err, output, tokenID[:8]+"...")
	}

	logger.Info("Agent token configured successfully")
	logger.Info("Consul daemon will now use this token for internal operations")

	// EVALUATE - Verify token is active
	// Wait a second for the daemon to pick up the token
	logger.Debug("Verifying agent token is active")

	// Note: We can't easily verify this without causing side effects
	// The best verification is to check logs for absence of "blocked by ACLs" errors

	return nil
}

// PersistAgentTokenToConfig writes the agent token to the Consul config file.
//
// This makes the agent token persistent across Consul restarts by adding
// it to the HCL configuration file.
//
// WARNING: This modifies /etc/consul.d/consul.hcl and requires Consul restart.
// Prefer using ConfigureAgentToken() with token_persistence enabled instead.
//
// The token is added to the tokens block:
//
//	acl {
//	  enabled = true
//	  tokens {
//	    agent = "secret-token-id"
//	  }
//	}
//
// Parameters:
//   - rc: Runtime context
//   - tokenID: The SecretID of the agent token
//   - configPath: Path to Consul config file (e.g., /etc/consul.d/consul.hcl)
//
// Returns:
//   - Error if file modification fails
//
// Example:
//
//	err := acl.PersistAgentTokenToConfig(rc, tokenID, "/etc/consul.d/consul.hcl")
//	if err != nil {
//	    logger.Warn("Failed to persist token to config", zap.Error(err))
//	    logger.Warn("Token is configured in memory but won't survive restart")
//	}
func PersistAgentTokenToConfig(rc *eos_io.RuntimeContext, tokenID string, configPath string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Persisting agent token to config file",
		zap.String("config_path", configPath))

	// ASSESS - Read current config
	content, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	configStr := string(content)

	// ASSESS - Check if agent token already set in config
	if containsAgentToken(configStr) {
		logger.Info("Agent token already present in config file")
		logger.Info("Updating existing token value")

		// TODO: Implement HCL parser-based update
		// For now, warn user to manually update
		logger.Warn("Automatic token update not yet implemented")
		logger.Warn("Please manually update the agent token in the config file:")
		logger.Warn("  Edit: " + configPath)
		logger.Warn("  Set: acl.tokens.agent = \"<new-token>\"")
		logger.Warn("  Then: systemctl restart consul")

		return fmt.Errorf("agent token update not yet implemented - manual update required")
	}

	// INTERVENE - Add agent token to config
	// This is a simplified implementation - proper HCL parsing would be better
	logger.Warn("Automatic token persistence not yet implemented")
	logger.Warn("For persistent agent token across restarts:")
	logger.Warn("  1. Edit: " + configPath)
	logger.Warn("  2. Add to acl.tokens block:")
	logger.Warn("       acl = {")
	logger.Warn("         enabled = true")
	logger.Warn("         tokens = {")
	logger.Warn(fmt.Sprintf("           agent = \"%s\"", tokenID))
	logger.Warn("         }")
	logger.Warn("       }")
	logger.Warn("  3. Restart: systemctl restart consul")
	logger.Warn("")
	logger.Warn("OR enable token_persistence in Consul config (recommended):")
	logger.Warn("  acl.enable_token_persistence = true")

	return fmt.Errorf("config file persistence not yet implemented - use token_persistence instead")
}

// containsAgentToken checks if the config string already has an agent token
func containsAgentToken(configStr string) bool {
	// Simple string check - proper implementation would use HCL parser
	return configStr != "" &&
		(containsPattern(configStr, `tokens\s*\{\s*agent\s*=`) ||
		containsPattern(configStr, `tokens\.agent\s*=`))
}

// containsPattern checks if a regex pattern exists in the string
func containsPattern(str string, pattern string) bool {
	matched, _ := regexp.MatchString(pattern, str)
	return matched
}

// CreateAndConfigureAgentToken is a convenience function that creates an agent
// token and immediately configures the Consul daemon to use it.
//
// This combines CreateAgentToken() and ConfigureAgentToken() into a single
// operation, which is the most common use case.
//
// Parameters:
//   - rc: Runtime context
//   - bootstrapToken: The bootstrap/management token
//   - nodeName: Name of the Consul node (hostname if empty)
//
// Returns:
//   - AgentTokenResult with Configured=true if successful
//   - Error if either operation fails
//
// Example:
//
//	result, err := acl.CreateAndConfigureAgentToken(rc, bootstrapToken, "")
//	if err != nil {
//	    return fmt.Errorf("failed to setup agent token: %w", err)
//	}
//	logger.Info("Agent token ready", zap.String("accessor", result.AccessorID))
func CreateAndConfigureAgentToken(rc *eos_io.RuntimeContext, bootstrapToken string, nodeName string) (*AgentTokenResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Create token
	result, err := CreateAgentToken(rc, bootstrapToken, nodeName)
	if err != nil {
		return nil, fmt.Errorf("failed to create agent token: %w", err)
	}

	// Configure daemon
	if err := ConfigureAgentToken(rc, result.TokenID); err != nil {
		return nil, fmt.Errorf("agent token created but failed to configure daemon: %w\n"+
			"Token details:\n"+
			"  AccessorID: %s\n"+
			"  NodeName: %s\n"+
			"Manual configuration:\n"+
			"  consul acl set-agent-token agent %s",
			err, result.AccessorID, result.NodeName, result.TokenID)
	}

	result.Configured = true

	logger.Info("Agent token created and configured successfully",
		zap.String("accessor", result.AccessorID),
		zap.String("node", result.NodeName))

	return result, nil
}
