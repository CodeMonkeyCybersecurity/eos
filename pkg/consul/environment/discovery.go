// Package environment provides Consul-based environment discovery for Vault secret operations.
//
// This package is separate from pkg/environment to avoid circular imports:
// - pkg/consul depends on pkg/environment
// - Environment discovery using Consul needs pkg/consul
// - Solution: Create pkg/consul/environment as intermediary
package environment

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	sharedvault "github.com/CodeMonkeyCybersecurity/eos/pkg/shared/vault"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DiscoverFromConsul reads the node's environment from Consul KV.
//
// This function queries Consul KV at eos/nodes/{hostname}/environment to retrieve
// the environment previously set via 'eos update consul --environment <env>'.
//
// Consul becomes the authoritative source of truth for node environment, enabling
// automatic environment detection for Vault secret operations.
//
// Returns:
//   - Environment: The discovered environment (production, staging, development, review)
//   - error: If Consul is unavailable, environment not set, or validation fails
//
// Example:
//
//	env, err := environment.DiscoverFromConsul(rc)
//	if err != nil {
//	    // Handle fail-closed: cannot determine environment
//	    return fmt.Errorf("environment discovery failed: %w", err)
//	}
//	logger.Info("Using environment from Consul", zap.String("environment", string(env)))
func DiscoverFromConsul(rc *eos_io.RuntimeContext) (sharedvault.Environment, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("failed to get hostname: %w", err)
	}

	// Connect to Consul (no token required for public KV reads in default policy)
	consulClient, err := consul.ConfigureConsulClient(rc, "")
	if err != nil {
		return "", fmt.Errorf("Consul unavailable: %w\n\n"+
			"Cannot determine environment without Consul (fail-closed security).\n\n"+
			"Remediation:\n"+
			"  - Ensure Consul is running: systemctl status consul\n"+
			"  - Check Consul health: consul members\n"+
			"  - Emergency override: CONSUL_EMERGENCY_OVERRIDE=true eos <command> --environment <env>", err)
	}

	// Query KV store
	kvPath := fmt.Sprintf("eos/nodes/%s/environment", hostname)
	pair, _, err := consulClient.KV().Get(kvPath, nil)
	if err != nil {
		return "", fmt.Errorf("failed to query Consul KV at %s: %w\n\n"+
			"Remediation:\n"+
			"  - Check Consul connectivity: consul kv get %s\n"+
			"  - Verify ACL token permissions if ACLs enabled", kvPath, err, kvPath)
	}

	if pair == nil {
		return "", fmt.Errorf("environment not set in Consul for node '%s'\n\n"+
			"This node's environment must be registered before using Vault secret operations.\n\n"+
			"Remediation:\n"+
			"  - Set environment: eos update consul --environment <env>\n"+
			"  - Valid environments: development, staging, production, review\n\n"+
			"Examples:\n"+
			"  eos update consul --environment development\n"+
			"  eos update consul --environment production\n\n"+
			"Emergency override (Consul unavailable):\n"+
			"  CONSUL_EMERGENCY_OVERRIDE=true eos <command> --environment <env>",
			hostname)
	}

	env := string(pair.Value)

	// Validate environment
	if err := sharedvault.ValidateEnvironment(env); err != nil {
		return "", fmt.Errorf("invalid environment '%s' in Consul at %s: %w\n\n"+
			"The environment stored in Consul is not valid.\n\n"+
			"Remediation:\n"+
			"  1. Delete invalid key: consul kv delete %s\n"+
			"  2. Set valid environment: eos update consul --environment <env>\n"+
			"  3. Valid environments: development, staging, production, review",
			env, kvPath, err, kvPath)
	}

	logger.Debug("Discovered environment from Consul",
		zap.String("hostname", hostname),
		zap.String("environment", env),
		zap.String("consul_path", kvPath))

	// Log to audit log for compliance (user requirement)
	logger.Info("Environment query",
		zap.String("source", "consul"),
		zap.String("hostname", hostname),
		zap.String("environment", env),
		zap.String("kv_path", kvPath),
		zap.String("audit", "environment_discovery"))

	return sharedvault.Environment(env), nil
}
