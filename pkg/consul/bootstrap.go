// pkg/consul/bootstrap.go

package consul

import (
	"fmt"
	"os/exec"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BootstrapConsulCluster handles the complex process of bootstrapping a Consul cluster
func BootstrapConsulCluster(rc *eos_io.RuntimeContext, config *ConsulConfig) (*BootstrapStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check if bootstrap is needed and possible
	logger.Info("Assessing cluster bootstrap requirements",
		zap.String("datacenter", config.Datacenter),
		zap.Int("bootstrap_expect", config.BootstrapExpect))

	// Check if cluster is already bootstrapped
	if status, err := checkBootstrapStatus(rc, config); err != nil {
		return nil, fmt.Errorf("failed to check bootstrap status: %w", err)
	} else if status.Bootstrapped {
		logger.Info("Cluster is already bootstrapped",
			zap.String("leader", status.Leader),
			zap.Int("peer_count", len(status.Peers)))
		return status, nil
	}

	// Validate bootstrap configuration
	if err := validateBootstrapConfig(rc, config); err != nil {
		return nil, fmt.Errorf("bootstrap configuration validation failed: %w", err)
	}

	// INTERVENE - Perform bootstrap process
	logger.Info("Beginning cluster bootstrap process")

	// Step 1: Wait for required number of nodes
	if err := waitForBootstrapNodes(rc, config); err != nil {
		return nil, fmt.Errorf("failed to wait for bootstrap nodes: %w", err)
	}

	// Step 2: Initialize cluster
	if err := initializeCluster(rc, config); err != nil {
		return nil, fmt.Errorf("failed to initialize cluster: %w", err)
	}

	// Step 3: Bootstrap ACLs if enabled
	var initialToken string
	if config.EnableACL {
		token, err := bootstrapACLSystem(rc, config)
		if err != nil {
			return nil, fmt.Errorf("failed to bootstrap ACL system: %w", err)
		}
		initialToken = token
	}

	// Step 4: Configure initial policies and services
	if err := configureInitialServices(rc, config); err != nil {
		logger.Warn("Failed to configure initial services",
			zap.Error(err))
		// Non-fatal - can be done later
	}

	// EVALUATE - Verify bootstrap succeeded
	logger.Info("Evaluating bootstrap success")

	// Check cluster health
	finalStatus, err := verifyBootstrapSuccess(rc, config)
	if err != nil {
		return nil, fmt.Errorf("bootstrap verification failed: %w", err)
	}

	// Update bootstrap status
	finalStatus.ACLBootstrapped = config.EnableACL
	finalStatus.InitialRootToken = initialToken
	finalStatus.BootstrapTime = time.Now()

	logger.Info("Cluster bootstrap completed successfully",
		zap.String("leader", finalStatus.Leader),
		zap.Int("peer_count", len(finalStatus.Peers)))

	return finalStatus, nil
}

// checkBootstrapStatus checks if the cluster is already bootstrapped
func checkBootstrapStatus(rc *eos_io.RuntimeContext, config *ConsulConfig) (*BootstrapStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Checking cluster bootstrap status")

	// Create Consul client
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	status := &BootstrapStatus{
		Bootstrapped:    false,
		ACLBootstrapped: false,
		Peers:           []string{},
	}

	// Check if we can connect to Consul
	leader, err := client.Status().Leader()
	if err != nil {
		logger.Debug("Cannot connect to Consul - likely not bootstrapped yet")
		return status, nil
	}

	if leader != "" {
		status.Bootstrapped = true
		status.Leader = leader
	}

	// Get cluster peers
	peers, err := client.Status().Peers()
	if err != nil {
		logger.Warn("Failed to get cluster peers", zap.Error(err))
	} else {
		status.Peers = peers
	}

	// Check ACL status
	if config.EnableACL {
		if aclStatus, _, err := client.ACL().Info("master", nil); err == nil && aclStatus != nil {
			status.ACLBootstrapped = true
		}
	}

	return status, nil
}

// validateBootstrapConfig validates the bootstrap configuration
func validateBootstrapConfig(rc *eos_io.RuntimeContext, config *ConsulConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Validating bootstrap configuration")

	// Validate bootstrap expect
	if config.BootstrapExpect < 1 {
		return eos_err.NewUserError("bootstrap_expect must be at least 1")
	}

	// Validate this is a server node
	if config.Mode != "server" {
		return eos_err.NewUserError("only server nodes can bootstrap a cluster")
	}

	// Validate datacenter
	if config.Datacenter == "" {
		return eos_err.NewUserError("datacenter must be specified for bootstrap")
	}

	// Validate node name
	if config.NodeName == "" {
		return eos_err.NewUserError("node_name must be specified for bootstrap")
	}

	logger.Info("Bootstrap configuration validation completed")
	return nil
}

// waitForBootstrapNodes waits for the required number of nodes to be available
func waitForBootstrapNodes(rc *eos_io.RuntimeContext, config *ConsulConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Waiting for bootstrap nodes",
		zap.Int("expected", config.BootstrapExpect))

	// Create Consul client
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return fmt.Errorf("failed to create Consul client: %w", err)
	}

	// Wait for nodes with timeout
	timeout := 5 * time.Minute
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		// Get cluster members
		members, err := client.Agent().Members(false)
		if err != nil {
			logger.Debug("Failed to get cluster members", zap.Error(err))
			time.Sleep(10 * time.Second)
			continue
		}

		// Count server nodes
		serverCount := 0
		for _, member := range members {
			if member.Tags["role"] == "consul" {
				serverCount++
			}
		}

		logger.Debug("Checking bootstrap nodes",
			zap.Int("current", serverCount),
			zap.Int("expected", config.BootstrapExpect))

		if serverCount >= config.BootstrapExpect {
			logger.Info("Required number of nodes available for bootstrap",
				zap.Int("count", serverCount))
			return nil
		}

		time.Sleep(10 * time.Second)
	}

	return fmt.Errorf("timeout waiting for %d nodes (found %d)", config.BootstrapExpect, 0)
}

// initializeCluster initializes the Consul cluster
func initializeCluster(rc *eos_io.RuntimeContext, config *ConsulConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Initializing Consul cluster")

	// The cluster initialization happens automatically when bootstrap_expect is met
	// We just need to wait for the election to complete

	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return fmt.Errorf("failed to create Consul client: %w", err)
	}

	// Wait for leader election
	timeout := 2 * time.Minute
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		leader, err := client.Status().Leader()
		if err != nil {
			logger.Debug("Failed to get leader status", zap.Error(err))
			time.Sleep(5 * time.Second)
			continue
		}

		if leader != "" {
			logger.Info("Cluster leader elected",
				zap.String("leader", leader))
			return nil
		}

		time.Sleep(5 * time.Second)
	}

	return fmt.Errorf("timeout waiting for leader election")
}

// bootstrapACLSystem bootstraps the ACL system
func bootstrapACLSystem(rc *eos_io.RuntimeContext, config *ConsulConfig) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Bootstrapping ACL system")

	// Wait a bit for cluster to stabilize
	time.Sleep(10 * time.Second)

	// Bootstrap ACL system
	cmd := exec.Command("consul", "acl", "bootstrap")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to bootstrap ACL system: %w\n"+
			"Output: %s\n"+
			"Remediation:\n"+
			"  1. Check if ACLs already bootstrapped: consul acl bootstrap\n"+
			"  2. If already bootstrapped, retrieve existing token from Consul KV\n"+
			"  3. Verify Consul is running: systemctl status consul",
			err, string(output))
	}

	// Extract the initial root token from output
	// The output contains: SecretID: <token>
	token, err := parseACLBootstrapOutput(string(output))
	if err != nil {
		logger.Warn("Failed to parse ACL bootstrap token from output",
			zap.Error(err),
			zap.String("output", string(output)))
		return "", fmt.Errorf("failed to parse ACL bootstrap token: %w", err)
	}

	logger.Info("ACL system bootstrapped successfully",
		zap.String("token_id", token[:min(8, len(token))]+"..."))

	// Store token in Consul KV for other nodes to retrieve (bootstrap storage)
	// This allows nodes to join the cluster before Vault is installed
	logger.Info("Storing ACL bootstrap token in Consul KV for cluster nodes")

	// Create Consul client with the bootstrap token we just created
	clientConfig := api.DefaultConfig()
	clientConfig.Token = token
	client, err := api.NewClient(clientConfig)
	if err != nil {
		logger.Warn("Failed to create Consul client to store token",
			zap.Error(err),
			zap.String("note", "Token not stored in Consul KV - manual distribution required"))
		return token, nil // Return token anyway, storage failure is non-fatal
	}

	// Store token in Consul KV using our auth package function
	if err := StoreTokenInConsulKV(rc, token, client); err != nil {
		logger.Warn("Failed to store ACL token in Consul KV",
			zap.Error(err),
			zap.String("note", "Token not stored - other nodes will need manual token configuration"))
		// Non-fatal - return token anyway
	} else {
		logger.Info("ACL bootstrap token stored successfully in Consul KV",
			zap.String("path", "eos/consul/acl_token"),
			zap.String("note", "Other nodes can now retrieve token automatically via 'eos sync consul'"))
	}

	return token, nil
}

// parseACLBootstrapOutput parses the consul acl bootstrap output to extract SecretID
// Example output:
//   AccessorID:       e5f93a48-e7c5-4f1e-9f9e-8b8e1c9e0a1d
//   SecretID:         3b9c3c0a-1234-5678-9abc-def123456789
//   ...
func parseACLBootstrapOutput(output string) (string, error) {
	lines := splitLines(output)
	for _, line := range lines {
		// Look for line starting with "SecretID:"
		if len(line) > 10 && line[:9] == "SecretID:" {
			// Extract token after "SecretID:"
			token := trimSpace(line[9:])
			if token != "" {
				return token, nil
			}
		}
	}
	return "", fmt.Errorf("SecretID not found in bootstrap output")
}

// Helper functions to avoid importing strings
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// configureInitialServices configures initial services and policies
func configureInitialServices(rc *eos_io.RuntimeContext, config *ConsulConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Configuring initial services")

	// TODO: Implement initial service configuration
	// This would involve:
	// 1. Create default policies
	// 2. Configure agent tokens
	// 3. Set up mesh gateway if enabled
	// 4. Configure ingress/egress gateways

	return nil
}

// verifyBootstrapSuccess verifies that the bootstrap process succeeded
func verifyBootstrapSuccess(rc *eos_io.RuntimeContext, config *ConsulConfig) (*BootstrapStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Verifying bootstrap success")

	// Create Consul client
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	status := &BootstrapStatus{
		Bootstrapped: false,
		Peers:        []string{},
	}

	// Check leader
	leader, err := client.Status().Leader()
	if err != nil {
		return nil, fmt.Errorf("failed to get leader: %w", err)
	}

	if leader == "" {
		return nil, fmt.Errorf("no leader elected")
	}

	status.Leader = leader
	status.Bootstrapped = true

	// Get peers
	peers, err := client.Status().Peers()
	if err != nil {
		return nil, fmt.Errorf("failed to get peers: %w", err)
	}

	status.Peers = peers

	// Verify minimum peer count
	if len(peers) < config.BootstrapExpect {
		return nil, fmt.Errorf("insufficient peers: got %d, expected %d", len(peers), config.BootstrapExpect)
	}

	// Check cluster health
	if err := verifyClusterHealth(rc, client); err != nil {
		return nil, fmt.Errorf("cluster health check failed: %w", err)
	}

	logger.Info("Bootstrap verification completed successfully",
		zap.String("leader", leader),
		zap.Int("peer_count", len(peers)))

	return status, nil
}

// verifyClusterHealth verifies that the cluster is healthy
func verifyClusterHealth(rc *eos_io.RuntimeContext, client *api.Client) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Verifying cluster health")

	// Check operator status
	if err := exec.Command("consul", "operator", "raft", "list-peers").Run(); err != nil {
		return fmt.Errorf("raft peers check failed: %w", err)
	}

	// Check if all nodes are alive
	members, err := client.Agent().Members(false)
	if err != nil {
		return fmt.Errorf("failed to get cluster members: %w", err)
	}

	aliveCount := 0
	for _, member := range members {
		if member.Status == 1 { // Alive
			aliveCount++
		}
	}

	logger.Info("Cluster health check completed",
		zap.Int("alive_members", aliveCount),
		zap.Int("total_members", len(members)))

	if aliveCount == 0 {
		return fmt.Errorf("no alive members in cluster")
	}

	return nil
}

// RecoverFromBootstrapFailure attempts to recover from bootstrap failures
func RecoverFromBootstrapFailure(rc *eos_io.RuntimeContext, config *ConsulConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Attempting to recover from bootstrap failure")

	// TODO: Implement bootstrap recovery
	// This would involve:
	// 1. Check for split-brain scenarios
	// 2. Verify network connectivity
	// 3. Reset bootstrap state if needed
	// 4. Restart services
	// 5. Attempt re-bootstrap

	return nil
}

// GetBootstrapStatus returns the current bootstrap status
func GetBootstrapStatus(rc *eos_io.RuntimeContext, config *ConsulConfig) (*BootstrapStatus, error) {
	return checkBootstrapStatus(rc, config)
}

// WaitForBootstrapComplete waits for bootstrap to complete
func WaitForBootstrapComplete(rc *eos_io.RuntimeContext, config *ConsulConfig, timeout time.Duration) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Waiting for bootstrap completion",
		zap.Duration("timeout", timeout))

	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		status, err := checkBootstrapStatus(rc, config)
		if err != nil {
			logger.Debug("Bootstrap status check failed", zap.Error(err))
			time.Sleep(5 * time.Second)
			continue
		}

		if status.Bootstrapped {
			logger.Info("Bootstrap completed successfully")
			return nil
		}

		time.Sleep(5 * time.Second)
	}

	return fmt.Errorf("timeout waiting for bootstrap completion")
}