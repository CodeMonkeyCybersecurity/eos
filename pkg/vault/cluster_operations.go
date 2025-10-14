// pkg/vault/cluster_operations.go

package vault

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ClusterInitConfig contains configuration for Raft cluster initialization
// Reference: vault-complete-specification-v1.0-raft-integrated.md - Multi-Node Cluster Initialization
type ClusterInitConfig struct {
	// Shamir's Secret Sharing configuration
	KeyShares    int // Number of key shares to generate (default: 5)
	KeyThreshold int // Number of keys required to unseal (default: 3)

	// Recovery keys (for auto-unseal)
	RecoveryShares    int // Number of recovery key shares (for auto-unseal)
	RecoveryThreshold int // Number of recovery keys required

	// Output configuration
	OutputPath string // Path to save initialization output (default: /var/lib/eos/secret/vault_init.json)

	// Auto-unseal mode
	AutoUnseal bool // Whether auto-unseal is configured
}

// DefaultClusterInitConfig returns default cluster initialization configuration
func DefaultClusterInitConfig() *ClusterInitConfig {
	return &ClusterInitConfig{
		KeyShares:    5,
		KeyThreshold: 3,
		OutputPath:   shared.VaultInitPath,
		AutoUnseal:   false,
	}
}

// InitializeRaftCluster initializes a new Raft cluster on the first node
// Reference: vault-complete-specification-v1.0-raft-integrated.md - Multi-Node Cluster Initialization
func InitializeRaftCluster(rc *eos_io.RuntimeContext, config *ClusterInitConfig) (*VaultInitResult, error) {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("Initializing Raft cluster",
		zap.Int("key_shares", config.KeyShares),
		zap.Int("key_threshold", config.KeyThreshold),
		zap.Bool("auto_unseal", config.AutoUnseal))

	// Build vault operator init command
	args := []string{"operator", "init"}

	if config.AutoUnseal {
		// For auto-unseal, use recovery keys instead of unseal keys
		args = append(args,
			"-recovery-shares", fmt.Sprintf("%d", config.RecoveryShares),
			"-recovery-threshold", fmt.Sprintf("%d", config.RecoveryThreshold))
	} else {
		// For manual unsealing, use standard Shamir's Secret Sharing
		args = append(args,
			"-key-shares", fmt.Sprintf("%d", config.KeyShares),
			"-key-threshold", fmt.Sprintf("%d", config.KeyThreshold))
	}

	args = append(args, "-format=json")

	// Execute vault operator init
	cmd := exec.CommandContext(rc.Ctx, "vault", args...)
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("VAULT_ADDR=%s", shared.GetVaultAddr()),
		"VAULT_SKIP_VERIFY=1") // For self-signed certs

	log.Info("Executing vault operator init", zap.Strings("args", args))
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error("Failed to initialize Vault", zap.Error(err), zap.String("output", string(output)))
		return nil, fmt.Errorf("vault operator init failed: %w\nOutput: %s", err, string(output))
	}

	// Parse initialization output
	var result VaultInitResult
	if err := json.Unmarshal(output, &result); err != nil {
		log.Error("Failed to parse init output", zap.Error(err))
		return nil, fmt.Errorf("parse init output: %w", err)
	}

	log.Info("Vault cluster initialized successfully",
		zap.Int("unseal_keys", len(result.UnsealKeys)),
		zap.Int("recovery_keys", len(result.RecoveryKeys)),
		zap.Bool("has_root_token", result.RootToken != ""))

	return &result, nil
}

// VaultInitResult contains the result of vault operator init
type VaultInitResult struct {
	UnsealKeys   []string `json:"unseal_keys_b64,omitempty"`
	RootToken    string   `json:"root_token"`
	RecoveryKeys []string `json:"recovery_keys_b64,omitempty"`
}

// JoinRaftCluster joins a node to an existing Raft cluster
// Reference: vault-complete-specification-v1.0-raft-integrated.md - Multi-Node Cluster Initialization
func JoinRaftCluster(rc *eos_io.RuntimeContext, leaderAddr string) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("Joining Raft cluster", zap.String("leader", leaderAddr))

	// Execute vault operator raft join
	cmd := exec.CommandContext(rc.Ctx, "vault", "operator", "raft", "join", leaderAddr)
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("VAULT_ADDR=%s", shared.GetVaultAddr()),
		"VAULT_SKIP_VERIFY=1")

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error("Failed to join cluster", zap.Error(err), zap.String("output", string(output)))
		return fmt.Errorf("vault operator raft join failed: %w\nOutput: %s", err, string(output))
	}

	log.Info("Successfully joined Raft cluster", zap.String("output", string(output)))
	return nil
}

// UnsealVaultWithKeys unseals a Vault instance using provided unseal keys
// Reference: vault-complete-specification-v1.0-raft-integrated.md - Initialization and Unsealing
func UnsealVaultWithKeys(rc *eos_io.RuntimeContext, unsealKeys []string, threshold int) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("Unsealing Vault", zap.Int("keys_provided", len(unsealKeys)), zap.Int("threshold", threshold))

	if len(unsealKeys) < threshold {
		return fmt.Errorf("insufficient unseal keys: have %d, need %d", len(unsealKeys), threshold)
	}

	// Unseal using threshold number of keys
	for i := 0; i < threshold; i++ {
		log.Info("Applying unseal key", zap.Int("key_number", i+1))

		cmd := exec.CommandContext(rc.Ctx, "vault", "operator", "unseal", unsealKeys[i])
		cmd.Env = append(cmd.Env,
			fmt.Sprintf("VAULT_ADDR=%s", shared.GetVaultAddr()),
			"VAULT_SKIP_VERIFY=1")

		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Error("Failed to unseal", zap.Error(err), zap.String("output", string(output)))
			return fmt.Errorf("vault operator unseal failed: %w", err)
		}

		log.Debug("Unseal key applied", zap.String("output", string(output)))
	}

	log.Info("Vault unsealed successfully")
	return nil
}

// GetRaftPeers retrieves the list of Raft peers in the cluster
// Reference: vault-complete-specification-v1.0-raft-integrated.md - Multi-Node Raft Cluster
func GetRaftPeers(rc *eos_io.RuntimeContext) ([]RaftPeer, error) {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("Retrieving Raft peer list")

	cmd := exec.CommandContext(rc.Ctx, "vault", "operator", "raft", "list-peers", "-format=json")
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("VAULT_ADDR=%s", shared.GetVaultAddr()),
		"VAULT_SKIP_VERIFY=1")

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error("Failed to list peers", zap.Error(err), zap.String("output", string(output)))
		return nil, fmt.Errorf("vault operator raft list-peers failed: %w", err)
	}

	var result struct {
		Data struct {
			Config struct {
				Servers []RaftPeer `json:"servers"`
			} `json:"config"`
		} `json:"data"`
	}

	if err := json.Unmarshal(output, &result); err != nil {
		log.Error("Failed to parse peer list", zap.Error(err))
		return nil, fmt.Errorf("parse peer list: %w", err)
	}

	peers := result.Data.Config.Servers
	log.Info("Retrieved Raft peers", zap.Int("peer_count", len(peers)))

	return peers, nil
}

// RaftPeer represents a node in the Raft cluster
type RaftPeer struct {
	NodeID  string `json:"node_id"`
	Address string `json:"address"`
	Leader  bool   `json:"leader"`
	Voter   bool   `json:"voter"`
}

// ConfigureRaftAutopilot configures Autopilot for automated node lifecycle management
// Reference: vault-complete-specification-v1.0-raft-integrated.md - Autopilot Configuration
// token parameter should be the root token or a token with sufficient permissions
func ConfigureRaftAutopilot(rc *eos_io.RuntimeContext, token string, config *AutopilotConfig) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("Configuring Raft Autopilot",
		zap.Bool("cleanup_dead_servers", config.CleanupDeadServers),
		zap.Int("min_quorum", config.MinQuorum))

	args := []string{"operator", "raft", "autopilot", "set-config"}

	if config.CleanupDeadServers {
		args = append(args, "-cleanup-dead-servers=true")
	}

	if config.DeadServerLastContactThreshold != "" {
		args = append(args, fmt.Sprintf("-dead-server-last-contact-threshold=%s", config.DeadServerLastContactThreshold))
	}

	if config.MinQuorum > 0 {
		args = append(args, fmt.Sprintf("-min-quorum=%d", config.MinQuorum))
	}

	if config.ServerStabilizationTime != "" {
		args = append(args, fmt.Sprintf("-server-stabilization-time=%s", config.ServerStabilizationTime))
	}

	cmd := exec.CommandContext(rc.Ctx, "vault", args...)
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("VAULT_ADDR=%s", shared.GetVaultAddr()),
		fmt.Sprintf("VAULT_TOKEN=%s", token),
		"VAULT_SKIP_VERIFY=1")

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error("Failed to configure Autopilot", zap.Error(err), zap.String("output", string(output)))
		return fmt.Errorf("configure autopilot failed: %w", err)
	}

	log.Info("Autopilot configured successfully")
	return nil
}

// AutopilotConfig contains Autopilot configuration
// Reference: vault-complete-specification-v1.0-raft-integrated.md - Autopilot Configuration
type AutopilotConfig struct {
	CleanupDeadServers             bool   // Automatically remove dead servers
	DeadServerLastContactThreshold string // Time before considering server dead (e.g., "10m")
	MinQuorum                      int    // Minimum quorum size (e.g., 3 for 5-node cluster)
	ServerStabilizationTime        string // Time to wait before promoting new nodes (e.g., "10s")
}

// DefaultAutopilotConfig returns default Autopilot configuration for a 5-node cluster
func DefaultAutopilotConfig() *AutopilotConfig {
	return &AutopilotConfig{
		CleanupDeadServers:             true,
		DeadServerLastContactThreshold: "10m",
		MinQuorum:                      3,
		ServerStabilizationTime:        "10s",
	}
}

// GetAutopilotState retrieves the current Autopilot state
// token parameter should be the root token or a token with sufficient permissions
func GetAutopilotState(rc *eos_io.RuntimeContext, token string) (*AutopilotState, error) {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("Retrieving Autopilot state")

	cmd := exec.CommandContext(rc.Ctx, "vault", "operator", "raft", "autopilot", "state", "-format=json")
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("VAULT_ADDR=%s", shared.GetVaultAddr()),
		fmt.Sprintf("VAULT_TOKEN=%s", token),
		"VAULT_SKIP_VERIFY=1")

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error("Failed to get Autopilot state", zap.Error(err), zap.String("output", string(output)))
		return nil, fmt.Errorf("get autopilot state failed: %w", err)
	}

	var state AutopilotState
	if err := json.Unmarshal(output, &state); err != nil {
		log.Error("Failed to parse Autopilot state", zap.Error(err))
		return nil, fmt.Errorf("parse autopilot state: %w", err)
	}

	log.Info("Retrieved Autopilot state", zap.Bool("healthy", state.Healthy))
	return &state, nil
}

// AutopilotState represents the current state of Autopilot
type AutopilotState struct {
	Healthy                    bool                       `json:"healthy"`
	FailureTolerance           int                        `json:"failure_tolerance"`
	Leader                     string                     `json:"leader"`
	Voters                     []string                   `json:"voters"`
	Servers                    map[string]AutopilotServer `json:"servers"`
	RedundancyZones            map[string]interface{}     `json:"redundancy_zones,omitempty"`
	UpgradeInfo                interface{}                `json:"upgrade_info,omitempty"`
	OptimisticFailureTolerance int                        `json:"optimistic_failure_tolerance"`
}

// AutopilotServer represents a server in Autopilot state
type AutopilotServer struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Address     string            `json:"address"`
	NodeStatus  string            `json:"node_status"`
	LastContact string            `json:"last_contact"`
	LastTerm    int               `json:"last_term"`
	LastIndex   int               `json:"last_index"`
	Healthy     bool              `json:"healthy"`
	StableSince time.Time         `json:"stable_since"`
	Status      string            `json:"status"`
	Meta        map[string]string `json:"meta,omitempty"`
}

// RemoveRaftPeer removes a peer from the Raft cluster
// Use with caution - only for removing permanently failed nodes
// token parameter should be the root token or a token with sufficient permissions
func RemoveRaftPeer(rc *eos_io.RuntimeContext, token string, nodeID string) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Warn("Removing Raft peer", zap.String("node_id", nodeID))

	cmd := exec.CommandContext(rc.Ctx, "vault", "operator", "raft", "remove-peer", nodeID)
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("VAULT_ADDR=%s", shared.GetVaultAddr()),
		fmt.Sprintf("VAULT_TOKEN=%s", token),
		"VAULT_SKIP_VERIFY=1")

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error("Failed to remove peer", zap.Error(err), zap.String("output", string(output)))
		return fmt.Errorf("remove peer failed: %w", err)
	}

	log.Info("Raft peer removed successfully", zap.String("node_id", nodeID))
	return nil
}

// TakeRaftSnapshot creates a snapshot of the Raft cluster
// Reference: vault-complete-specification-v1.0-raft-integrated.md - Backup and Restore
// token parameter should be the root token or a token with sufficient permissions
func TakeRaftSnapshot(rc *eos_io.RuntimeContext, token string, outputPath string) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("Taking Raft snapshot", zap.String("output", outputPath))

	cmd := exec.CommandContext(rc.Ctx, "vault", "operator", "raft", "snapshot", "save", outputPath)
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("VAULT_ADDR=%s", shared.GetVaultAddr()),
		fmt.Sprintf("VAULT_TOKEN=%s", token),
		"VAULT_SKIP_VERIFY=1")

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error("Failed to take snapshot", zap.Error(err), zap.String("output", string(output)))
		return fmt.Errorf("take snapshot failed: %w", err)
	}

	log.Info("Raft snapshot created successfully", zap.String("path", outputPath))
	return nil
}

// RestoreRaftSnapshot restores a Raft cluster from a snapshot
// Reference: vault-complete-specification-v1.0-raft-integrated.md - Backup and Restore
// token parameter should be the root token or a token with sufficient permissions
func RestoreRaftSnapshot(rc *eos_io.RuntimeContext, token string, snapshotPath string, force bool) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Warn("Restoring Raft snapshot", zap.String("snapshot", snapshotPath), zap.Bool("force", force))

	args := []string{"operator", "raft", "snapshot", "restore"}
	if force {
		args = append(args, "-force")
	}
	args = append(args, snapshotPath)

	cmd := exec.CommandContext(rc.Ctx, "vault", args...)
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("VAULT_ADDR=%s", shared.GetVaultAddr()),
		fmt.Sprintf("VAULT_TOKEN=%s", token),
		"VAULT_SKIP_VERIFY=1")

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error("Failed to restore snapshot", zap.Error(err), zap.String("output", string(output)))
		return fmt.Errorf("restore snapshot failed: %w", err)
	}

	log.Info("Raft snapshot restored successfully")
	return nil
}

// GetClusterHealth checks the health of the Raft cluster
func GetClusterHealth(rc *eos_io.RuntimeContext) (*ClusterHealth, error) {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("Checking cluster health")

	// Get Raft peers
	peers, err := GetRaftPeers(rc)
	if err != nil {
		return nil, fmt.Errorf("get raft peers: %w", err)
	}

	// Get Autopilot state (requires token - skip if not available)
	// For now, we'll skip Autopilot state in health check
	// TODO: Accept token parameter for complete health check

	// Count healthy nodes
	healthyNodes := 0
	leaderFound := false
	for _, peer := range peers {
		if peer.Leader {
			leaderFound = true
		}
		// Assume voter nodes are healthy (more detailed health check would query each node)
		if peer.Voter {
			healthyNodes++
		}
	}

	health := &ClusterHealth{
		TotalNodes:   len(peers),
		HealthyNodes: healthyNodes,
		HasLeader:    leaderFound,
		Peers:        peers,
	}

	// Autopilot state would be added here if token was provided
	// health.AutopilotHealthy = autopilot.Healthy
	// health.FailureTolerance = autopilot.FailureTolerance

	// Determine overall health
	health.Healthy = leaderFound && healthyNodes >= (len(peers)/2+1)

	log.Info("Cluster health check complete",
		zap.Bool("healthy", health.Healthy),
		zap.Int("total_nodes", health.TotalNodes),
		zap.Int("healthy_nodes", health.HealthyNodes),
		zap.Bool("has_leader", health.HasLeader))

	return health, nil
}

// ClusterHealth represents the health status of the Raft cluster
type ClusterHealth struct {
	Healthy          bool       `json:"healthy"`
	TotalNodes       int        `json:"total_nodes"`
	HealthyNodes     int        `json:"healthy_nodes"`
	HasLeader        bool       `json:"has_leader"`
	AutopilotHealthy bool       `json:"autopilot_healthy"`
	FailureTolerance int        `json:"failure_tolerance"`
	Peers            []RaftPeer `json:"peers"`
}

// String returns a human-readable representation of cluster health
func (h *ClusterHealth) String() string {
	var sb strings.Builder

	if h.Healthy {
		sb.WriteString(" Cluster is HEALTHY\n")
	} else {
		sb.WriteString("❌ Cluster is UNHEALTHY\n")
	}

	sb.WriteString(fmt.Sprintf("Nodes: %d total, %d healthy\n", h.TotalNodes, h.HealthyNodes))
	sb.WriteString(fmt.Sprintf("Leader: %v\n", h.HasLeader))
	sb.WriteString(fmt.Sprintf("Failure Tolerance: %d nodes\n", h.FailureTolerance))

	if h.AutopilotHealthy {
		sb.WriteString("Autopilot:  Healthy\n")
	} else {
		sb.WriteString("Autopilot:   Not healthy or not configured\n")
	}

	sb.WriteString("\nPeers:\n")
	for _, peer := range h.Peers {
		status := "follower"
		if peer.Leader {
			status = "leader"
		}
		voter := ""
		if peer.Voter {
			voter = " (voter)"
		}
		sb.WriteString(fmt.Sprintf("  - %s: %s%s at %s\n", peer.NodeID, status, voter, peer.Address))
	}

	return sb.String()
}
