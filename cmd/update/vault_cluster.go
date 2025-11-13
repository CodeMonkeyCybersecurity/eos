// cmd/update/vault_cluster.go

package update

import (
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var vaultClusterCmd = &cobra.Command{
	Use:   "vault-cluster",
	Short: "Manage Vault Raft cluster operations",
	Long: `Manage HashiCorp Vault Raft cluster operations.

Operations:
  join       - Join this node to an existing Raft cluster
  autopilot  - Configure Autopilot for automated node lifecycle
  snapshot   - Take or restore Raft snapshots
  peers      - List Raft cluster peers
  health     - Check cluster health

Reference: vault-complete-specification-v1.0-raft-integrated.md

Examples:
  # Join cluster
  eos update vault-cluster join --leader=https://node1.example.com:8179

  # Configure Autopilot
  eos update vault-cluster autopilot --min-quorum=3

  # Take snapshot
  eos update vault-cluster snapshot --output=/backup/vault-snapshot.snap

  # List peers
  eos update vault-cluster peers

  # Check health
  eos update vault-cluster health`,
	Args: cobra.ExactArgs(1),
	RunE: eos.Wrap(runVaultCluster),
}

func init() {
	// Join flags
	vaultClusterCmd.Flags().String("leader", "", "Leader node API address for joining")

	// Autopilot flags
	vaultClusterCmd.Flags().Bool("cleanup-dead-servers", true, "Automatically remove dead servers")
	vaultClusterCmd.Flags().String("dead-server-threshold", "10m", "Time before considering server dead")
	vaultClusterCmd.Flags().Int("min-quorum", 3, "Minimum quorum size")
	vaultClusterCmd.Flags().String("stabilization-time", "10s", "Time to wait before promoting new nodes")

	// Snapshot flags
	vaultClusterCmd.Flags().String("output", "", "Output path for snapshot")
	vaultClusterCmd.Flags().String("input", "", "Input path for snapshot restore")
	vaultClusterCmd.Flags().Bool("force", false, "Force snapshot restore")

	// Token flag (required for authenticated operations)
	vaultClusterCmd.Flags().String("token", "", "Vault token (or set VAULT_TOKEN env var)")

	UpdateCmd.AddCommand(vaultClusterCmd)
}

func runVaultCluster(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	log := otelzap.Ctx(rc.Ctx)

	// CRITICAL: Detect flag-like args (P0-1 fix)
	if err := verify.ValidateNoFlagLikeArgs(args); err != nil {
		return err
	}

	operation := args[0]

	log.Info("Vault cluster operation", zap.String("operation", operation))

	switch operation {
	case "join":
		return runVaultClusterJoin(rc, cmd)
	case "autopilot":
		return runVaultClusterAutopilot(rc, cmd)
	case "snapshot":
		return runVaultClusterSnapshot(rc, cmd)
	case "peers":
		return runVaultClusterPeers(rc, cmd)
	case "health":
		return runVaultClusterHealth(rc, cmd)
	default:
		return fmt.Errorf("unknown operation: %s (valid: join, autopilot, snapshot, peers, health)", operation)
	}
}

func runVaultClusterJoin(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	log := otelzap.Ctx(rc.Ctx)

	leaderAddr, _ := cmd.Flags().GetString("leader")
	if leaderAddr == "" {
		return fmt.Errorf("--leader is required for join operation")
	}

	log.Info("Joining Raft cluster", zap.String("leader", leaderAddr))

	if err := vault.JoinRaftCluster(rc, leaderAddr); err != nil {
		log.Error("Failed to join cluster", zap.Error(err))
		return fmt.Errorf("join cluster: %w", err)
	}

	log.Info(" Successfully joined Raft cluster")
	log.Info("terminal prompt: Next steps:")
	log.Info("terminal prompt: 1. Unseal this node with the same unseal keys as the leader")
	log.Info("terminal prompt: 2. Verify cluster status: eos update vault-cluster peers")

	return nil
}

func runVaultClusterAutopilot(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	log := otelzap.Ctx(rc.Ctx)

	// ASSESS: Get authenticated token (delegates to pkg/vault for authentication)
	token, err := getAuthenticatedVaultClient(rc, cmd)
	if err != nil {
		return err // Error already includes remediation guidance
	}

	// Parse Autopilot configuration
	cleanupDeadServers, _ := cmd.Flags().GetBool("cleanup-dead-servers")
	deadServerThreshold, _ := cmd.Flags().GetString("dead-server-threshold")
	minQuorum, _ := cmd.Flags().GetInt("min-quorum")
	stabilizationTime, _ := cmd.Flags().GetString("stabilization-time")

	config := &vault.AutopilotConfig{
		CleanupDeadServers:             cleanupDeadServers,
		DeadServerLastContactThreshold: deadServerThreshold,
		MinQuorum:                      minQuorum,
		ServerStabilizationTime:        stabilizationTime,
	}

	log.Info("Configuring Autopilot",
		zap.Bool("cleanup_dead_servers", cleanupDeadServers),
		zap.Int("min_quorum", minQuorum))

	if err := vault.ConfigureRaftAutopilot(rc, token, config); err != nil {
		log.Error("Failed to configure Autopilot", zap.Error(err))
		return fmt.Errorf("configure autopilot: %w", err)
	}

	log.Info(" Autopilot configured successfully")
	log.Info("terminal prompt: Autopilot will now automatically manage node lifecycle")

	return nil
}

func runVaultClusterSnapshot(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	log := otelzap.Ctx(rc.Ctx)

	// ASSESS: Get authenticated token (delegates to pkg/vault for authentication)
	token, err := getAuthenticatedVaultClient(rc, cmd)
	if err != nil {
		return err // Error already includes remediation guidance
	}

	outputPath, _ := cmd.Flags().GetString("output")
	inputPath, _ := cmd.Flags().GetString("input")
	force, _ := cmd.Flags().GetBool("force")

	// Determine operation: backup or restore
	if inputPath != "" {
		// Restore operation (DANGEROUS - requires explicit confirmation)
		log.Warn("⚠️  SNAPSHOT RESTORE IS DESTRUCTIVE")
		log.Warn("This will replace all Vault data with the snapshot.")
		log.Warn("All unsealed Vault nodes must be sealed before restore.")
		log.Warn("")

		if !force {
			// Require explicit --force flag for safety
			log.Info("To proceed with snapshot restore, use the --force flag:")
			log.Info("  eos update vault-cluster snapshot --input=<path> --force")
			log.Info("")
			log.Info("⚠️  WARNING: Snapshot restore will:")
			log.Info("  • Replace all Vault data (KV secrets, policies, auth methods)")
			log.Info("  • Require all nodes to be restarted")
			log.Info("  • Cannot be undone without a backup")
			return fmt.Errorf("snapshot restore requires --force flag for safety")
		}

		log.Warn("Restoring Raft snapshot", zap.String("input", inputPath), zap.Bool("force", force))

		if err := vault.RestoreRaftSnapshot(rc, token, inputPath, force); err != nil {
			log.Error("Failed to restore snapshot", zap.Error(err))
			return fmt.Errorf("restore snapshot: %w", err)
		}

		log.Info(" Snapshot restored successfully")
		log.Info("terminal prompt: Cluster has been restored from snapshot")
		log.Info("terminal prompt: All nodes should be restarted to sync with restored state")

	} else if outputPath != "" {
		// Backup operation
		log.Info("Taking Raft snapshot", zap.String("output", outputPath))

		if err := vault.TakeRaftSnapshot(rc, token, outputPath); err != nil {
			log.Error("Failed to take snapshot", zap.Error(err))
			return fmt.Errorf("take snapshot: %w", err)
		}

		log.Info(" Snapshot created successfully", zap.String("path", outputPath))
		log.Info("terminal prompt: Snapshot saved - store securely for disaster recovery")

	} else {
		return fmt.Errorf("either --output (backup) or --input (restore) is required")
	}

	return nil
}

func runVaultClusterPeers(rc *eos_io.RuntimeContext, _ *cobra.Command) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info("Retrieving Raft cluster peers")

	peers, err := vault.GetRaftPeers(rc)
	if err != nil {
		log.Error("Failed to get peers", zap.Error(err))
		return fmt.Errorf("get peers: %w", err)
	}

	log.Info(fmt.Sprintf("terminal prompt: Raft Cluster Peers (%d nodes)", len(peers)))
	log.Info("terminal prompt: ")

	for _, peer := range peers {
		status := "follower"
		if peer.Leader {
			status = "leader ⭐"
		}

		voter := ""
		if peer.Voter {
			voter = " (voter)"
		}

		log.Info(fmt.Sprintf("terminal prompt:   %s: %s%s", peer.NodeID, status, voter))
		log.Info(fmt.Sprintf("terminal prompt:     Address: %s", peer.Address))
	}

	log.Info("terminal prompt: ")

	return nil
}

func runVaultClusterHealth(rc *eos_io.RuntimeContext, _ *cobra.Command) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info("Checking Raft cluster health")

	health, err := vault.GetClusterHealth(rc)
	if err != nil {
		log.Error("Failed to get cluster health", zap.Error(err))
		return fmt.Errorf("get cluster health: %w", err)
	}

	// Display health information
	log.Info("terminal prompt: " + health.String())

	if !health.Healthy {
		log.Warn("  Cluster is not healthy")
		return fmt.Errorf("cluster health check failed")
	}

	return nil
}

// getAuthenticatedVaultClient handles authentication for cluster operations.
// This is orchestration code (stays in cmd/) that delegates to pkg/vault for business logic.
//
// Authentication hierarchy:
// 1. --token flag (explicit user-provided token)
// 2. VAULT_TOKEN environment variable (CI/CD or scripted usage)
// 3. Admin authentication (Vault Agent → Admin AppRole → Root Token with consent)
//
// SECURITY: Token values are NEVER logged. All token validation happens in pkg/vault
// which implements token sanitization for logging.
//
// Returns: (token_string, error)
//
// Note: Returns only token (not client) because cluster operations use shell commands
// (vault operator raft ...) which need token in VAULT_TOKEN env var, not SDK client object.
func getAuthenticatedVaultClient(rc *eos_io.RuntimeContext, cmd *cobra.Command) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Try 1: --token flag (highest priority - user explicitly provided)
	if token, _ := cmd.Flags().GetString("token"); token != "" {
		logger.Info("Using token from --token flag")
		// Validate token has required capabilities
		_, err := vault.GetVaultClientWithToken(rc, token)
		if err != nil {
			return "", fmt.Errorf("invalid token from --token flag: %w", err)
		}
		return token, nil
	}

	// Try 2: VAULT_TOKEN environment variable (CI/CD usage)
	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		logger.Info("Using token from VAULT_TOKEN environment variable")
		// Validate token has required capabilities
		_, err := vault.GetVaultClientWithToken(rc, token)
		if err != nil {
			return "", fmt.Errorf("invalid token from VAULT_TOKEN: %w", err)
		}
		return token, nil
	}

	// Try 3: Admin authentication hierarchy (interactive or automated)
	logger.Info("No token provided via --token or VAULT_TOKEN")
	logger.Info("Attempting admin authentication (Vault Agent → AppRole → Root)")
	logger.Info("")

	adminClient, err := vault.GetAdminClient(rc)
	if err != nil {
		return "", fmt.Errorf("admin authentication failed: %w\n\n"+
			"Cluster operations require admin-level access. Provide token via:\n"+
			"  eos update vault-cluster ... --token <token>\n"+
			"  VAULT_TOKEN=<token> eos update vault-cluster ...\n"+
			"  <interactive>  Let Eos authenticate automatically (Vault Agent, AppRole, or emergency root)", err)
	}

	return adminClient.Token(), nil
}
