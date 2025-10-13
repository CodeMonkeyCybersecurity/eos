// cmd/create/vault_raft.go

package create

import (
	"fmt"
	"net"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var vaultRaftCmd = &cobra.Command{
	Use:   "vault-raft",
	Short: "Create Vault with Raft Integrated Storage",
	Long: `Create and configure HashiCorp Vault with Raft Integrated Storage.

Raft Integrated Storage is the recommended storage backend for Vault and is
REQUIRED for Vault Enterprise 1.12.0+. File storage is deprecated.

Reference: vault-complete-specification-v1.0-raft-integrated.md

Deployment Types:
  Single-node (Development):
    - Suitable for: Development, testing, POC
    - Tolerates: 0 node failures
    - Command: eos create vault-raft --node-id=eos-vault-dev

  Multi-node (Production):
    - Suitable for: Production HA deployments
    - Recommended: 5 nodes across 3 availability zones
    - Tolerates: 2 node failures (5-node cluster)
    - Command: eos create vault-raft --multi-node --nodes=node1:10.0.1.10,node2:10.0.1.11,node3:10.0.1.12

Auto-Unseal (Production Recommended):
  AWS KMS:
    eos create vault-raft --auto-unseal=awskms --kms-key-id=alias/vault-unseal --kms-region=ap-southeast-2
  
  Azure Key Vault:
    eos create vault-raft --auto-unseal=azure --azure-vault-name=my-vault --azure-key-name=vault-key
  
  GCP Cloud KMS:
    eos create vault-raft --auto-unseal=gcp --gcp-project=my-project --gcp-keyring=vault-keyring --gcp-key=vault-key

Examples:
  # Single-node development
  eos create vault-raft --node-id=eos-vault-dev

  # Multi-node production cluster
  eos create vault-raft --multi-node --nodes=node1:10.0.1.10,node2:10.0.1.11,node3:10.0.1.12

  # With auto-unseal (AWS KMS)
  eos create vault-raft --auto-unseal=awskms --kms-key-id=alias/vault-unseal

  # Generate TLS certificates
  eos create vault-raft --generate-tls --node-id=eos-vault-node1`,
	RunE: eos.Wrap(runVaultRaft),
}

func init() {
	// Node configuration
	vaultRaftCmd.Flags().String("node-id", "eos-vault-node1", "Unique node identifier for Raft")
	vaultRaftCmd.Flags().String("api-addr", "", "This node's API address (e.g., https://10.0.1.10:8179)")
	vaultRaftCmd.Flags().String("cluster-addr", "", "This node's cluster address (e.g., https://10.0.1.10:8180)")
	vaultRaftCmd.Flags().Int("cluster-port", 8180, "Raft cluster communication port")
	
	// Multi-node configuration
	vaultRaftCmd.Flags().Bool("multi-node", false, "Configure for multi-node cluster")
	vaultRaftCmd.Flags().String("nodes", "", "Comma-separated list of nodes (hostname:ip)")
	
	// TLS configuration
	vaultRaftCmd.Flags().Bool("generate-tls", false, "Generate TLS certificates")
	vaultRaftCmd.Flags().String("tls-cert", shared.TLSCrt, "Path to TLS certificate")
	vaultRaftCmd.Flags().String("tls-key", shared.TLSKey, "Path to TLS private key")
	vaultRaftCmd.Flags().StringSlice("dns-names", []string{"localhost"}, "DNS names for TLS certificate")
	vaultRaftCmd.Flags().StringSlice("ip-addresses", []string{"127.0.0.1"}, "IP addresses for TLS certificate")
	
	// Auto-unseal configuration
	vaultRaftCmd.Flags().String("auto-unseal", "", "Auto-unseal type (awskms, azure, gcp)")
	vaultRaftCmd.Flags().String("kms-key-id", "", "AWS KMS key ID")
	vaultRaftCmd.Flags().String("kms-region", "ap-southeast-2", "AWS KMS region")
	vaultRaftCmd.Flags().String("azure-tenant-id", "", "Azure tenant ID")
	vaultRaftCmd.Flags().String("azure-client-id", "", "Azure client ID")
	vaultRaftCmd.Flags().String("azure-client-secret", "", "Azure client secret")
	vaultRaftCmd.Flags().String("azure-vault-name", "", "Azure Key Vault name")
	vaultRaftCmd.Flags().String("azure-key-name", "", "Azure Key Vault key name")
	vaultRaftCmd.Flags().String("gcp-project", "", "GCP project ID")
	vaultRaftCmd.Flags().String("gcp-location", "australia-southeast1", "GCP location")
	vaultRaftCmd.Flags().String("gcp-keyring", "", "GCP KMS keyring")
	vaultRaftCmd.Flags().String("gcp-key", "", "GCP KMS crypto key")
	vaultRaftCmd.Flags().String("gcp-credentials", "", "Path to GCP credentials file")
	
	// Storage configuration
	vaultRaftCmd.Flags().String("data-path", shared.VaultDataPath, "Path for Raft data storage")
	
	// Operational flags
	vaultRaftCmd.Flags().Bool("dry-run", false, "Show configuration without creating")
	vaultRaftCmd.Flags().Bool("skip-install", false, "Skip Vault installation (config only)")
	
	CreateCmd.AddCommand(vaultRaftCmd)
}

func runVaultRaft(rc *eos_io.RuntimeContext, cmd *cobra.Command, _ []string) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("Creating Vault with Raft Integrated Storage")
	
	// Parse flags
	nodeID, _ := cmd.Flags().GetString("node-id")
	apiAddr, _ := cmd.Flags().GetString("api-addr")
	clusterAddr, _ := cmd.Flags().GetString("cluster-addr")
	clusterPort, _ := cmd.Flags().GetInt("cluster-port")
	multiNode, _ := cmd.Flags().GetBool("multi-node")
	nodesStr, _ := cmd.Flags().GetString("nodes")
	generateTLS, _ := cmd.Flags().GetBool("generate-tls")
	tlsCert, _ := cmd.Flags().GetString("tls-cert")
	tlsKey, _ := cmd.Flags().GetString("tls-key")
	dnsNames, _ := cmd.Flags().GetStringSlice("dns-names")
	ipAddresses, _ := cmd.Flags().GetStringSlice("ip-addresses")
	autoUnseal, _ := cmd.Flags().GetString("auto-unseal")
	dataPath, _ := cmd.Flags().GetString("data-path")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	skipInstall, _ := cmd.Flags().GetBool("skip-install")
	
	// Set default addresses if not provided
	if apiAddr == "" {
		apiAddr = fmt.Sprintf("https://127.0.0.1:%d", shared.PortVault)
	}
	if clusterAddr == "" {
		clusterAddr = fmt.Sprintf("https://127.0.0.1:%d", clusterPort)
	}
	
	// Parse nodes for multi-node configuration
	var retryJoinNodes []shared.RetryJoinNode
	if multiNode && nodesStr != "" {
		var err error
		retryJoinNodes, err = parseNodes(nodesStr)
		if err != nil {
			log.Error("Failed to parse nodes", zap.Error(err))
			return fmt.Errorf("parse nodes: %w", err)
		}
		log.Info("Multi-node configuration", zap.Int("node_count", len(retryJoinNodes)))
	}
	
	// Generate TLS certificates if requested
	if generateTLS {
		log.Info("Generating TLS certificates for Raft")
		
		// Parse IP addresses
		ips := make([]net.IP, 0, len(ipAddresses))
		for _, ipStr := range ipAddresses {
			if ip := net.ParseIP(ipStr); ip != nil {
				ips = append(ips, ip)
			} else {
				log.Warn("Invalid IP address", zap.String("ip", ipStr))
			}
		}
		
		// Create TLS configuration
		tlsConfig := vault.DefaultTLSCertificateConfig()
		tlsConfig.CommonName = nodeID
		tlsConfig.DNSNames = dnsNames
		tlsConfig.IPAddresses = ips
		tlsConfig.CertPath = tlsCert
		tlsConfig.KeyPath = tlsKey
		
		if dryRun {
			log.Info("DRY RUN: Would generate TLS certificate",
				zap.String("common_name", tlsConfig.CommonName),
				zap.Strings("dns_names", tlsConfig.DNSNames),
				zap.Int("ip_count", len(tlsConfig.IPAddresses)))
		} else {
			if err := vault.GenerateRaftTLSCertificate(rc, tlsConfig); err != nil {
				log.Error("Failed to generate TLS certificate", zap.Error(err))
				return fmt.Errorf("generate TLS certificate: %w", err)
			}
			log.Info("TLS certificate generated successfully",
				zap.String("cert", tlsCert),
				zap.String("key", tlsKey))
		}
	}
	
	// Build install configuration
	installConfig := &vault.InstallConfig{
		Version:        "latest",
		StorageBackend: "raft",
		NodeID:         nodeID,
		APIAddr:        apiAddr,
		ClusterAddr:    clusterAddr,
		ClusterPort:    clusterPort,
		DataPath:       dataPath,
		TLSEnabled:     true,
		UIEnabled:      true,
		LogLevel:       "info",
		RetryJoinNodes: retryJoinNodes,
	}
	
	// Configure auto-unseal if requested
	if autoUnseal != "" {
		installConfig.AutoUnseal = true
		installConfig.AutoUnsealType = autoUnseal
		
		switch strings.ToLower(autoUnseal) {
		case "awskms", "aws":
			kmsKeyID, _ := cmd.Flags().GetString("kms-key-id")
			kmsRegion, _ := cmd.Flags().GetString("kms-region")
			if kmsKeyID == "" {
				return fmt.Errorf("--kms-key-id is required for AWS KMS auto-unseal")
			}
			installConfig.KMSKeyID = kmsKeyID
			installConfig.KMSRegion = kmsRegion
			log.Info("Configuring AWS KMS auto-unseal",
				zap.String("key_id", kmsKeyID),
				zap.String("region", kmsRegion))
			
		case "azurekeyvault", "azure":
			azureTenantID, _ := cmd.Flags().GetString("azure-tenant-id")
			azureClientID, _ := cmd.Flags().GetString("azure-client-id")
			azureClientSecret, _ := cmd.Flags().GetString("azure-client-secret")
			azureVaultName, _ := cmd.Flags().GetString("azure-vault-name")
			azureKeyName, _ := cmd.Flags().GetString("azure-key-name")
			
			if azureTenantID == "" || azureClientID == "" || azureClientSecret == "" ||
				azureVaultName == "" || azureKeyName == "" {
				return fmt.Errorf("Azure Key Vault auto-unseal requires: tenant-id, client-id, client-secret, vault-name, key-name")
			}
			
			installConfig.AzureTenantID = azureTenantID
			installConfig.AzureClientID = azureClientID
			installConfig.AzureClientSecret = azureClientSecret
			installConfig.AzureVaultName = azureVaultName
			installConfig.AzureKeyName = azureKeyName
			log.Info("Configuring Azure Key Vault auto-unseal",
				zap.String("vault_name", azureVaultName),
				zap.String("key_name", azureKeyName))
			
		case "gcpckms", "gcp":
			gcpProject, _ := cmd.Flags().GetString("gcp-project")
			gcpLocation, _ := cmd.Flags().GetString("gcp-location")
			gcpKeyRing, _ := cmd.Flags().GetString("gcp-keyring")
			gcpKey, _ := cmd.Flags().GetString("gcp-key")
			gcpCredentials, _ := cmd.Flags().GetString("gcp-credentials")
			
			if gcpProject == "" || gcpKeyRing == "" || gcpKey == "" {
				return fmt.Errorf("GCP Cloud KMS auto-unseal requires: project, keyring, key")
			}
			
			installConfig.GCPProject = gcpProject
			installConfig.GCPLocation = gcpLocation
			installConfig.GCPKeyRing = gcpKeyRing
			installConfig.GCPCryptoKey = gcpKey
			installConfig.GCPCredentials = gcpCredentials
			log.Info("Configuring GCP Cloud KMS auto-unseal",
				zap.String("project", gcpProject),
				zap.String("keyring", gcpKeyRing),
				zap.String("key", gcpKey))
			
		default:
			return fmt.Errorf("unsupported auto-unseal type: %s (supported: awskms, azure, gcp)", autoUnseal)
		}
	}
	
	// Validate Raft configuration
	if err := vault.ValidateRaftConfig(rc, installConfig); err != nil {
		log.Error("Invalid Raft configuration", zap.Error(err))
		return fmt.Errorf("validate raft config: %w", err)
	}
	
	// Generate and display configuration
	hcl, err := vault.RenderRaftConfig(rc, installConfig)
	if err != nil {
		log.Error("Failed to render Raft configuration", zap.Error(err))
		return fmt.Errorf("render raft config: %w", err)
	}
	
	if dryRun {
		log.Info("DRY RUN: Vault Raft Configuration")
		log.Info("terminal prompt: ===== Vault Configuration (vault.hcl) =====")
		log.Info(fmt.Sprintf("terminal prompt: %s", hcl))
		log.Info("terminal prompt: ==========================================")
		log.Info("terminal prompt: Configuration validated successfully")
		log.Info(fmt.Sprintf("terminal prompt: Node ID: %s", nodeID))
		log.Info(fmt.Sprintf("terminal prompt: API Address: %s", apiAddr))
		log.Info(fmt.Sprintf("terminal prompt: Cluster Address: %s", clusterAddr))
		log.Info(fmt.Sprintf("terminal prompt: Storage Backend: Raft Integrated Storage"))
		if multiNode {
			log.Info(fmt.Sprintf("terminal prompt: Cluster Nodes: %d", len(retryJoinNodes)))
		}
		if autoUnseal != "" {
			log.Info(fmt.Sprintf("terminal prompt: Auto-Unseal: %s", autoUnseal))
		}
		return nil
	}
	
	// Install Vault if not skipped
	if !skipInstall {
		log.Info("Installing Vault with Raft Integrated Storage")
		installer := vault.NewVaultInstaller(rc, installConfig)
		
		if err := installer.Install(); err != nil {
			log.Error("Failed to install Vault", zap.Error(err))
			return fmt.Errorf("install vault: %w", err)
		}
		
		log.Info("Vault installed successfully with Raft Integrated Storage")
	}
	
	// Write configuration
	log.Info("Writing Vault configuration")
	if err := vault.WriteVaultHCL(rc); err != nil {
		log.Error("Failed to write Vault configuration", zap.Error(err))
		return fmt.Errorf("write vault config: %w", err)
	}
	
	log.Info("✅ Vault with Raft Integrated Storage created successfully")
	log.Info("terminal prompt: ")
	log.Info("terminal prompt: Next steps:")
	log.Info("terminal prompt: 1. Start Vault: sudo systemctl start vault")
	log.Info("terminal prompt: 2. Initialize cluster: eos bootstrap vault")
	if multiNode {
		log.Info("terminal prompt: 3. Join additional nodes: eos update vault join-cluster --leader=<leader-addr>")
		log.Info("terminal prompt: 4. Configure Autopilot: eos update vault autopilot")
	}
	log.Info("terminal prompt: ")
	
	return nil
}

// parseNodes parses comma-separated node list in format: hostname:ip,hostname:ip
func parseNodes(nodesStr string) ([]shared.RetryJoinNode, error) {
	if nodesStr == "" {
		return nil, nil
	}
	
	parts := strings.Split(nodesStr, ",")
	nodes := make([]shared.RetryJoinNode, 0, len(parts))
	
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		
		// Parse hostname:ip format
		hostIP := strings.Split(part, ":")
		if len(hostIP) != 2 {
			return nil, fmt.Errorf("invalid node format '%s' (expected hostname:ip)", part)
		}
		
		hostname := strings.TrimSpace(hostIP[0])
		ip := strings.TrimSpace(hostIP[1])
		
		if hostname == "" || ip == "" {
			return nil, fmt.Errorf("invalid node format '%s' (hostname and IP required)", part)
		}
		
		// Validate IP address
		if net.ParseIP(ip) == nil {
			return nil, fmt.Errorf("invalid IP address '%s' in node '%s'", ip, part)
		}
		
		nodes = append(nodes, shared.RetryJoinNode{
			APIAddr:  fmt.Sprintf("https://%s:%d", ip, shared.PortVault),
			Hostname: hostname,
		})
	}
	
	return nodes, nil
}
