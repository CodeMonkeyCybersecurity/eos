package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/cephfs"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var cephfsCmd = &cobra.Command{
	Use:   "cephfs",
	Short: "Deploy CephFS cluster on bare metal with SaltStack and Terraform orchestration",
	Long: `Deploy CephFS cluster on bare metal using the three-tier orchestration:
1. SaltStack generates Terraform configurations from pillar data
2. Terraform applies these configurations to deploy CephFS via cephadm
3. CephFS runs on bare metal (not containerized) for optimal I/O performance

The deployment includes:
- Cluster initialization with configurable FSID
- OSD deployment with all-available-devices spec
- Network configuration (public and cluster networks)
- SSH-based remote execution for cephadm operations
- Comprehensive health checks and verification

Prerequisites:
- Ubuntu 22.04 LTS or later
- Root access on all target nodes
- SSH key authentication configured
- Minimum 4GB RAM per OSD node
- Available block devices for OSD storage`,

	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		
		logger.Info("Starting CephFS cluster deployment")

		// Get configuration from flags
		clusterFSID, _ := cmd.Flags().GetString("cluster-fsid")
		adminHost, _ := cmd.Flags().GetString("admin-host")
		sshUser, _ := cmd.Flags().GetString("ssh-user")
		cephImage, _ := cmd.Flags().GetString("ceph-image")
		publicNetwork, _ := cmd.Flags().GetString("public-network")
		clusterNetwork, _ := cmd.Flags().GetString("cluster-network")
		osdDevices, _ := cmd.Flags().GetStringSlice("osd-devices")
		skipVerify, _ := cmd.Flags().GetBool("skip-verify")
		saltOnly, _ := cmd.Flags().GetBool("salt-only")
		terraformOnly, _ := cmd.Flags().GetBool("terraform-only")

		// Create configuration
		config := &cephfs.Config{
			ClusterFSID:    clusterFSID,
			AdminHost:      adminHost,
			SSHUser:        sshUser,
			CephImage:      cephImage,
			PublicNetwork:  publicNetwork,
			ClusterNetwork: clusterNetwork,
			OSDDevices:     osdDevices,
			SkipVerify:     skipVerify,
			SaltOnly:       saltOnly,
			TerraformOnly:  terraformOnly,
		}

		// Orchestrate deployment phases
		if !config.TerraformOnly {
			logger.Info("Phase 1: SaltStack configuration generation")
			if err := cephfs.GenerateSaltStackConfig(rc, config); err != nil {
				logger.Error("SaltStack configuration generation failed", zap.Error(err))
				return err
			}
		}

		if !config.SaltOnly {
			logger.Info("Phase 2: Terraform infrastructure deployment")
			if err := cephfs.DeployTerraform(rc, config); err != nil {
				logger.Error("Terraform deployment failed", zap.Error(err))
				return err
			}
		}

		if !config.SkipVerify && !config.SaltOnly {
			logger.Info("Phase 3: CephFS cluster verification")
			if err := cephfs.VerifyCluster(rc, config); err != nil {
				logger.Error("CephFS cluster verification failed", zap.Error(err))
				return err
			}
		}

		logger.Info("CephFS deployment completed successfully")
		return nil
	}),
}

func init() {
	// Core deployment configuration
	cephfsCmd.Flags().String("cluster-fsid", "", "Ceph cluster FSID (UUID format, generated if not provided)")
	cephfsCmd.Flags().String("admin-host", "", "Admin host for cephadm operations (required)")
	cephfsCmd.Flags().String("ssh-user", "root", "SSH user for remote operations")
	cephfsCmd.Flags().String("ceph-image", "quay.io/ceph/ceph:v18.2.1", "Ceph container image to use")
	
	// Network configuration
	cephfsCmd.Flags().String("public-network", "", "Public network CIDR (e.g., 10.0.0.0/24)")
	cephfsCmd.Flags().String("cluster-network", "", "Cluster network CIDR (e.g., 10.1.0.0/24)")
	
	// Storage configuration
	cephfsCmd.Flags().StringSlice("osd-devices", []string{}, "Specific OSD devices to use (defaults to all available)")
	
	// Control flags
	cephfsCmd.Flags().Bool("skip-verify", false, "Skip cluster health verification")
	cephfsCmd.Flags().Bool("salt-only", false, "Only generate SaltStack configuration, don't deploy")
	cephfsCmd.Flags().Bool("terraform-only", false, "Only run Terraform deployment, skip SaltStack generation")

	// Mark required flags
	cephfsCmd.MarkFlagRequired("admin-host")
	cephfsCmd.MarkFlagRequired("public-network")
	cephfsCmd.MarkFlagRequired("cluster-network")

	// Register with parent command
	CreateCmd.AddCommand(cephfsCmd)
}