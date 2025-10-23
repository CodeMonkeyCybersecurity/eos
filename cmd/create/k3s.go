// cmd/create/k3s.go
package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kubernetes"
	// "github.com/CodeMonkeyCybersecurity/eos/pkg/container" // TODO: Uncomment when KubernetesInstallOptions is implemented
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	"github.com/spf13/cobra"
)

// DEPRECATED: K3s support is deprecated. Use Nomad instead.
// k3sCmd is the subcommand for deploying K3s.
var CreateK3sCmd = &cobra.Command{
	Use:        "k3s",
	Short:      "Deploy K3s on a server or worker node (DEPRECATED - use 'nomad' instead)",
	Deprecated: "K3s support is deprecated. Use 'eos create nomad' for container orchestration instead.",
	Long: `DEPRECATED: This command is deprecated and will be removed in a future version.
Use 'eos create nomad' for container orchestration instead.

K3s has been replaced with HashiCorp Nomad for simpler container orchestration.
Nomad provides the same capabilities as K3s but with lower overhead and easier management.

Migration:
  # Instead of: eos create k3s
  # Use:        eos create nomad

  # Migrate existing K3s cluster:
  eos create migrate-k3s --domain=your-domain.com

For Terraform-based deployment, use:
  eos create nomad-terraform --domain=your-domain.com`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Display prominent deprecation warning
		logger.Warn("═══════════════════════════════════════════════════════════")
		logger.Warn("  DEPRECATION WARNING: K3s support is being removed")
		logger.Warn("═══════════════════════════════════════════════════════════")
		logger.Warn("K3s has been replaced with HashiCorp Nomad for container orchestration.")
		logger.Warn("")
		logger.Warn("Recommended actions:")
		logger.Warn("  • New deployments: Use 'eos create nomad' instead")
		logger.Warn("  • Existing clusters: Migrate with 'eos create migrate-k3s --domain=your-domain.com'")
		logger.Warn("")
		logger.Warn("This command will be removed in Eos v2.0.0 (approximately 6 months)")
		logger.Warn("═══════════════════════════════════════════════════════════")
		logger.Warn("")

		useTerraform, _ := cmd.Flags().GetBool("terraform")
		if useTerraform {
			return kubernetes.GenerateK3sTerraform(rc, cmd)
		}
		kubernetes.DeployK3s(rc)
		return nil
	}),
}


var CreateKubeadmCmd = &cobra.Command{
	Use:   "kubeadm",
	Short: "Install Kubernetes using kubeadm",
	Long: `Install and configure Kubernetes using kubeadm.
This command will:
- Install prerequisites and Kubernetes packages
- Configure firewall settings
- Disable swap (required for Kubernetes)
- Initialize the cluster
- Configure kubectl for the current user

Requires root privileges (sudo).

Examples:
  sudo eos create kubeadm
  sudo eos create kubeadm --control-plane-endpoint=192.168.1.100:6443
  sudo eos create kubeadm --pod-network-cidr=10.244.0.0/16`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return kubernetes.RunCreateKubeadm(rc, cmd, args)
	}),
}
