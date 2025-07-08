// cmd/create/k3s.go
package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kubernetes"
	// "github.com/CodeMonkeyCybersecurity/eos/pkg/container" // TODO: Uncomment when KubernetesInstallOptions is implemented
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"

	"github.com/spf13/cobra"
)

// k3sCmd is the subcommand for deploying K3s.
var CreateK3sCmd = &cobra.Command{
	Use:   "k3s",
	Short: "Deploy K3s on a server or worker node",
	Long: `Deploy K3s on a node with interactive prompts.
For server nodes, you'll be prompted for the TLS SAN.
For worker nodes, you'll be prompted for the server URL and node token.
Additional checks for IPv6 and Tailscale are performed.
The generated install command is previewed and saved to a script file
for safe, human-approved execution.

Use --terraform flag to generate Terraform configuration instead of direct installation.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		useTerraform, _ := cmd.Flags().GetBool("terraform")
		if useTerraform {
			return kubernetes.GenerateK3sTerraform(rc, cmd)
		}
		kubernetes.DeployK3s(rc)
		return nil
	}),
}

var k3sTerraformCmd = &cobra.Command{
	Use:   "k3s-terraform",
	Short: "Generate Terraform configuration for K3s deployment",
	Long: `Generate Terraform configuration for K3s deployment on cloud infrastructure.
Supports Hetzner Cloud provider with automated server provisioning and K3s installation.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return kubernetes.GenerateK3sTerraform(rc, cmd)
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
