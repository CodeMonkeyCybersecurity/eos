// cmd/create/k3s_caddy_nginx.go

package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kubernetes"
	"github.com/spf13/cobra"
)

var k3sCaddyNginxCmd = &cobra.Command{
	Use:        "k3s-caddy-nginx",
	Short:      "Deploy K3s with Caddy and Nginx (DEPRECATED - use 'nomad-ingress' instead)",
	Deprecated: "K3s support is deprecated. Use 'eos create nomad-ingress' for ingress instead.",
	Long: `DEPRECATED: This command is deprecated and will be removed in a future version.
Use 'eos create nomad-ingress' for ingress instead.

K3s has been replaced with HashiCorp Nomad. The equivalent functionality is now available as:

Migration:
  # Instead of: eos create k3s-caddy-nginx --domain=example.com
  # Use:        eos create nomad-ingress --domain=example.com --enable-mail

The Nomad-based ingress provides the same Caddy + Nginx functionality but with
simpler deployment and better resource efficiency.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return kubernetes.GenerateK3sCaddyNginx(rc, cmd)
	}),
}

func init() {
	CreateCmd.AddCommand(k3sCaddyNginxCmd)

	k3sCaddyNginxCmd.Flags().String("output-dir", "./k3s-caddy-nginx", "Output directory for Terraform files")
	k3sCaddyNginxCmd.Flags().Bool("cloud", false, "Deploy to cloud infrastructure (Hetzner)")
	k3sCaddyNginxCmd.Flags().String("domain", "", "Primary domain for the cluster")
	k3sCaddyNginxCmd.Flags().String("cluster-name", "k3s-cluster", "Name for the K3s cluster")
	k3sCaddyNginxCmd.Flags().String("server-type", "cx21", "Server type for cloud instance")
	k3sCaddyNginxCmd.Flags().String("location", "nbg1", "Location for cloud instance")
	k3sCaddyNginxCmd.Flags().Bool("enable-mail", false, "Include Nginx mail proxy configuration")
}
