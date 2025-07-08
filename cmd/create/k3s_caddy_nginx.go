// cmd/create/k3s_caddy_nginx.go

package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kubernetes"
	"github.com/spf13/cobra"
)

var k3sCaddyNginxCmd = &cobra.Command{
	Use:   "k3s-caddy-nginx",
	Short: "Deploy K3s with Caddy (HTTP/HTTPS) and Nginx (mail) instead of Traefik",
	Long: `Deploy K3s cluster with Caddy as HTTP/HTTPS ingress controller and Nginx as mail proxy.
This replaces the default Traefik ingress with a familiar Caddy + Nginx setup.

Features:
- K3s without Traefik
- Caddy for HTTP/HTTPS with automatic SSL
- Nginx for mail proxy (SMTP/IMAP/POP3)
- MetalLB for LoadBalancer services
- Cloud deployment support (Hetzner)`,
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
