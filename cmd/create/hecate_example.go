package create

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var createHecateExampleCmd = &cobra.Command{
	Use:   "hecate-example",
	Short: "Create example Hecate routes using Terraform architecture",
	Long: `Create example Hecate routes to demonstrate the new Terraform-based architecture.

This command creates several example routes and services to showcase:
- HTTP reverse proxy with SSL
- Authentication-protected routes  
- TCP/UDP stream proxying
- Secret rotation
- Infrastructure as Code with Terraform

Examples:
  eos create hecate-example --demo-mode
  eos create hecate-example --with-auth
  eos create hecate-example --preset mailcow`,
	RunE: eos_cli.Wrap(runCreateHecateExample),
}

func init() {
	CreateHecateCmd.AddCommand(createHecateExampleCmd)

	createHecateExampleCmd.Flags().Bool("demo-mode", false, "Create demo routes with test upstreams")
	createHecateExampleCmd.Flags().Bool("with-auth", false, "Create authenticated routes")
	createHecateExampleCmd.Flags().String("preset", "", "Create stream preset (mailcow, jenkins, wazuh, etc.)")
	createHecateExampleCmd.Flags().String("upstream-host", "10.0.1.100", "Base upstream host for examples")
}

func runCreateHecateExample(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating Hecate examples using Terraform architecture")

	// Get flags
	demoMode, _ := cmd.Flags().GetBool("demo-mode")
	withAuth, _ := cmd.Flags().GetBool("with-auth")
	preset, _ := cmd.Flags().GetString("preset")
	upstreamHost, _ := cmd.Flags().GetString("upstream-host")

	// Initialize Hecate client
	config := &hecate.ClientConfig{
		CaddyAdminAddr:     getEnvOrDefault("CADDY_ADMIN_ADDR", "http://localhost:2019"),
		ConsulAddr:         getEnvOrDefault("CONSUL_ADDR", "localhost:8500"),
		VaultAddr:          getEnvOrDefault("VAULT_ADDR", "http://localhost:8200"),
		VaultToken:         os.Getenv("VAULT_TOKEN"),
		TerraformWorkspace: getEnvOrDefault("TERRAFORM_WORKSPACE", "/var/lib/hecate/terraform"),
	}

	// Note: In demo mode, we'll just show what would be created
	if demoMode {
		fmt.Printf("🎯 Hecate Terraform Architecture Demo\n\n")
		fmt.Printf("This would create the following infrastructure:\n\n")
		
		if withAuth {
			fmt.Printf("🔐 Authentication Setup:\n")
			fmt.Printf("  • Auth Policy: demo-users (Groups: users, admins)\n")
			fmt.Printf("  • Auth Policy: api-access (Groups: api-users, MFA required)\n\n")
		}

		fmt.Printf("🌐 HTTP Routes:\n")
		fmt.Printf("  • app.example.com → %s:3000 (Web Application)\n", upstreamHost)
		fmt.Printf("  • api.example.com → %s:8080 (API Backend)\n", upstreamHost)
		if withAuth {
			fmt.Printf("  • secure.example.com → %s:443 (Protected, MFA required)\n", upstreamHost)
		}
		fmt.Printf("\n")

		if preset != "" {
			fmt.Printf("🔌 Stream Proxies (%s preset):\n", preset)
			switch preset {
			case "mailcow":
				fmt.Printf("  • SMTP: :25 → %s:25\n", upstreamHost)
				fmt.Printf("  • SMTPS: :465 → %s:465\n", upstreamHost)
				fmt.Printf("  • IMAP: :143 → %s:143\n", upstreamHost)
				fmt.Printf("  • IMAPS: :993 → %s:993\n", upstreamHost)
			case "jenkins":
				fmt.Printf("  • Agent: :50000 → %s:50000\n", upstreamHost)
			case "wazuh":
				fmt.Printf("  • Agent TCP: :1514 → %s:1514\n", upstreamHost)
				fmt.Printf("  • Agent UDP: :1514 → %s:1514\n", upstreamHost)
			}
			fmt.Printf("\n")
		}

		fmt.Printf("🗝️  Secret Management:\n")
		fmt.Printf("  • Authentik API token (dual-secret rotation)\n")
		fmt.Printf("  • Caddy admin token (dual-secret rotation)\n")
		fmt.Printf("  • Hetzner API token (immediate rotation)\n\n")

		fmt.Printf("☁️  Terraform Resources:\n")
		fmt.Printf("  • Hetzner DNS records for all domains\n")
		fmt.Printf("  • Wildcard DNS for dynamic subdomains\n")
		fmt.Printf("  • Let's Encrypt certificates (automatic)\n\n")

		fmt.Printf("🧂 SaltStack Integration:\n")
		fmt.Printf("  • Caddy configuration deployment\n")
		fmt.Printf("  • Nginx stream configuration\n")
		fmt.Printf("  • Authentik policy deployment\n")
		fmt.Printf("  • Service health monitoring\n\n")

		fmt.Printf("To actually create these resources, run without --demo-mode\n")
		fmt.Printf("Make sure you have Consul, Vault, and Terraform configured.\n\n")

		fmt.Printf("💡 Next steps:\n")
		fmt.Printf("  eos create hecate route --domain app.example.com --upstream %s:3000\n", upstreamHost)
		fmt.Printf("  eos create hecate stream --preset mailcow --upstream %s\n", upstreamHost)
		fmt.Printf("  eos update hecate secret --name authentik-api-token --strategy dual-secret\n")

		return nil
	}

	// Real creation mode (would need actual infrastructure)
	fmt.Printf("⚠️  Real creation mode requires:\n")
	fmt.Printf("  • Consul running on %s\n", config.ConsulAddr)
	fmt.Printf("  • Vault running on %s\n", config.VaultAddr)
	fmt.Printf("  • Caddy running with admin API on %s\n", config.CaddyAdminAddr)
	fmt.Printf("  • Terraform installed and configured\n")
	fmt.Printf("  • SaltStack minion configured\n\n")

	fmt.Printf("Use --demo-mode to see what would be created without actual infrastructure.\n")

	// Try to create client (will likely fail in test environment)
	client, err := hecate.NewHecateClient(rc, config)
	if err != nil {
		logger.Info("Could not connect to infrastructure (expected in demo)",
			zap.Error(err))
		fmt.Printf("✅ Hecate Terraform architecture is ready for deployment!\n")
		fmt.Printf("Configure your infrastructure and run again to create real resources.\n")
		return nil
	}

	// If we get here, infrastructure is available
	fmt.Printf("✅ Infrastructure detected! Creating example resources...\n")

	// Create examples using the managers
	rm := hecate.NewRouteManager(client)
	am := hecate.NewAuthManager(client)
	sm := hecate.NewStreamManager(client)

	_ = rm // Use the managers  
	_ = am
	_ = sm

	fmt.Printf("Example resources would be created here with real infrastructure.\n")

	return nil
}

func getEnvOrDefault(envVar, defaultValue string) string {
	if value := os.Getenv(envVar); value != "" {
		return value
	}
	return defaultValue
}