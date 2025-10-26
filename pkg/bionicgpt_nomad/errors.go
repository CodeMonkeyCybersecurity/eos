// Package bionicgpt_nomad provides contextual error messages for BionicGPT deployment
// Following Eos P0 philosophy: Human-centric - explain complexity clearly
//
// Philosophy: Teach users about the system rather than hide complexity.
// Good error messages help users understand WHAT, WHY, and HOW.
package bionicgpt_nomad

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
)

// GenerateMissingConfigError creates a helpful error message when required configuration is missing
// Pattern: Explain what's missing, why it's needed, how to provide it
//
// This teaches users about the system architecture rather than hiding it.
func GenerateMissingConfigError(missingFlags []string) error {
	var msg strings.Builder

	msg.WriteString("BionicGPT deployment requires configuration\n\n")
	msg.WriteString("BionicGPT is an enterprise multi-tenant LLM platform that integrates with:\n")
	msg.WriteString("  • Authentik (SSO authentication)\n")
	msg.WriteString("  • Hecate (reverse proxy)\n")
	msg.WriteString("  • Nomad (orchestration)\n")
	msg.WriteString("  • Consul (service discovery)\n")
	msg.WriteString("\n")

	msg.WriteString("════════════════════════════════════════════════════════════════\n")
	msg.WriteString("Required Configuration\n")
	msg.WriteString("════════════════════════════════════════════════════════════════\n")
	msg.WriteString("\n")

	// Explain each missing flag with context
	flagNum := 1
	for _, flag := range missingFlags {
		switch flag {
		case "domain":
			msg.WriteString(fmt.Sprintf("%d. PUBLIC DOMAIN (--domain)\n", flagNum))
			msg.WriteString("\n")
			msg.WriteString("   What: The public URL where users access BionicGPT\n")
			msg.WriteString("   Example: chat.example.com\n")
			msg.WriteString("\n")
			msg.WriteString("   Why needed:\n")
			msg.WriteString("     • Users navigate to this domain to use the chat interface\n")
			msg.WriteString("     • Caddy (via Hecate) routes requests to BionicGPT\n")
			msg.WriteString("     • TLS certificates are issued for this domain\n")
			msg.WriteString("\n")
			msg.WriteString("   Prerequisites:\n")
			msg.WriteString("     • You control this domain\n")
			msg.WriteString("     • DNS A/AAAA record points to your cloud node\n")
			msg.WriteString("     • Hecate is configured to handle this domain\n")
			msg.WriteString("\n")
			flagNum++

		case "cloud-node":
			msg.WriteString(fmt.Sprintf("%d. CLOUD NODE (--cloud-node)\n", flagNum))
			msg.WriteString("\n")
			msg.WriteString("   What: Tailscale hostname where Hecate and Authentik run\n")
			msg.WriteString("   Example: cloud-hecate\n")
			msg.WriteString("\n")
			msg.WriteString("   Why needed:\n")
			msg.WriteString("     • BionicGPT connects to Authentik for SSO\n")
			msg.WriteString("     • Hecate reverse proxy routes public traffic\n")
			msg.WriteString("     • Consul WAN federation links local and cloud\n")
			msg.WriteString("\n")
			msg.WriteString("   How to find:\n")
			if hostname, err := os.Hostname(); err == nil {
				msg.WriteString(fmt.Sprintf("     • Current node: %s\n", hostname))
			}
			msg.WriteString("     • List Tailscale nodes: tailscale status\n")
			msg.WriteString("     • Check Consul members: consul members -wan\n")
			msg.WriteString("\n")
			flagNum++

		case "auth-url":
			msg.WriteString(fmt.Sprintf("%d. AUTHENTIK URL (--auth-url)\n", flagNum))
			msg.WriteString("\n")
			msg.WriteString("   What: Public URL of your Authentik SSO server\n")
			msg.WriteString("   Example: https://auth.example.com\n")
			msg.WriteString("\n")
			msg.WriteString("   Why needed:\n")
			msg.WriteString("     • BionicGPT uses OAuth2/OIDC for authentication\n")
			msg.WriteString("     • Users log in via Authentik SSO\n")
			msg.WriteString("     • Multi-tenancy based on Authentik groups\n")
			msg.WriteString("\n")
			msg.WriteString("   How to find:\n")
			msg.WriteString("     • Check if Authentik is deployed: eos list services\n")
			msg.WriteString("     • Check Consul catalog: consul catalog services | grep authentik\n")
			msg.WriteString("     • Check Hecate routes: eos read hecate-route\n")
			msg.WriteString("\n")
			msg.WriteString("   If Authentik is not deployed:\n")
			msg.WriteString("     • Deploy Hecate (includes Authentik): eos create hecate\n")
			msg.WriteString("\n")
			flagNum++
		}
	}

	msg.WriteString("════════════════════════════════════════════════════════════════\n")
	msg.WriteString("How to Provide Configuration\n")
	msg.WriteString("════════════════════════════════════════════════════════════════\n")
	msg.WriteString("\n")

	// Show example command with PLACEHOLDERS (not copy-pasteable literal values)
	msg.WriteString("Provide flags:\n")
	msg.WriteString("\n")
	msg.WriteString("  eos create bionicgpt \\\n")
	msg.WriteString("    --domain YOUR_DOMAIN \\\n")
	msg.WriteString("    --cloud-node YOUR_CLOUD_NODE \\\n")
	msg.WriteString("    --auth-url YOUR_AUTHENTIK_URL\n")
	msg.WriteString("\n")
	msg.WriteString("Example:\n")
	msg.WriteString("\n")
	msg.WriteString("  eos create bionicgpt \\\n")
	msg.WriteString("    --domain chat.example.com \\\n")
	msg.WriteString("    --cloud-node cloud-hecate \\\n")
	msg.WriteString("    --auth-url https://auth.example.com\n")
	msg.WriteString("\n")

	msg.WriteString("════════════════════════════════════════════════════════════════\n")
	msg.WriteString("Troubleshooting\n")
	msg.WriteString("════════════════════════════════════════════════════════════════\n")
	msg.WriteString("\n")

	msg.WriteString("Check what's deployed:\n")
	msg.WriteString("  eos list services                    # List all Eos services\n")
	msg.WriteString("  consul catalog services              # List Consul services\n")
	msg.WriteString("  tailscale status                     # List Tailscale nodes\n")
	msg.WriteString("\n")

	msg.WriteString("Check Hecate configuration:\n")
	msg.WriteString("  eos read hecate                      # Hecate status\n")
	msg.WriteString("  eos list hecate-routes               # List configured routes\n")
	msg.WriteString("\n")

	msg.WriteString("Deployment guide:\n")
	msg.WriteString("  eos create bionicgpt --help          # Full documentation\n")
	msg.WriteString("\n")

	return eos_err.NewUserError("%s", msg.String())
}

// GenerateMissingConfigErrorShort creates a concise error message for missing configuration
// Pattern: Brief explanation + example + pointer to --help for full details
func GenerateMissingConfigErrorShort(missingFlags []string) error {
	var msg strings.Builder

	msg.WriteString("BionicGPT deployment requires configuration\n\n")
	msg.WriteString("Missing required flags:\n")
	for _, flag := range missingFlags {
		msg.WriteString(fmt.Sprintf("  --%-12s  ", flag))
		switch flag {
		case "domain":
			msg.WriteString("Public domain (e.g., chat.example.com)\n")
		case "cloud-node":
			msg.WriteString("Cloud node hostname (Tailscale name)\n")
		case "auth-url":
			msg.WriteString("Authentik URL (e.g., https://auth.example.com)\n")
		}
	}
	msg.WriteString("\nExample:\n")
	msg.WriteString("  eos create bionicgpt \\\n")
	msg.WriteString("    --domain chat.example.com \\\n")
	msg.WriteString("    --cloud-node cloud-hecate \\\n")
	msg.WriteString("    --auth-url https://auth.example.com\n\n")
	msg.WriteString("For detailed explanations of each flag, run:\n")
	msg.WriteString("  eos create bionicgpt --help\n")

	return eos_err.NewUserError("%s", msg.String())
}

// ValidateRequiredFlags checks if required configuration flags are provided
// Returns user-friendly error if any are missing
func ValidateRequiredFlags(config *EnterpriseConfig) error {
	var missingFlags []string

	if config.Domain == "" {
		missingFlags = append(missingFlags, "domain")
	}
	if config.CloudNode == "" {
		missingFlags = append(missingFlags, "cloud-node")
	}
	if config.AuthURL == "" {
		missingFlags = append(missingFlags, "auth-url")
	}

	if len(missingFlags) > 0 {
		return GenerateMissingConfigErrorShort(missingFlags)
	}

	return nil
}

// GenerateDeploymentSummary creates a post-deployment message with next steps
// Used for successful deployments to guide users on what to do next
func GenerateDeploymentSummary(config *EnterpriseConfig, healthy bool) string {
	var msg strings.Builder

	msg.WriteString("\n")
	msg.WriteString("════════════════════════════════════════════════════════════════\n")

	if healthy {
		msg.WriteString("✓ BionicGPT Deployment Successful\n")
	} else {
		msg.WriteString("⚠ BionicGPT Deployment Completed with Warnings\n")
	}

	msg.WriteString("════════════════════════════════════════════════════════════════\n")
	msg.WriteString("\n")

	msg.WriteString("Access:\n")
	msg.WriteString(fmt.Sprintf("  URL: https://%s\n", config.Domain))
	msg.WriteString(fmt.Sprintf("  SSO: %s\n", config.AuthURL))
	msg.WriteString("\n")

	if healthy {
		msg.WriteString("Next Steps:\n")
		msg.WriteString("\n")
		msg.WriteString("1. Log in via Authentik SSO\n")
		msg.WriteString("   • Navigate to the URL above\n")
		msg.WriteString("   • Click \"Sign in with SSO\"\n")
		msg.WriteString("   • Use your Authentik credentials\n")
		msg.WriteString("\n")
		msg.WriteString("2. Configure user access in Authentik\n")
		msg.WriteString(fmt.Sprintf("   • Superadmins: Add users to '%s' group\n", config.SuperadminGroup))
		msg.WriteString(fmt.Sprintf("   • Demo users: Add users to '%s' group\n", config.DemoGroup))
		msg.WriteString("\n")
		msg.WriteString("3. Upload documents for RAG\n")
		msg.WriteString("   • Go to Documents section in BionicGPT UI\n")
		msg.WriteString("   • Upload PDFs, text files, or documents\n")
		msg.WriteString("   • Documents are automatically processed and indexed\n")
		msg.WriteString("\n")
		msg.WriteString("4. Start chatting with your LLM\n")
		msg.WriteString("   • Create a new conversation\n")
		msg.WriteString("   • Ask questions about your uploaded documents\n")
		msg.WriteString("\n")
	} else {
		msg.WriteString("Troubleshooting:\n")
		msg.WriteString("\n")
		msg.WriteString("Check deployment status:\n")
		msg.WriteString("  nomad job status bionicgpt           # Check Nomad job status\n")
		msg.WriteString("  nomad alloc logs <ALLOC_ID>          # View container logs\n")
		msg.WriteString("  eos debug bionicgpt                  # Run comprehensive diagnostics\n")
		msg.WriteString("\n")
		msg.WriteString("Check service health:\n")
		msg.WriteString("  consul catalog services | grep bionicgpt\n")
		msg.WriteString("  tailscale ping " + config.CloudNode + "\n")
		msg.WriteString("\n")
	}

	msg.WriteString("Useful Commands:\n")
	msg.WriteString("  eos read bionicgpt                   # Check deployment status\n")
	msg.WriteString("  eos debug bionicgpt                  # Run diagnostics\n")
	msg.WriteString("  nomad job deployments bionicgpt      # Check health checks\n")
	msg.WriteString("\n")

	return msg.String()
}
