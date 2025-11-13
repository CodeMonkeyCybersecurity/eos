// pkg/bionicgpt_nomad/hecate.go - Phase 7: Hecate configuration

package bionicgpt_nomad

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConfigureHecate configures Hecate reverse proxy to route to BionicGPT
func (ei *EnterpriseInstaller) ConfigureHecate() error {
	logger := otelzap.Ctx(ei.rc.Ctx)

	logger.Info("Phase 7: Configuring Hecate reverse proxy")

	// Step 1: Get local Tailscale IP for oauth2-proxy backend
	logger.Info("  [1/3] Getting local node Tailscale IP")
	localIP, err := ei.getLocalTailscaleIP()
	if err != nil {
		return fmt.Errorf("failed to get local Tailscale IP: %w", err)
	}
	logger.Info("    Local IP", zap.String("ip", localIP))

	// Step 2: Get cloud node Tailscale IP for Caddy Admin API
	logger.Info("  [2/3] Connecting to Caddy Admin API on cloud node")
	cloudIP, err := ei.getTailscaleIP(ei.config.CloudNode)
	if err != nil {
		return fmt.Errorf("failed to get cloud node Tailscale IP: %w", err)
	}

	caddyClient := hecate.NewCaddyAdminClient(cloudIP)

	// Step 3: Generate and load Caddyfile
	logger.Info("  [3/3] Loading Caddyfile configuration")
	caddyfile, err := ei.generateCaddyfile(localIP)
	if err != nil {
		return fmt.Errorf("failed to generate Caddyfile: %w", err)
	}

	if err := caddyClient.LoadCaddyfile(ei.rc.Ctx, caddyfile); err != nil {
		return fmt.Errorf("failed to load Caddyfile via Admin API: %w", err)
	}

	logger.Info("    ✓ Caddyfile loaded successfully")
	logger.Info("✓ Hecate configuration complete")
	return nil
}

// generateCaddyfile generates a Caddyfile for routing to oauth2-proxy
func (ei *EnterpriseInstaller) generateCaddyfile(localIP string) (string, error) {
	// TODO: Use template rendering system
	// For now, generate inline
	caddyfile := fmt.Sprintf(`%s {
	# Forward authentication via oauth2-proxy on local node
	reverse_proxy http://%s:4180

	# Headers
	header {
		X-Frame-Options "SAMEORIGIN"
		X-Content-Type-Options "nosniff"
		X-XSS-Protection "1; mode=block"
		Referrer-Policy "strict-origin-when-cross-origin"
	}

	# Access logs
	log {
		output file /var/log/caddy/bionicgpt-access.log
		format json
	}
}`, ei.config.Domain, localIP)

	return caddyfile, nil
}
