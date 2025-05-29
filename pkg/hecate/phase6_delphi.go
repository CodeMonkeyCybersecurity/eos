// pkg/hecate/phase6_delphi.go

package hecate

import (
	"bufio"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SetupWazuhWizard prompts the user for Wazuh setup info and returns a ServiceBundle.
func SetupWazuhWizard(rc *eos_io.RuntimeContext, reader *bufio.Reader) ServiceBundle {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("🔧 Collecting Wazuh setup information...")

	// Define the fields to prompt for.
	fields := []PromptField{
		{
			Prompt:  "Enter Wazuh domain (e.g., delphi.domain.com)",
			Default: "delphi.domain.com",
			EnvVar:  "WazuhDomain",
			Reader:  reader,
		},
		{
			Prompt:  "Enter backend IP address for Wazuh (e.g., 192.168.0.10)",
			Default: "127.0.0.1",
			EnvVar:  "BackendIP",
			Reader:  reader,
		},
	}

	// Prepare Caddy reverse proxy info
	caddyProxy := &CaddyAppProxy{
		AppName:     "wazuh",
		Domain:      "<WazuhDomain>", // Template var, resolved during rendering
		BackendIP:   "<BackendIP>",   // Template var, resolved during rendering
		BackendPort: "443",
	}

	// Prepare NGINX spec
	nginxSpec := &NginxSpec{
		StreamBlocks: shared.WazuhStreamBlocks,
		PortsTCP:     []string{"1515", "1514", "55000"},
		PortsUDP:     []string{"1514"},
	}

	// Build the ServiceBundle using GenericWizard.
	return GenericWizard(
		rc,
		"hecate-wazuh-setup",
		fields,
		"wazuh",
		DockerNginxService,
		caddyProxy,
		nginxSpec,
		nil,                               // depends_on (can add if needed)
		nil,                               // volumes (Wazuh doesn't mount anything special here)
		[]string{"1515", "1514", "55000"}, // expose ports in Compose
	)
}

// SetupWazuh performs the full setup: renders Compose, Caddy, and Nginx fragments.
func SetupWazuh(rc *eos_io.RuntimeContext, bundle ServiceBundle, targetDir string) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info("🚀 Starting Wazuh setup rendering...")

	err := RenderBundleFragments(
		rc,
		bundle,
		fmt.Sprintf("%s/docker-compose.override.yml", targetDir),
		fmt.Sprintf("%s/Caddy-fragments", targetDir),
		fmt.Sprintf("%s/conf.d/stream", targetDir),
		"wazuh",
	)
	if err != nil {
		log.Error("❌ Failed to render Wazuh service", zap.Error(err))
		return err
	}

	log.Info("✅ Wazuh setup rendered successfully!")
	return nil
}
