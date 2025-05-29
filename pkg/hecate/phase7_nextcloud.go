// pkg/hecate/phase7_nextcloud.go

package hecate

import (
	"bufio"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SetupNextcloudWizard prompts the user for Nextcloud + Coturn setup and returns a ServiceBundle.
func SetupNextcloudWizard(rc *eos_io.RuntimeContext, reader *bufio.Reader) ServiceBundle {
	log := otelzap.Ctx(rc.Ctx)
	log.Info("🔧 Collecting Nextcloud + Coturn setup information...")

	// Define the prompts
	fields := []PromptField{
		{
			Prompt:  "Enter Coturn auth secret (for TURN server)",
			Default: "changeme",
			EnvVar:  "CoturnAuthSecret",
			Reader:  reader,
		},
		{
			Prompt:  "Enter Nextcloud domain (e.g., nextcloud.domain.com)",
			Default: "nextcloud.domain.com",
			EnvVar:  "NextcloudDomain",
			Reader:  reader,
		},
		{
			Prompt:  "Enter backend IP address for Nextcloud (e.g., 192.168.0.10)",
			Default: "127.0.0.1",
			EnvVar:  "BackendIP",
			Reader:  reader,
		},
	}

	// Prepare Caddy reverse proxy info
	caddyProxy := &CaddyAppProxy{
		AppName:     "nextcloud",
		Domain:      "<NextcloudDomain>", // Template var, resolved later
		BackendIP:   "<BackendIP>",       // Template var, resolved later
		BackendPort: "80",                // Default Nextcloud Docker port
	}

	// No NGINX stream blocks required for Nextcloud/Coturn in this example
	nginxSpec := (*NginxSpec)(nil)

	return GenericWizard(
		rc,
		"hecate-nextcloud-setup",
		fields,
		"coturn",
		DockerCoturnService,
		caddyProxy,
		nginxSpec,
		nil, // depends_on
		nil, // volumes
		nil, // ports
	)
}

// SetupNextcloud performs the full setup: renders Compose + Caddy fragments.
func SetupNextcloud(rc *eos_io.RuntimeContext, bundle ServiceBundle, targetDir string) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info("🚀 Starting Nextcloud + Coturn setup rendering...")

	err := RenderBundleFragments(
		rc,
		bundle,
		fmt.Sprintf("%s/docker-compose.override.yml", targetDir),
		fmt.Sprintf("%s/Caddy-fragments", targetDir),
		"", // No Nginx directory (no Nginx spec here)
		"nextcloud",
	)
	if err != nil {
		log.Error("❌ Failed to render Nextcloud service", zap.Error(err))
		return err
	}

	log.Info("✅ Nextcloud setup rendered successfully!")
	return nil
}
