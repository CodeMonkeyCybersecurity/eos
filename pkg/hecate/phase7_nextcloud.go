// pkg/hecate/phase7_nextcloud.go

package hecate

import (
	"bufio"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"go.uber.org/zap"
)

// SetupNextcloudWizard prompts the user for Nextcloud setup info and returns a ServiceBundle.
func SetupNextcloudWizard(reader *bufio.Reader) ServiceBundle {
	log := zap.L().Named("hecate-nextcloud-setup")
	log.Info("🔧 Collecting Nextcloud setup information...")

	// Ask for Coturn secret
	coturnAuthSecret := interaction.PromptInputWithReader("Enter Coturn auth secret (for TURN server)", "changeme", reader)

	// Ask for Nextcloud domain + backend IP
	nextcloudDomain := interaction.PromptInputWithReader("Enter Nextcloud domain (e.g., nextcloud.domain.com)", "nextcloud.domain.com", reader)
	backendIP := interaction.PromptInputWithReader("Enter backend IP address for Nextcloud (e.g., 192.168.0.10)", "", reader)

	// ==== Compose ====
	composeSpec := &ServiceSpec{
		Name:            "coturn",
		FullServiceYAML: DockerCoturnService,
		Environment: map[string]string{
			"CoturnAuthSecret": coturnAuthSecret,
		},
	}

	// ==== Caddy ====
	caddySpec := &CaddySpec{
		Proxies: []CaddyAppProxy{
			{
				AppName:     "nextcloud",
				Domain:      nextcloudDomain,
				BackendIP:   backendIP,
				BackendPort: "80",
			},
		},
	}

	log.Info("✅ Nextcloud (Coturn) ServiceBundle prepared")
	compose := &ComposeSpec{
		Services: map[string]*ServiceSpec{
			"nextcloud": composeSpec,
		},
	}

	return ServiceBundle{
		Compose: compose,
		Caddy:   caddySpec,
	}
}

// SetupNextcloudCompose builds and returns the DockerComposeFragment for Coturn (Nextcloud).
func SetupNextcloudCompose(config DockerConfig) (DockerComposeFragment, error) {
	log := zap.L().Named("hecate-nextcloud-compose-setup")
	log.Info("🔧 Building Docker Compose fragment for Coturn (Nextcloud)...")

	// Render the template using the passed-in DockerConfig
	rendered, err := renderTemplateFromString(DockerCoturnService, config)
	if err != nil {
		log.Error("Failed to render Docker Compose fragment for Coturn", zap.Error(err))
		return DockerComposeFragment{}, fmt.Errorf("failed to render Coturn Docker Compose: %w", err)
	}

	log.Info("✅ Docker Compose fragment for Coturn rendered successfully")
	return DockerComposeFragment{
		ServiceYAML: rendered,
	}, nil
}

// RenderNextcloudCompose renders and writes the Coturn Docker Compose fragment.
func RenderNextcloudCompose(bundle ServiceBundle) error {
	log := zap.L().Named("hecate-nextcloud-compose-render")
	for serviceName, svc := range bundle.Compose.Services {
		log.Info("🔧 Rendering service", zap.String("service", serviceName))

		rendered, err := renderTemplateFromString(svc.FullServiceYAML, svc.Environment)
		if err != nil {
			log.Error("Failed to render service", zap.Error(err),
				zap.String("service", serviceName),
			)
			return fmt.Errorf("failed to render service %s: %w", serviceName, err)
		}

		dockerComposePath := "./docker-compose.override.yml"
		err = appendToFile(dockerComposePath, rendered)
		if err != nil {
			log.Error("Failed to write Docker Compose block", zap.Error(err),
				zap.String("path", dockerComposePath),
				zap.String("service", serviceName),
			)
			return fmt.Errorf("failed to write Docker Compose for service %s: %w", serviceName, err)
		}
	}

	log.Info("✅ All Coturn (Nextcloud) Docker Compose blocks written successfully")
	return nil
}

// SetupNextcloudCaddy prompts for domain + backend info and returns a CaddyConfig fragment.
func SetupNextcloudCaddy(reader *bufio.Reader) CaddyConfig {
	log := zap.L().Named("hecate-nextcloud-caddy-setup")
	log.Info("🔧 Collecting Nextcloud Caddy reverse proxy setup information...")

	nextcloudDomain := interaction.PromptInputWithReader("Enter Nextcloud domain (e.g., nextcloud.domain.com)", "nextcloud.domain.com", reader)
	backendIP := interaction.PromptInputWithReader("Enter backend IP address for Nextcloud (e.g., 192.168.0.10)", "", reader)

	caddyCfg := CaddyConfig{
		Proxies: []CaddyAppProxy{
			{
				AppName:     "nextcloud",
				Domain:      nextcloudDomain,
				BackendIP:   backendIP,
				BackendPort: "80", // Assuming Nextcloud runs on port 80 inside Docker
			},
		},
	}

	log.Info("✅ Nextcloud Caddy config fragment prepared",
		zap.String("domain", nextcloudDomain),
		zap.String("backend_ip", backendIP),
	)

	return caddyCfg
}

// RenderNextcloudCaddy renders and writes the Caddyfile block for Nextcloud.
func RenderNextcloudCaddy(bundle ServiceBundle) error {
	log := zap.L().Named("hecate-nextcloud-caddy-render")
	log.Info("🔧 Rendering Nextcloud Caddyfile fragment...")

	caddyCfg := CaddyConfig{
		Proxies: bundle.Caddy.Proxies,
	}

	content, err := RenderCaddyfileContent(caddyCfg)
	if err != nil {
		log.Error("Failed to render Nextcloud Caddyfile content", zap.Error(err))
		return fmt.Errorf("failed to render Nextcloud Caddyfile: %w", err)
	}

	targetDir := "./Caddy-fragments"
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		log.Error("Failed to create Caddy fragments directory", zap.Error(err))
		return fmt.Errorf("failed to create Caddy fragments directory: %w", err)
	}

	filePath := fmt.Sprintf("%s/%s.caddy", targetDir, "nextcloud")
	err = os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		log.Error("Failed to write Nextcloud Caddy fragment", zap.Error(err),
			zap.String("path", filePath),
		)
		return fmt.Errorf("failed to write Nextcloud Caddy block: %w", err)
	}

	log.Info("📝 Nextcloud Caddy block written successfully",
		zap.String("path", filePath),
	)
	return nil
}
