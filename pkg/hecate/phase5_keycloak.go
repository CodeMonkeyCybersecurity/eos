//pkg/hecate/phase5_keycloak.go

package hecate

import (
	"bufio"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"go.uber.org/zap"
)

// SetupKeycloakWizard prompts the user for Keycloak setup info and returns a ServiceBundle.
func SetupKeycloakWizard(reader *bufio.Reader) ServiceBundle {
	log := zap.L().Named("hecate-keycloak-setup")
	log.Info("🔧 Collecting Keycloak setup information...")

	// === Prompt the user ===
	keycloakDomain := interaction.PromptInputWithReader("Enter Keycloak domain (e.g., hera.domain.com)", "hera.domain.com", reader)
	keycloakDBName := interaction.PromptInputWithReader("Enter Keycloak DB name", "keycloak", reader)
	keycloakDBUser := interaction.PromptInputWithReader("Enter Keycloak DB user", "keycloak", reader)
	keycloakDBPassword := interaction.PromptInputWithReader("Enter Keycloak DB password", "changeme", reader)
	keycloakAdminUser := interaction.PromptInputWithReader("Enter Keycloak admin user", "admin", reader)
	keycloakAdminPassword := interaction.PromptInputWithReader("Enter Keycloak admin password", "changeme", reader)

	// === Compose Spec ===
	serviceSpec := &ServiceSpec{
		Name:            "keycloak",
		FullServiceYAML: DockerKeycloakService, // Template will be rendered later
		Environment: map[string]string{
			"KeycloakDomain":        keycloakDomain,
			"KeycloakDBName":        keycloakDBName,
			"KeycloakDBUser":        keycloakDBUser,
			"KeycloakDBPassword":    keycloakDBPassword,
			"KeycloakAdminUser":     keycloakAdminUser,
			"KeycloakAdminPassword": keycloakAdminPassword,
		},
		DependsOn: []string{"kc-db"},
		Volumes:   []string{"kc-db-data:/var/lib/postgresql/data"},
	}
	composeSpec := &ComposeSpec{
		Services: map[string]*ServiceSpec{
			"keycloak": serviceSpec,
		},
	}

	// === Caddy Spec ===
	caddySpec := &CaddySpec{
		KeycloakDomain: keycloakDomain,
		Proxies:        []CaddyAppProxy{}, // No extra proxies for Keycloak (special case)
	}

	log.Info("✅ Keycloak ServiceBundle created")

	return ServiceBundle{
		Compose: composeSpec,
		Nginx:   nil, // No NGINX config needed for Keycloak
		Caddy:   caddySpec,
	}
}

// SetupKeycloakCompose handles creating the Docker Compose section for Keycloak.
func SetupKeycloakCompose(config DockerConfig) error {
	log := zap.L().Named("hecate-keycloak-compose")
	log.Info("🔧 Setting up Docker Compose config for Keycloak...",
		zap.String("domain", config.KeycloakDomain),
		zap.String("db_name", config.KeycloakDBName),
		zap.String("db_user", config.KeycloakDBUser),
	)

	// Placeholder: in the real implementation, you'd render and write the docker-compose.yml entry here.
	log.Info("📝 Would render Docker Compose block for Keycloak",
		zap.String("compose_service", "keycloak + kc-db with environment vars, volumes, and network setup"),
	)

	// TODO: Implement actual Docker Compose writing here if needed.
	return nil
}

// RenderKeycloakCompose renders and writes the Docker Compose block for Keycloak.
func RenderKeycloakCompose(bundle ServiceBundle) error {
	log := zap.L().Named("hecate-keycloak-compose-render")
	if bundle.Compose == nil || bundle.Compose.Services == nil {
		log.Warn("No Compose services found in bundle")
		return nil
	}

	for name, svc := range bundle.Compose.Services {
		log.Info("🔧 Rendering Docker Compose block for Keycloak service...",
			zap.String("service", name),
		)
		rendered, err := renderTemplateFromString(svc.FullServiceYAML, svc.Environment)
		if err != nil {
			log.Error("Failed to render Docker Compose content", zap.String("service", name), zap.Error(err))
			return err
		}
		dockerComposePath := "./docker-compose.override.yml"
		err = appendToFile(dockerComposePath, rendered)
		if err != nil {
			log.Error("Failed to write Docker Compose block", zap.String("service", name), zap.Error(err),
				zap.String("path", dockerComposePath),
			)
			return fmt.Errorf("failed to write Docker Compose: %w", err)
		}
		log.Info("📝 Docker Compose block written successfully",
			zap.String("service", name),
			zap.String("path", dockerComposePath),
		)
	}
	return nil
}

// SetupKeycloakCaddy handles creating the Caddy reverse proxy config for Keycloak.
func SetupKeycloakCaddy(config DockerConfig) error {
	log := zap.L().Named("hecate-keycloak-caddy")
	log.Info("🔧 Setting up Caddy config for Keycloak...",
		zap.String("domain", config.KeycloakDomain),
		zap.String("backend", "https://keycloak:8080"),
	)

	// Placeholder: in the real implementation, you'd render and write the Caddyfile entry here.
	// For now we just log what would happen.
	log.Info("📝 Would render Caddy config block:",
		zap.String("caddy_block", config.KeycloakDomain+" {\n\treverse_proxy https://keycloak:8080\n}"),
	)

	// TODO: Implement actual Caddyfile writing here if needed.
	return nil
}

// RenderKeycloakCaddy renders and writes the Caddyfile block for Keycloak.
func RenderKeycloakCaddy(bundle ServiceBundle) error {
	log := zap.L().Named("hecate-keycloak-caddy-render")

	caddyCfg := CaddyConfig{
		KeycloakDomain: bundle.Caddy.KeycloakDomain,
		Proxies:        bundle.Caddy.Proxies,
	}

	caddyContent, err := RenderCaddyfileContent(caddyCfg)
	if err != nil {
		log.Error("Failed to render Caddyfile content", zap.Error(err))
		return err
	}

	log.Info("✅ Caddyfile content rendered successfully")

	caddyfilePath := HecateCaddyfile
	err = os.WriteFile(caddyfilePath, []byte(caddyContent), 0644)
	if err != nil {
		log.Error("Failed to write Caddyfile", zap.Error(err),
			zap.String("path", caddyfilePath),
		)
		return fmt.Errorf("failed to write Caddyfile: %w", err)
	}

	log.Info("📝 Caddyfile written successfully",
		zap.String("path", caddyfilePath),
	)

	return nil
}
