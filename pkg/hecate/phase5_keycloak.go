// pkg/hecate/phase5_keycloak.go

package hecate

import (
	"bufio"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SetupKeycloakWizard prompts the user for Keycloak setup info and returns a ServiceBundle.
func SetupKeycloakWizard(rc *eos_io.RuntimeContext, reader *bufio.Reader) ServiceBundle {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Collecting Keycloak setup information...")

	// Define the fields to prompt for.
	fields := []PromptField{
		{
			Prompt:  "Enter Keycloak domain (e.g., hera.domain.com)",
			Default: "hera.domain.com",
			EnvVar:  "KeycloakDomain",
			Reader:  reader,
		},
		{
			Prompt:  "Enter Keycloak DB name",
			Default: "keycloak",
			EnvVar:  "KeycloakDBName",
			Reader:  reader,
		},
		{
			Prompt:  "Enter Keycloak DB user",
			Default: "keycloak",
			EnvVar:  "KeycloakDBUser",
			Reader:  reader,
		},
		{
			Prompt:  "Enter Keycloak DB password",
			Default: "changeme",
			EnvVar:  "KeycloakDBPassword",
			Reader:  reader,
		},
		{
			Prompt:  "Enter Keycloak admin user",
			Default: "admin",
			EnvVar:  "KeycloakAdminUser",
			Reader:  reader,
		},
		{
			Prompt:  "Enter Keycloak admin password",
			Default: "changeme",
			EnvVar:  "KeycloakAdminPassword",
			Reader:  reader,
		},
	}

	// Prepare Caddy reverse proxy info (using Docker service name internally)
	caddyProxy := &CaddyAppProxy{
		AppName:     "keycloak",
		Domain:      "<KeycloakDomain>", // Placeholder; will get interpolated during rendering
		BackendIP:   "keycloak",         // Docker service name for Keycloak container
		BackendPort: "8080",
	}

	// Build the ServiceBundle using GenericWizard.
	return GenericWizard(
		rc,
		"hecate-keycloak-setup",
		fields,
		"keycloak",
		DockerKeycloakService,
		caddyProxy,
		nil,               // No NGINX config needed for Keycloak
		[]string{"kc-db"}, // depends_on
		[]string{"kc-db-data:/var/lib/postgresql/data"}, // volumes
		nil, // ports (Keycloak is proxied)
	)
}

// SetupKeycloak performs the full setup: renders Compose, Caddy, etc.
func SetupKeycloak(rc *eos_io.RuntimeContext, bundle ServiceBundle, targetDir string) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info(" Starting Keycloak setup rendering...")

	err := RenderBundleFragments(
		rc,
		bundle,
		fmt.Sprintf("%s/docker-compose.override.yml", targetDir),
		fmt.Sprintf("%s/Caddy-fragments", targetDir),
		fmt.Sprintf("%s/conf.d/stream", targetDir),
		"keycloak",
	)
	if err != nil {
		log.Error(" Failed to render Keycloak service", zap.Error(err))
		return err
	}

	log.Info(" Keycloak setup rendered successfully!")
	return nil
}
