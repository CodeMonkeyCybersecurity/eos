// pkg/hecate/phase5_authentik.go

package hecate

import (
	"bufio"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SetupAuthentikWizard prompts the user for Authentik setup info and returns a ServiceBundle.
func SetupAuthentikWizard(rc *eos_io.RuntimeContext, reader *bufio.Reader) ServiceBundle {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Collecting Authentik setup information...")

	// Define the fields to prompt for.
	fields := []PromptField{
		{
			Prompt:  "Enter Authentik domain (e.g., auth.domain.com)",
			Default: "auth.domain.com",
			EnvVar:  "AuthentikDomain",
			Reader:  reader,
		},
		{
			Prompt:  "Enter Authentik DB name",
			Default: "authentik",
			EnvVar:  "AuthentikDBName",
			Reader:  reader,
		},
		{
			Prompt:  "Enter Authentik DB user",
			Default: "authentik",
			EnvVar:  "AuthentikDBUser",
			Reader:  reader,
		},
		{
			Prompt:  "Enter Authentik DB password",
			Default: "changeme",
			EnvVar:  "AuthentikDBPassword",
			Reader:  reader,
		},
		{
			Prompt:  "Enter Authentik secret key (leave empty to generate)",
			Default: "",
			EnvVar:  "AuthentikSecretKey",
			Reader:  reader,
		},
		{
			Prompt:  "Enter Authentik Redis password",
			Default: "changeme",
			EnvVar:  "AuthentikRedisPassword",
			Reader:  reader,
		},
	}

	// Prepare Caddy reverse proxy info (using Docker service name internally)
	caddyProxy := &CaddyAppProxy{
		AppName:     "authentik",
		Domain:      "<AuthentikDomain>", // Placeholder; will get interpolated during rendering
		BackendIP:   "authentik-server",  // Docker service name for Authentik container
		BackendPort: "9000",
	}

	// Build the ServiceBundle using GenericWizard.
	return GenericWizard(
		rc,
		"hecate-authentik-setup",
		fields,
		"authentik",
		DockerAuthentikService,
		caddyProxy,
		nil,                                             // No NGINX config needed for Authentik
		[]string{"authentik-postgres", "authentik-redis"}, // depends_on
		[]string{
			"authentik-postgres-data:/var/lib/postgresql/data",
			"authentik-redis-data:/data",
		}, // volumes
		nil, // ports (Authentik is proxied)
	)
}

// SetupAuthentik performs the full setup: renders Compose, Caddy, etc.
func SetupAuthentik(rc *eos_io.RuntimeContext, bundle ServiceBundle, targetDir string) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info(" Starting Authentik setup rendering...")

	err := RenderBundleFragments(
		rc,
		bundle,
		fmt.Sprintf("%s/docker-compose.override.yml", targetDir),
		fmt.Sprintf("%s/Caddy-fragments", targetDir),
		fmt.Sprintf("%s/conf.d/stream", targetDir),
		"authentik",
	)
	if err != nil {
		log.Error(" Failed to render Authentik service", zap.Error(err))
		return err
	}

	log.Info(" Authentik setup rendered successfully!")
	return nil
}