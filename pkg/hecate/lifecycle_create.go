// pkg/hecate/lifecycle_create.go

package hecate

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// startHecateServices starts the Hecate Docker Compose stack
func startHecateServices(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Hecate services with docker compose")

	// ASSESS - Check if docker compose is available
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker not found in PATH. Please install Docker first")
	}

	// INTERVENE - Run docker compose up -d
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "up", "-d"},
		Dir:     BaseDir,
		Capture: true,
	})

	if err != nil {
		return fmt.Errorf("failed to start services: %s\nError: %w", output, err)
	}

	// EVALUATE - Verify services started
	logger.Info("Services started successfully")
	logger.Debug("Docker compose output", zap.String("output", output))

	logger.Info("")
	logger.Info("Hecate deployment completed!")
	logger.Info("Next steps:")
	logger.Info("  1. Configure DNS to point hera.yourdomain.com to this server")
	logger.Info("  2. Access Authentik at https://hera.yourdomain.com")
	logger.Info("  3. Complete Authentik initial setup")
	logger.Info("")

	return nil
}

// OrchestrateHecateWizard runs the Hecate setup wizard
func OrchestrateHecateWizard(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Hecate deployment wizard")

	// ASSESS - Prompt for required configuration
	logger.Info("terminal prompt: Enter your domain (e.g., example.com):")
	domain, err := eos_io.ReadInput(rc)
	if err != nil {
		return fmt.Errorf("failed to read domain input: %w", err)
	}

	domain = strings.TrimSpace(domain)
	if domain == "" {
		return fmt.Errorf("domain is required")
	}

	logger.Info("Using domain", zap.String("domain", domain))

	// INTERVENE - Generate all configuration files
	if err := GenerateCompleteHecateStack(rc, domain); err != nil {
		return fmt.Errorf("failed to generate Hecate stack: %w", err)
	}

	// Show summary
	logger.Info("")
	logger.Info("Successfully generated Hecate configuration files:")
	logger.Info("  - /opt/hecate/docker-compose.yml")
	logger.Info("  - /opt/hecate/.env")
	logger.Info("  - /opt/hecate/Caddyfile")
	logger.Info("")

	// DNS Setup (before starting services)
	if err := SetupHecateDNS(rc, domain); err != nil {
		logger.Warn("DNS setup encountered issues", zap.Error(err))
		logger.Info("You can configure DNS manually or run: eos create hecate hetzner-dns")
		// Don't fail the entire deployment if DNS setup fails
	}

	logger.Info("Authentik will be accessible at: hera." + domain)
	logger.Info("")

	// Ask if user wants to start services (defaults to Yes on empty input)
	if !interaction.PromptYesNo(rc.Ctx, "Start services now?", true) {
		logger.Info("Skipped starting services")
		logger.Info("To start manually, run: cd /opt/hecate && docker compose up -d")
		return nil
	}

	// EVALUATE - Start services with docker compose
	logger.Info("Starting Hecate services...")
	return startHecateServices(rc)
}

// ShouldExitNoServicesSelected checks if no services were selected and logs a friendly exit message.
func ShouldExitNoServicesSelected(rc *eos_io.RuntimeContext, authentik, nextcloud, wazuh, jenkins bool) bool {
	if !authentik && !nextcloud && !wazuh && !jenkins {
		otelzap.Ctx(rc.Ctx).Warn(" No services selected. Exiting without making any changes.")
		return true
	}
	return false
}

// Deprecated: Use ShouldExitNoServicesSelected with authentik parameter instead
func ShouldExitNoServicesSelectedKeycloak(rc *eos_io.RuntimeContext, keycloak, nextcloud, wazuh, jenkins bool) bool {
	return ShouldExitNoServicesSelected(rc, keycloak, nextcloud, wazuh, jenkins)
}

func CollateAndWriteFile[T any](
	rc *eos_io.RuntimeContext,
	logName string,
	fragments []T,
	filePath string,
	header string,
	footer string,
	renderFunc func(T) string,
) error {
	log := otelzap.Ctx(rc.Ctx)

	// Skip file creation if no fragments & no header/footer
	if len(fragments) == 0 && header == "" && footer == "" {
		log.Info("No fragments to write; skipping", zap.String("path", filePath))
		return nil
	}

	var buf bytes.Buffer

	if header != "" {
		buf.WriteString(header)
		if header[len(header)-1] != '\n' {
			buf.WriteString("\n")
		}
	}

	for _, frag := range fragments {
		buf.WriteString(renderFunc(frag))
		buf.WriteString("\n\n")
	}

	if footer != "" {
		buf.WriteString(footer)
	}

	err := os.WriteFile(filePath, buf.Bytes(), 0644)
	if err != nil {
		log.Error("Failed to write file", zap.Error(err), zap.String("path", filePath))
		return fmt.Errorf("failed to write file %s: %w", filePath, err)
	}

	log.Info(" Final file written successfully", zap.String("path", filePath))
	return nil
}

// HecateConfiguration holds the user-provided configuration for Hecate setup
type HecateConfiguration struct {
	DomainName      string
	AuthentikDomain string
	BackendIP       string
	Proxies         []CaddyAppProxy
	EnabledServices map[string]bool
	// Deprecated: Use AuthentikDomain instead
	KeycloakDomain string
}
