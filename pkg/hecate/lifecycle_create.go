// pkg/hecate/lifecycle_create.go

package hecate

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// OrchestrateHecateWizard runs the Hecate setup phases in order.
func OrchestrateHecateWizard(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info(" Welcome to the Hecate setup wizard!")

	// Phase 0: ensure /opt/hecate exists
	if err := eos_unix.MkdirP(rc.Ctx, BaseDir, 0o755); err != nil {
		log.Error("Failed to create base directory", zap.Error(err))
		return fmt.Errorf("failed to create %s: %w", BaseDir, err)
	}

	// Collect configuration from user interactively
	config, err := collectHecateConfiguration(rc)
	if err != nil {
		log.Error("Failed to collect configuration", zap.Error(err))
		return fmt.Errorf("configuration collection failed: %w", err)
	}

	// Phase 1: Docker Compose (no context arg)
	log.Info(" Running Phase Docker Compose…")
	if err := PhaseDockerCompose(rc, "hecate-compose-orchestrator", HecateDockerCompose); err != nil {
		log.Error("Phase Docker Compose failed", zap.Error(err))
		return fmt.Errorf("phase docker compose failed: %w", err)
	}

	// Phase 2: Caddy (this one does take context+spec)
	spec := CaddySpec{
		AuthentikDomain: config.AuthentikDomain,
		Proxies:        config.Proxies,
	}
	log.Info(" Running Phase Caddy setup…")
	if err := PhaseCaddy(rc, spec); err != nil {
		log.Error("Phase Caddy failed", zap.Error(err))
		return fmt.Errorf("phase caddy failed: %w", err)
	}

	// Phase 3: Nginx (only backendIP)
	log.Info(" Running Phase Nginx setup…")
	if err := PhaseNginx(config.BackendIP, rc); err != nil {
		log.Error("Phase Nginx failed", zap.Error(err))
		return fmt.Errorf("phase nginx failed: %w", err)
	}

	log.Info(" Hecate setup wizard completed successfully!")
	return nil
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
	KeycloakDomain  string
}

// collectHecateConfiguration interactively collects configuration from the user
func collectHecateConfiguration(rc *eos_io.RuntimeContext) (*HecateConfiguration, error) {
	logger := otelzap.Ctx(rc.Ctx)
	reader := bufio.NewReader(os.Stdin)

	config := &HecateConfiguration{
		EnabledServices: make(map[string]bool),
		Proxies:         []CaddyAppProxy{},
	}

	logger.Info(" Welcome to Hecate Setup Wizard")
	logger.Info("This wizard will help you set up a reverse proxy for your applications")
	logger.Info("")

	// Collect domain name
	logger.Info(" Enter your primary domain name (e.g., example.com):")
	domain, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read domain: %w", err)
	}
	config.DomainName = strings.TrimSpace(domain)

	if config.DomainName == "" {
		config.DomainName = "localhost"
		logger.Info(" Using default domain: localhost")
	}

	// Collect backend IP
	logger.Info(" Enter your backend server IP (default: 127.0.0.1):")
	backendIP, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read backend IP: %w", err)
	}
	config.BackendIP = strings.TrimSpace(backendIP)

	if config.BackendIP == "" {
		config.BackendIP = "127.0.0.1"
		logger.Info(" Using default backend IP: 127.0.0.1")
	}

	// For now, we'll set up a basic vanilla reverse proxy
	// Future versions can add more service selection
	config.AuthentikDomain = "" // No Authentik for vanilla setup
	config.KeycloakDomain = ""  // Deprecated, for backward compatibility

	logger.Info(" Configuration collected successfully",
		zap.String("domain", config.DomainName),
		zap.String("backend_ip", config.BackendIP),
	)

	return config, nil
}
