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

	// Pre-operation diagnostics (claude.md P2 - Debug Verbosity)
	composeFile := BaseDir + "/docker-compose.yml"
	composeExists := false
	if _, err := os.Stat(composeFile); err == nil {
		composeExists = true
	}

	// Get Docker version for diagnostics
	dockerVersionCmd := exec.Command("docker", "version", "--format", "{{.Server.Version}}")
	dockerVersion, _ := dockerVersionCmd.Output()

	// Get available memory for diagnostics
	memCmd := exec.Command("free", "-h")
	memOutput, _ := memCmd.Output()

	logger.Debug("Pre-operation diagnostics",
		zap.String("service_dir", BaseDir),
		zap.Bool("compose_file_exists", composeExists),
		zap.String("compose_file", composeFile),
		zap.String("docker_version", strings.TrimSpace(string(dockerVersion))),
		zap.String("memory_status", strings.TrimSpace(string(memOutput))))

	// Pre-pull images to avoid OOM during parallel pulls
	logger.Info("Pulling Docker images (this may take a few minutes)...")
	pullOutput, pullErr := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "pull", "--ignore-pull-failures"},
		Dir:     BaseDir,
		Capture: true,
	})
	if pullErr != nil {
		logger.Warn("Some images failed to pull, will retry during up",
			zap.Error(pullErr),
			zap.String("output", pullOutput))
	} else {
		logger.Info("Images pulled successfully")
	}

	// INTERVENE - Run docker compose up -d
	logger.Debug("Executing docker compose",
		zap.String("command", "docker"),
		zap.Strings("args", []string{"compose", "up", "-d"}),
		zap.String("working_dir", BaseDir))

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "up", "-d"},
		Dir:     BaseDir,
		Capture: true,
	})

	if err != nil {
		// Enhanced error context per claude.md P1 - Error Context
		logger.Error("Docker compose failed",
			zap.Error(err),
			zap.String("output", output),
			zap.String("working_dir", BaseDir))
		return fmt.Errorf("failed to start services: %s\n"+
			"Working directory: %s\n"+
			"Remediation:\n"+
			"  1. Check available memory: free -h\n"+
			"  2. Try pulling images separately: cd %s && docker compose pull\n"+
			"  3. Check Docker logs: docker compose logs\n"+
			"Error: %w",
			output, BaseDir, BaseDir, err)
	}

	// EVALUATE - Verify services started
	logger.Info("Services started successfully")
	logger.Debug("Docker compose output", zap.String("output", output))

	// Post-operation verification (claude.md P2 - Debug Verbosity)
	psCmd := exec.Command("docker", "compose", "ps", "--format", "json")
	psCmd.Dir = BaseDir
	psOutput, _ := psCmd.Output()
	logger.Debug("Post-operation verification",
		zap.String("containers_status", strings.TrimSpace(string(psOutput))))

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

	var domain string
	var config *HecateConsulConfig

	// ASSESS - Try to load config from Consul first
	consulMgr, err := NewConsulConfigManager(rc)
	if err != nil {
		logger.Warn("Consul not available, using interactive prompts", zap.Error(err))
		logger.Info("Tip: Install Consul to save configuration for future use")
		logger.Info("")

		// Fallback to manual prompt
		logger.Info("terminal prompt: Enter your domain (e.g., example.com):")
		domain, err = eos_io.ReadInput(rc)
		if err != nil {
			return fmt.Errorf("failed to read domain input: %w", err)
		}
		domain = strings.TrimSpace(domain)
		if domain == "" {
			return fmt.Errorf("domain is required")
		}
	} else {
		// Consul is available - try to load or prompt for config
		config, err = consulMgr.LoadOrPromptConfig(rc, true)
		if err != nil {
			return fmt.Errorf("failed to load configuration: %w", err)
		}
		domain = config.Domain
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

	// Save configuration to Consul BEFORE starting services (so it persists even if startup fails)
	if consulMgr != nil {
		logger.Info("Saving configuration to Consul for future use")
		saveConfig := &HecateConsulConfig{
			Domain:          domain,
			ConsulAvailable: true,
		}
		// Include server IP if we detected it during DNS setup
		if config != nil && config.ServerIP != "" {
			saveConfig.ServerIP = config.ServerIP
		}
		if err := consulMgr.SaveConfig(rc, saveConfig); err != nil {
			logger.Warn("Failed to save configuration to Consul", zap.Error(err))
			// Don't fail deployment if Consul save fails
		} else {
			logger.Info("Configuration saved to Consul successfully")
			logger.Info("Next time you run 'eos create hecate', these settings will be suggested")
		}
	}

	// Ask if user wants to start services (defaults to Yes on empty input)
	if !interaction.PromptYesNo(rc.Ctx, "Start services now?", true) {
		logger.Info("Skipped starting services")
		logger.Info("To start manually, run: cd /opt/hecate && docker compose up -d")
		return nil
	}

	// EVALUATE - Start services with docker compose
	logger.Info("Starting Hecate services...")
	if err := startHecateServices(rc); err != nil {
		return err
	}

	logger.Info("")
	logger.Info("terminal prompt: ✓ Hecate deployment completed successfully!")
	logger.Info("")

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
	KeycloakDomain string
}
