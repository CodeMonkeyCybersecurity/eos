// pkg/hecate/lifecycle_create.go

package hecate

import (
	"bytes"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// OrchestrateHecateWizard runs the Hecate setup phases in order.
func OrchestrateHecateWizard(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info("🚀 Welcome to the Hecate setup wizard!")

	// Phase 0: ensure /opt/hecate exists
	if err := eos_unix.MkdirP(rc.Ctx, BaseDir, 0o755); err != nil {
		log.Error("Failed to create base directory", zap.Error(err))
		return fmt.Errorf("failed to create %s: %w", BaseDir, err)
	}

	// ─── STUB: collect your real values here ───
	keycloakDomain := ""                  // e.g. from user prompts
	proxies := []CaddyAppProxy{ /* … */ } // build via handleService()
	backendIP := "127.0.0.1"              // gather from user
	// ─────────────────────────────────────────────

	// Phase 1: Docker Compose (no context arg)
	log.Info("⚙️ Running Phase Docker Compose…")
	if err := PhaseDockerCompose(rc, "hecate-compose-orchestrator", HecateDockerCompose); err != nil {
		log.Error("Phase Docker Compose failed", zap.Error(err))
		return fmt.Errorf("phase docker compose failed: %w", err)
	}

	// Phase 2: Caddy (this one does take context+spec)
	spec := CaddySpec{
		KeycloakDomain: keycloakDomain,
		Proxies:        proxies,
	}
	log.Info("⚙️ Running Phase Caddy setup…")
	if err := PhaseCaddy(rc, spec); err != nil {
		log.Error("Phase Caddy failed", zap.Error(err))
		return fmt.Errorf("phase caddy failed: %w", err)
	}

	// Phase 3: Nginx (only backendIP)
	log.Info("⚙️ Running Phase Nginx setup…")
	if err := PhaseNginx(backendIP, rc); err != nil {
		log.Error("Phase Nginx failed", zap.Error(err))
		return fmt.Errorf("phase nginx failed: %w", err)
	}

	log.Info("✅ Hecate setup wizard completed successfully!")
	return nil
}

// ShouldExitNoServicesSelected checks if no services were selected and logs a friendly exit message.
func ShouldExitNoServicesSelected(rc *eos_io.RuntimeContext, keycloak, nextcloud, wazuh, jenkins bool) bool {
	if !keycloak && !nextcloud && !wazuh && !jenkins {
		otelzap.Ctx(rc.Ctx).Warn("🚫 No services selected. Exiting without making any changes.")
		return true
	}
	return false
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

	log.Info("✅ Final file written successfully", zap.String("path", filePath))
	return nil
}
