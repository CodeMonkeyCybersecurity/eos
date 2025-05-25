// pkg/hecate/phase2_caddy.go

package hecate

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"go.uber.org/zap"
)

func PhaseCaddy(ctx context.Context, spec CaddySpec) error {
	log := zap.L().Named("hecate-phase-caddy")
	log.Info("🚀 Phase 2: Caddy setup",
		zap.Int("proxy_count", len(spec.Proxies)),
		zap.String("keycloak_domain", spec.KeycloakDomain),
	)

	// 1) Ensure Caddy directories
	dirs := []string{HecateCertsDir, HecateAssetsDir, HecateLogsDir}
	for _, d := range dirs {
		if err := eos_unix.MkdirP(ctx, d, 0o755); err != nil {
			log.Error("ensure dir failed", zap.String("path", d), zap.Error(err))
			return fmt.Errorf("ensure caddy dir %s: %w", d, err)
		}
	}
	log.Info("✅ Caddy directories ensured")

	// 2) Skip if nothing to do
	if len(spec.Proxies) == 0 && spec.KeycloakDomain == "" {
		log.Info("⚠️ No proxies or Keycloak; skipping Caddyfile")
		return nil
	}

	// 3) Build + deploy Caddyfile
	if err := buildAndDeployCaddyfile(ctx, spec); err != nil {
		log.Error("Caddyfile deploy failed", zap.Error(err))
		return err
	}
	log.Info("✅ Caddyfile deployed")
	return nil
}

func BuildAndPlaceCaddyfile(ctx context.Context, spec CaddySpec) error {
	log := zap.L().Named("hecate-caddy-builder")
	content := GenerateCaddySpecMulti(spec)
	log.Info("Caddyfile generated", zap.Int("length", len(content)))

	// write temp file
	if err := os.WriteFile("Caddyfile", []byte(content), 0o644); err != nil {
		log.Error("write temp Caddyfile failed", zap.Error(err))
		return fmt.Errorf("write Caddyfile: %w", err)
	}

	// move into place with proper context
	if err := eos_unix.CopyFile(ctx, "Caddyfile", HecateCaddyfile, 0o644); err != nil {
		log.Error("move Caddyfile failed", zap.Error(err))
		return fmt.Errorf("move Caddyfile: %w", err)
	}
	return nil
}

// GenerateCaddySpecMulti creates the Caddyfile content from spec.
func GenerateCaddySpecMulti(spec CaddySpec) string {
	log := zap.L().Named("hecate-caddy-generator")
	log.Info("🔧 Starting Caddyfile generation", zap.Int("proxy_count", len(spec.Proxies)), zap.String("keycloak_domain", spec.KeycloakDomain))

	var builder strings.Builder

	for _, app := range spec.Proxies {
		builder.WriteString(fmt.Sprintf("%s {\n    reverse_proxy %s\n", app.Domain, app.BackendIP))

		switch strings.ToLower(app.AppName) {
		case "nextcloud":
			builder.WriteString("    header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n    encode zstd gzip\n")
		case "wazuh":
			builder.WriteString("    encode gzip\n")
		case "mailcow":
			builder.WriteString("    tls internal\n")
		default:
			builder.WriteString("    # No special features for this app\n")
		}
		builder.WriteString("}\n\n")
	}

	if spec.KeycloakDomain != "" {
		builder.WriteString(fmt.Sprintf("%s {\n    reverse_proxy hecate-kc:8080\n    # Keycloak special settings can be added here if needed\n}\n\n", spec.KeycloakDomain))
	}

	log.Info("✅ Caddyfile generation complete")
	return builder.String()
}

// CollateCaddyFragments handles collation + writing of the Caddyfile.
func CollateCaddyFragments() error {
	log := zap.L().Named("hecate-caddy-collation")
	log.Info("📦 Collating and writing Caddy fragments", zap.Int("fragment_count", len(caddyFragments)))

	return CollateAndWriteFile(
		"hecate-caddy-collation",
		caddyFragments,
		HecateCaddyfile,
		"",
		"",
		func(frag CaddyFragment) string {
			log.Info("🧩 Writing Caddy fragment", zap.String("service", frag.ServiceName))
			return frag.CaddyBlock
		},
	)
}

func buildAndDeployCaddyfile(ctx context.Context, spec CaddySpec) error {
	log := zap.L().Named("hecate-caddy-builder")
	content := GenerateCaddySpecMulti(spec)
	log.Info("Caddyfile generated", zap.Int("length", len(content)))

	// write to temp file
	if err := os.WriteFile("Caddyfile", []byte(content), 0o644); err != nil {
		log.Error("write temp Caddyfile failed", zap.Error(err))
		return fmt.Errorf("write Caddyfile: %w", err)
	}

	// move into place
	if err := eos_unix.CopyFile(ctx, "Caddyfile", HecateCaddyfile, 0o644); err != nil {
		log.Error("move Caddyfile failed", zap.Error(err))
		return fmt.Errorf("move Caddyfile: %w", err)
	}
	return nil
}
