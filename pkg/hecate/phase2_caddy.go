// pkg/hecate/phase2_caddy.go

package hecate

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"go.uber.org/zap"
)

// PhaseCaddy sets up the Caddy environment: dirs, Caddyfile, and placement.
func PhaseCaddy(spec CaddySpec) error {
	log := zap.L().Named("hecate-phase-caddy")
	log.Info("🚀 Starting Phase 2: Caddy setup",
		zap.Int("proxy_count", len(spec.Proxies)),
		zap.String("keycloak_domain", spec.KeycloakDomain),
	)

	// Always ensure directories
	if err := EnsureCaddyDirs(); err != nil {
		log.Error("❌ Failed to ensure Caddy directories", zap.Error(err))
		return fmt.Errorf("failed to ensure Caddy dirs: %w", err)
	}
	log.Info("✅ Caddy directories ensured")

	// Skip Caddyfile generation if no proxies & no Keycloak
	if len(spec.Proxies) == 0 && spec.KeycloakDomain == "" {
		log.Info("⚠️ No proxies or Keycloak domain specified; skipping Caddyfile")
		return nil
	}

	// Build, write, and place Caddyfile
	if err := BuildAndPlaceCaddyfile(spec); err != nil {
		log.Error("❌ Caddyfile build/deploy failed", zap.Error(err))
		return err
	}
	log.Info("✅ Caddyfile build/deploy completed")
	return nil
}

// BuildAndPlaceCaddyfile generates, writes, and moves the Caddyfile.
func BuildAndPlaceCaddyfile(spec CaddySpec) error {
	log := zap.L().Named("hecate-caddy-builder")
	log.Info("🔧 Generating Caddyfile...", zap.Int("proxy_count", len(spec.Proxies)))

	content := GenerateCaddySpecMulti(spec)
	log.Info("✅ Caddyfile content generated", zap.Int("content_length", len(content)))

	// Write locally
	if err := writeFile("Caddyfile", content); err != nil {
		return fmt.Errorf("failed to write Caddyfile: %w", err)
	}

	// Move to /opt/hecate
	if err := system.CopyFile("Caddyfile", HecateCaddyfile, 0644); err != nil {
		return fmt.Errorf("failed to move Caddyfile: %w", err)
	}

	log.Info("✅ Caddyfile placed at destination", zap.String("destination", HecateCaddyfile))
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

// EnsureCaddyDirs ensures required directories exist.
func EnsureCaddyDirs() error {
	dirs := []string{HecateCertsDir, HecateAssetsDir, HecateLogsDir}
	return system.EnsureDirs(dirs)
}

// writeFile writes content to a file.
func writeFile(path string, content string) error {
	log := zap.L().Named("hecate-caddy-writer")
	log.Info("💾 Writing file", zap.String("path", path))

	file, err := os.Create(path)
	if err != nil {
		log.Error("❌ Failed to create file", zap.Error(err))
		return err
	}
	defer file.Close()

	if _, err := file.WriteString(content); err != nil {
		log.Error("❌ Failed to write content", zap.Error(err))
		return err
	}

	log.Info("✅ File written successfully", zap.String("path", path))
	return nil
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
