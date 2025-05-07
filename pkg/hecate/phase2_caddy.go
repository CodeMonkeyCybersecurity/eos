// pkg/hecate/phase2_caddy.go

package hecate

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"go.uber.org/zap"
)

// PhaseCaddy sets up the Caddy environment: collate, render, and write.
// This is the phase 2 orchestrator, called by the main lifecycle.
func PhaseCaddy(spec CaddySpec) error {
	log := zap.L().Named("hecate-phase-caddy")
	log.Info("🚀 Starting Phase 2: Build and setup Caddy...",
		zap.Int("proxy_count", len(spec.Proxies)),
		zap.String("keycloak_domain", spec.KeycloakDomain),
	)

	// Ensure dirs always (even if no services selected)
	log.Info("📁 Ensuring Caddy directory structure...")
	if err := EnsureCaddyDirs(); err != nil {
		log.Error("❌ Failed to ensure Caddy directories", zap.Error(err))
		return fmt.Errorf("failed to ensure Caddy dirs: %w", err)
	}
	log.Info("✅ Caddy directories ensured")

	// If spec has no proxies and no Keycloak domain, skip actual file generation.
	if len(spec.Proxies) == 0 && spec.KeycloakDomain == "" {
		log.Info("⚠️ No Caddy services selected; skipping Caddyfile generation",
			zap.Int("proxy_count", len(spec.Proxies)),
			zap.String("keycloak_domain", spec.KeycloakDomain),
		)
		return nil
	}

	// Actually build and deploy the Caddyfile
	log.Info("🛠️ Proceeding to build and deploy Caddyfile...")
	err := BuildCaddyFile(spec)
	if err != nil {
		log.Error("❌ Caddyfile build/deploy failed", zap.Error(err))
	} else {
		log.Info("✅ Caddyfile build/deploy completed successfully")
	}
	return err
}

// BuildCaddyFile generates, writes, and moves the Caddyfile to its destination.
// This is the core function that handles file building.
func BuildCaddyFile(spec CaddySpec) error {
	log := zap.L().Named("hecate-caddy-builder")
	log.Info("🛠️ Building Caddyfile...",
		zap.Int("proxy_count", len(spec.Proxies)),
		zap.String("keycloak_domain", spec.KeycloakDomain),
	)

	// Step 1: Generate Caddyfile content
	log.Info("🔧 Generating Caddyfile content...")
	caddyContent := GenerateCaddySpecMulti(spec)
	log.Info("✅ Caddyfile content generated",
		zap.Int("content_length", len(caddyContent)),
	)

	// Step 2: Write Caddyfile locally
	log.Info("💾 Writing Caddyfile to working directory...")
	if err := WriteCaddyfile(caddyContent); err != nil {
		log.Error("❌ Failed to write Caddyfile", zap.Error(err))
		return fmt.Errorf("failed to write Caddyfile: %w", err)
	}
	log.Info("✅ Caddyfile written successfully", zap.String("file", "Caddyfile"))

	// Step 3: Move to /opt/hecate
	log.Info("🚚 Moving Caddyfile to /opt/hecate...")
	if err := MoveCaddyfileToHecate(); err != nil {
		log.Error("❌ Failed to move Caddyfile", zap.Error(err))
		return fmt.Errorf("failed to move Caddyfile: %w", err)
	}

	log.Info("✅ Caddyfile build and move completed successfully",
		zap.String("destination", HecateCaddyfile),
	)
	return nil
}

// SetupCaddyEnvironment sets up the full Caddy environment: directories, config generation, and placement.
func SetupCaddyEnvironment(spec CaddySpec) error {
	log := zap.L().Named("hecate-caddy-orchestrator")
	log.Info("🚀 Starting full Caddy setup for Hecate...",
		zap.Int("proxy_count", len(spec.Proxies)),
		zap.String("keycloak_domain", spec.KeycloakDomain),
	)

	// Step 1: Ensure the directory structure is ready
	log.Info("📁 Ensuring directory structure for Caddy...")
	if err := EnsureCaddyDirs(); err != nil {
		log.Error("❌ Failed to set up Caddy directories", zap.Error(err))
		return err
	}
	log.Info("✅ Directory structure ensured")

	// Step 2: Generate the Caddyfile content
	log.Info("🔧 Generating Caddyfile content...")
	caddyContent := GenerateCaddySpecMulti(spec)
	log.Info("✅ Caddyfile content generated",
		zap.Int("content_length", len(caddyContent)),
	)

	// Step 3: Write the Caddyfile locally
	log.Info("💾 Writing Caddyfile to working directory...")
	if err := WriteCaddyfile(caddyContent); err != nil {
		log.Error("❌ Failed to write Caddyfile", zap.Error(err))
		return err
	}
	log.Info("✅ Caddyfile written successfully")

	// Step 4: Move the Caddyfile to /opt/hecate
	log.Info("🚚 Moving Caddyfile to /opt/hecate...")
	if err := MoveCaddyfileToHecate(); err != nil {
		log.Error("❌ Failed to move Caddyfile to /opt/hecate", zap.Error(err))
		return err
	}
	log.Info("✅ Full Caddy setup completed successfully!",
		zap.String("final_path", HecateCaddyfile),
	)
	return nil
}

// GenerateCaddySpecMulti generates a Caddyfile with multiple reverse proxy blocks.
func GenerateCaddySpecMulti(spec CaddySpec) string {
	log := zap.L().Named("hecate-caddy-generator")
	log.Info("🔧 Starting Caddyfile generation", zap.Int("proxy_count", len(spec.Proxies)), zap.String("keycloak_domain", spec.KeycloakDomain))

	var builder strings.Builder

	// Loop through each app and create a Caddy block.
	for _, app := range spec.Proxies {
		log.Info("🔗 Generating block for app",
			zap.String("app_name", app.AppName),
			zap.String("domain", app.Domain),
			zap.String("backend_ip", app.BackendIP),
			zap.String("backend_port", app.BackendPort),
		)

		fullDomain := app.Domain

		builder.WriteString(fmt.Sprintf("%s {\n", fullDomain))
		builder.WriteString(fmt.Sprintf("    reverse_proxy %s\n", app.BackendIP))

		switch strings.ToLower(app.AppName) {
		case "nextcloud":
			builder.WriteString("    header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n")
			builder.WriteString("    encode zstd gzip\n")
			log.Info("🛡️  Added special config for Nextcloud", zap.String("domain", app.Domain))
		case "wazuh":
			builder.WriteString("    encode gzip\n")
			log.Info("🛡️  Added special config for Wazuh", zap.String("domain", app.Domain))
		case "mailcow":
			builder.WriteString("    tls internal\n")
			log.Info("🛡️  Added special config for Mailcow", zap.String("domain", app.Domain))
		default:
			builder.WriteString("    # No special features for this app\n")
			log.Info("ℹ️  No special config applied", zap.String("app_name", app.AppName))
		}

		builder.WriteString("}\n\n")
	}

	// Always add Keycloak proxy block at the end.
	if spec.KeycloakDomain != "" {
		log.Info("🔗 Adding Keycloak proxy block", zap.String("domain", spec.KeycloakDomain))
		builder.WriteString(fmt.Sprintf("%s {\n", spec.KeycloakDomain))
		builder.WriteString("    reverse_proxy hecate-kc:8080\n")
		builder.WriteString("    # Keycloak special settings can be added here if needed\n")
		builder.WriteString("}\n\n")
	} else {
		log.Info("ℹ️  No Keycloak domain specified; skipping Keycloak block")
	}

	log.Info("✅ Caddyfile generation complete")
	return builder.String()
}

// WriteCaddyfile writes the provided content to the Caddyfile.
func WriteCaddyfile(content string) error {
	log := zap.L().Named("hecate-caddy-writer")
	log.Info("📝 Writing Caddyfile to current directory", zap.String("path", "Caddyfile"))

	file, err := os.Create("Caddyfile")
	if err != nil {
		log.Error("❌ Failed to create Caddyfile", zap.Error(err))
		return err
	}
	defer file.Close()

	n, err := file.WriteString(content)
	if err != nil {
		log.Error("❌ Failed to write Caddyfile content", zap.Error(err))
		return err
	}

	log.Info("✅ Caddyfile written successfully", zap.Int("bytes_written", n))
	return nil
}

// EnsureCaddyDirs creates the necessary directory structure for the Caddy service in /opt/hecate.
func EnsureCaddyDirs() error {
	log := zap.L().Named("hecate-caddy-setup")
	log.Info("📁 Ensuring Caddy directories exist")

	dirs := []string{HecateCertsDir, HecateAssetsDir, HecateLogsDir}
	if err := system.EnsureDirs(dirs); err != nil {
		log.Error("❌ Failed to ensure Caddy directories", zap.Error(err), zap.Strings("dirs", dirs))
		return err
	}

	log.Info("✅ Caddy directories ensured", zap.Strings("dirs", dirs))
	return nil
}

// MoveCaddyfileToHecate moves the generated Caddyfile to /opt/hecate/Caddyfile.
func MoveCaddyfileToHecate() error {
	log := zap.L().Named("hecate-caddy-mover")
	log.Info("🚚 Moving Caddyfile to Hecate directory", zap.String("target_path", HecateCaddyfile))

	if err := system.CopyFile("Caddyfile", HecateCaddyfile, 0644); err != nil {
		log.Error("❌ Failed to move Caddyfile", zap.Error(err))
		return err
	}

	log.Info("✅ Caddyfile moved successfully", zap.String("destination", HecateCaddyfile))
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
