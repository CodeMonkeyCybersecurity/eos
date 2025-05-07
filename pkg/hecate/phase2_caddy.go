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
	zap.L().Named("hecate-phase-caddy").Info("🚀 Starting Phase 2: Build and setup Caddy...")

	// Ensure dirs always (even if no services selected)
	if err := EnsureCaddyDirs(); err != nil {
		return fmt.Errorf("failed to ensure Caddy dirs: %w", err)
	}

	// If spec has no proxies and no Keycloak domain, skip actual file generation.
	if len(spec.Proxies) == 0 && spec.KeycloakDomain == "" {
		zap.L().Named("hecate-phase-caddy").Info("No Caddy services selected; skipping Caddyfile generation")
		return nil
	}

	// Actually build and deploy the Caddyfile
	return BuildCaddyFile(spec)
}

// BuildCaddyFile generates, writes, and moves the Caddyfile to its destination.
// This is the core function that handles file building.
func BuildCaddyFile(spec CaddySpec) error {
	log := zap.L().Named("hecate-caddy-builder")
	log.Info("🛠️ Building Caddyfile...")

	// Step 1: Generate Caddyfile content
	caddyContent := GenerateCaddySpecMulti(spec)

	// Step 2: Write Caddyfile locally
	log.Info("Writing Caddyfile locally...")
	if err := WriteCaddyfile(caddyContent); err != nil {
		return fmt.Errorf("failed to write Caddyfile: %w", err)
	}

	// Step 3: Move to /opt/hecate
	log.Info("Moving Caddyfile to /opt/hecate...")
	if err := MoveCaddyfileToHecate(); err != nil {
		return fmt.Errorf("failed to move Caddyfile: %w", err)
	}

	log.Info("✅ Caddyfile build completed")
	return nil
}

// SetupCaddyEnvironment sets up the full Caddy environment: directories, config generation, and placement.
func SetupCaddyEnvironment(spec CaddySpec) error {
	log := zap.L().Named("hecate-caddy-orchestrator")
	log.Info("🚀 Starting full Caddy setup for Hecate...")

	// Step 1: Ensure the directory structure is ready
	if err := EnsureCaddyDirs(); err != nil {
		log.Error("Failed to set up Caddy directories", zap.Error(err))
		return err
	}

	// Step 2: Generate the Caddyfile content
	log.Info("Generating Caddyfile content...")
	caddyContent := GenerateCaddySpecMulti(spec)

	// Step 3: Write the Caddyfile locally
	log.Info("Writing Caddyfile to working directory...")
	if err := WriteCaddyfile(caddyContent); err != nil {
		log.Error("Failed to write Caddyfile", zap.Error(err))
		return err
	}

	// Step 4: Move the Caddyfile to /opt/hecate
	log.Info("Moving Caddyfile to /opt/hecate...")
	if err := MoveCaddyfileToHecate(); err != nil {
		log.Error("Failed to move Caddyfile to /opt/hecate", zap.Error(err))
		return err
	}

	log.Info("✅ Full Caddy setup completed successfully!")
	return nil
}

// GenerateCaddySpecMulti generates a Caddyfile with multiple reverse proxy blocks.
func GenerateCaddySpecMulti(spec CaddySpec) string {
	var builder strings.Builder

	// Loop through each app and create a Caddy block.
	for _, app := range spec.Proxies {
		fullDomain := app.Domain

		builder.WriteString(fmt.Sprintf("%s {\n", fullDomain))
		builder.WriteString(fmt.Sprintf("    reverse_proxy %s\n", app.BackendIP))

		switch strings.ToLower(app.AppName) {
		case "nextcloud":
			builder.WriteString("    header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n")
			builder.WriteString("    encode zstd gzip\n")
		case "wazuh":
			builder.WriteString("    encode gzip\n")
		case "mailcow":
			builder.WriteString("    tls internal\n")
		default:
			builder.WriteString("    # No special features for this app\n")
		}

		builder.WriteString("}\n\n")
	}

	// Always add Keycloak proxy block at the end.
	if spec.KeycloakDomain != "" {
		builder.WriteString(fmt.Sprintf("%s {\n", spec.KeycloakDomain))
		builder.WriteString("    reverse_proxy hecate-kc:8080\n")
		builder.WriteString("    # Keycloak special settings can be added here if needed\n")
		builder.WriteString("}\n\n")
	}

	return builder.String()
}

// WriteCaddyfile writes the provided content to the Caddyfile.
func WriteCaddyfile(content string) error {
	file, err := os.Create("Caddyfile")
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(content)
	return err
}

// EnsureCaddyDirs creates the necessary directory structure for the Caddy service in /opt/hecate.
func EnsureCaddyDirs() error {

	log := zap.L().Named("hecate-caddy-setup")

	dirs := []string{HecateCertsDir, HecateAssetsDir, HecateLogsDir}
	if err := system.EnsureDirs(dirs); err != nil {
		log.Error("Failed to ensure Caddy directories", zap.Error(err))
		return err
	}

	return nil
}

// MoveCaddyfileToHecate moves the generated Caddyfile to /opt/hecate/Caddyfile.
// MoveCaddyfileToHecate moves the generated Caddyfile to /opt/hecate/Caddyfile.
func MoveCaddyfileToHecate() error {
	return system.CopyFile("Caddyfile", HecateCaddyfile, 0644)
}

// CollateCaddyFragments handles collation + writing of the Caddyfile.
func CollateCaddyFragments() error {
	return CollateAndWriteFile(
		"hecate-caddy-collation",
		caddyFragments,
		HecateCaddyfile,
		"",
		"",
		func(frag CaddyFragment) string { return frag.CaddyBlock },
	)
}
