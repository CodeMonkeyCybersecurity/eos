// pkg/hecate/phase2_caddy.go

package hecate

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
)

// SetupCaddyEnvironment sets up the full Caddy environment: directories, config generation, and placement.
func SetupCaddyEnvironment(cfg CaddyConfig) error {
	log := zap.L().Named("hecate-caddy-orchestrator")
	log.Info("🚀 Starting full Caddy setup for Hecate...")

	// Step 1: Ensure the directory structure is ready
	if err := EnsureCaddyDirs(); err != nil {
		log.Error("Failed to set up Caddy directories", zap.Error(err))
		return err
	}

	// Step 2: Generate the Caddyfile content
	log.Info("Generating Caddyfile content...")
	caddyContent := GenerateCaddyConfigMulti(cfg)

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

// GenerateCaddyConfigMulti generates a Caddyfile with multiple reverse proxy blocks.
func GenerateCaddyConfigMulti(cfg CaddyConfig) string {
	var builder strings.Builder

	// Loop through each app and create a Caddy block.
	for _, app := range cfg.Apps {
		fullDomain := app.Domain
		if app.Subdomain != "" {
			fullDomain = app.Subdomain + "." + app.Domain
		}

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
	if cfg.KeycloakDomain != "" {
		builder.WriteString(fmt.Sprintf("%s {\n", cfg.KeycloakDomain))
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
	baseDir := "/opt/hecate"
	certsDir := filepath.Join(baseDir, "certs")
	assetsDir := filepath.Join(baseDir, "assets", "error_pages")
	logsDir := filepath.Join(baseDir, "logs", "caddy")

	log := zap.L().Named("hecate-caddy-setup")

	dirs := []string{certsDir, assetsDir, logsDir}

	for _, dir := range dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			log.Info("Creating directory...", zap.String("path", dir))
			if err := os.MkdirAll(dir, 0755); err != nil {
				log.Error("Failed to create directory", zap.String("path", dir), zap.Error(err))
				return err
			}
			log.Info("✅ Directory created", zap.String("path", dir))
		} else {
			log.Info("Directory already exists", zap.String("path", dir))
		}
	}

	return nil
}

// MoveCaddyfileToHecate moves the generated Caddyfile to /opt/hecate/Caddyfile.
func MoveCaddyfileToHecate() error {
	sourcePath := "Caddyfile"
	destPath := "/opt/hecate/Caddyfile"

	log := zap.L().Named("hecate-caddy-setup")

	srcFile, err := os.Open(sourcePath)
	if err != nil {
		log.Error("Failed to open source Caddyfile", zap.Error(err))
		return fmt.Errorf("failed to open %s: %w", sourcePath, err)
	}
	defer srcFile.Close()

	destFile, err := os.Create(destPath)
	if err != nil {
		log.Error("Failed to create destination Caddyfile", zap.Error(err))
		return fmt.Errorf("failed to create %s: %w", destPath, err)
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, srcFile); err != nil {
		log.Error("Failed to copy Caddyfile to /opt/hecate", zap.Error(err))
		return fmt.Errorf("failed to copy to %s: %w", destPath, err)
	}

	log.Info("✅ Caddyfile moved to /opt/hecate", zap.String("path", destPath))
	return nil
}
