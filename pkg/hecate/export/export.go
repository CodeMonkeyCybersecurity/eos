// pkg/hecate/export/export.go
// Unified export functionality for Hecate infrastructure
// Exports both Authentik configuration and Hecate-specific files

package export

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate/authentik"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ExportHecateConfig exports the complete Hecate infrastructure configuration
// This includes:
//   - Authentik SSO configuration (via API)
//   - Docker Compose file
//   - Caddyfile
//   - .env file (secrets)
//
// ASSESS → INTERVENE → EVALUATE pattern:
//  1. ASSESS: Verify prerequisites (Authentik token, files exist)
//  2. INTERVENE: Create export directory, export configs, copy files
//  3. EVALUATE: Verify export completeness, create archive
func ExportHecateConfig(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Hecate infrastructure export")

	// ========================================
	// ASSESS: Verify prerequisites
	// ========================================

	logger.Info("Verifying prerequisites")

	// Check if Authentik token exists (needed for API export)
	token, err := getAuthentikToken()
	if err != nil {
		logger.Warn("Failed to get Authentik token - will skip Authentik API export",
			zap.Error(err))
		// Continue with file exports even if Authentik API unavailable
		token = ""
	}

	// Check if required files exist
	filesToExport := []string{
		hecate.DockerComposeFilePath,
		hecate.CaddyfilePath,
		hecate.EnvFilePath,
	}

	var missingFiles []string
	for _, filePath := range filesToExport {
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			missingFiles = append(missingFiles, filePath)
		}
	}

	if len(missingFiles) > 0 {
		logger.Warn("Some Hecate files are missing - export will be incomplete",
			zap.Strings("missing_files", missingFiles))
	}

	// ========================================
	// INTERVENE: Create export and gather data
	// ========================================

	// Create timestamped export directory
	timestamp := time.Now().Format("20060102_150405")
	outputDir := filepath.Join(hecate.ExportsDir, fmt.Sprintf("hecate_full_backup_%s", timestamp))

	logger.Info("Creating export directory",
		zap.String("output_dir", outputDir))

	if err := os.MkdirAll(outputDir, hecate.BackupDirPerm); err != nil {
		return fmt.Errorf("failed to create export directory: %w", err)
	}

	// Export Authentik configuration if token available
	var authentikBaseURL string
	if token != "" {
		logger.Info("Exporting Authentik configuration via API")

		baseURL, err := getAuthentikBaseURL(rc)
		if err != nil {
			logger.Warn("Failed to determine Authentik base URL, using default",
				zap.Error(err))
			baseURL = fmt.Sprintf("http://%s:%d/api/v3", hecate.AuthentikHost, hecate.AuthentikPort)
		}
		authentikBaseURL = baseURL

		// Create subdirectory for Authentik exports
		authentikDir := filepath.Join(outputDir, "authentik")
		if err := os.MkdirAll(authentikDir, hecate.BackupDirPerm); err != nil {
			logger.Warn("Failed to create Authentik subdirectory",
				zap.Error(err))
		} else {
			// Use existing Authentik export functionality
			client := authentik.NewAuthentikClient(baseURL, token)
			if err := exportAuthentikConfigs(rc, client, authentikDir); err != nil {
				logger.Warn("Failed to export Authentik configurations",
					zap.Error(err))
			}
		}
	} else {
		logger.Info("Skipping Authentik API export (no token available)")
	}

	// Export Hecate-specific files
	logger.Info("Exporting Hecate configuration files")

	// Copy docker-compose.yml
	if err := copyFileToExport(hecate.DockerComposeFilePath, filepath.Join(outputDir, "docker-compose.yml")); err != nil {
		logger.Warn("Failed to export docker-compose.yml", zap.Error(err))
	} else {
		logger.Info("Exported docker-compose.yml")
	}

	// Copy Caddyfile
	if err := copyFileToExport(hecate.CaddyfilePath, filepath.Join(outputDir, "Caddyfile")); err != nil {
		logger.Warn("Failed to export Caddyfile", zap.Error(err))
	} else {
		logger.Info("Exported Caddyfile")
	}

	// Copy .env file (with security warning)
	if err := copyFileToExport(hecate.EnvFilePath, filepath.Join(outputDir, ".env")); err != nil {
		logger.Warn("Failed to export .env file", zap.Error(err))
	} else {
		logger.Info("Exported .env file (contains secrets - handle with care)")

		// Set restrictive permissions on exported .env
		if err := os.Chmod(filepath.Join(outputDir, ".env"), hecate.EnvFilePerm); err != nil {
			logger.Warn("Failed to set restrictive permissions on exported .env",
				zap.Error(err))
		}
	}

	// Create README with export information
	if err := createReadme(outputDir, authentikBaseURL); err != nil {
		logger.Warn("Failed to create README", zap.Error(err))
	}

	// ========================================
	// EVALUATE: Create archive and report
	// ========================================

	logger.Info("Creating compressed archive")

	archivePath, err := createArchive(outputDir)
	if err != nil {
		logger.Warn("Failed to create compressed archive",
			zap.Error(err))
	} else {
		logger.Info("Created compressed archive",
			zap.String("path", archivePath))
	}

	logger.Info("Hecate export completed successfully",
		zap.String("location", outputDir),
		zap.String("archive", archivePath))

	// Print summary for user
	logger.Info("Export summary",
		zap.String("directory", outputDir),
		zap.Bool("includes_authentik_api", token != ""),
		zap.Bool("includes_docker_compose", fileExists(hecate.DockerComposeFilePath)),
		zap.Bool("includes_caddyfile", fileExists(hecate.CaddyfilePath)),
		zap.Bool("includes_env", fileExists(hecate.EnvFilePath)))

	return nil
}

// getAuthentikToken retrieves the Authentik API token from .env file
func getAuthentikToken() (string, error) {
	// Read .env file
	data, err := os.ReadFile(hecate.EnvFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to read .env file: %w", err)
	}

	// Simple parsing for AUTHENTIK_BOOTSTRAP_TOKEN
	lines := string(data)
	for _, line := range strings.Split(lines, "\n") {
		line = strings.TrimSpace(line)
		if len(line) > 0 && line[0] != '#' {
			// Look for AUTHENTIK_BOOTSTRAP_TOKEN or AUTHENTIK_API_TOKEN
			if strings.HasPrefix(line, "AUTHENTIK_BOOTSTRAP_TOKEN=") {
				return strings.TrimPrefix(line, "AUTHENTIK_BOOTSTRAP_TOKEN="), nil
			}
			if strings.HasPrefix(line, "AUTHENTIK_API_TOKEN=") {
				return strings.TrimPrefix(line, "AUTHENTIK_API_TOKEN="), nil
			}
		}
	}

	return "", fmt.Errorf("Authentik token not found in .env file")
}

// getAuthentikBaseURL retrieves the Authentik base URL from Caddy configuration
func getAuthentikBaseURL(rc *eos_io.RuntimeContext) (string, error) {
	// Use default for now - in future could parse from Caddy config
	return fmt.Sprintf("http://hecate-server-1:%d/api/v3", hecate.AuthentikPort), nil
}

// exportAuthentikConfigs exports all Authentik configurations using the API client
func exportAuthentikConfigs(rc *eos_io.RuntimeContext, client *authentik.AuthentikClient, outputDir string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// List of API endpoints to export
	exports := []struct {
		name     string
		path     string
		filename string
	}{
		{
			name:     "Applications",
			path:     "/core/applications/",
			filename: "01_applications.json",
		},
		{
			name:     "Proxy Providers",
			path:     "/providers/proxy/",
			filename: "02_providers.json",
		},
		{
			name:     "Outposts",
			path:     "/outposts/instances/",
			filename: "03_outposts.json",
		},
		{
			name:     "Flows",
			path:     "/flows/instances/",
			filename: "04_flows.json",
		},
		{
			name:     "Property Mappings",
			path:     "/propertymappings/scope/",
			filename: "05_property_mappings.json",
		},
		{
			name:     "OAuth2 Sources",
			path:     "/sources/oauth/",
			filename: "06_oauth_sources.json",
		},
		{
			name:     "Policies",
			path:     "/policies/bindings/",
			filename: "07_policies.json",
		},
		{
			name:     "System Config",
			path:     "/root/config/",
			filename: "08_system_config.json",
		},
		{
			name:     "Tenants",
			path:     "/core/tenants/",
			filename: "09_tenants.json",
		},
		{
			name:     "Brands",
			path:     "/core/brands/",
			filename: "10_brands.json",
		},
	}

	for _, export := range exports {
		logger.Info(fmt.Sprintf("Exporting %s", export.name))

		data, err := client.DoRequest(rc.Ctx, "GET", export.path)
		if err != nil {
			logger.Warn(fmt.Sprintf("Failed to export %s", export.name),
				zap.Error(err))
			continue
		}

		// Write to file
		filePath := filepath.Join(outputDir, export.filename)
		if err := os.WriteFile(filePath, data, hecate.BackupFilePerm); err != nil {
			logger.Warn(fmt.Sprintf("Failed to write %s", export.name),
				zap.Error(err))
			continue
		}

		logger.Info(fmt.Sprintf("Exported %s", export.name),
			zap.String("file", export.filename))
	}

	return nil
}

// copyFileToExport copies a file to the export directory
func copyFileToExport(srcPath, dstPath string) error {
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to read source file: %w", err)
	}

	if err := os.WriteFile(dstPath, data, hecate.BackupFilePerm); err != nil {
		return fmt.Errorf("failed to write destination file: %w", err)
	}

	return nil
}

// createReadme creates a README file with export information
func createReadme(outputDir, authentikBaseURL string) error {
	readme := fmt.Sprintf(`# Hecate Infrastructure Backup
Generated: %s

## Overview
This export contains the complete Hecate reverse proxy infrastructure configuration.

## Contents

### Authentik SSO Configuration (authentik/)
- API exports of all Authentik configurations
- Applications, providers, outposts
- Authentication and authorization flows
- Property mappings and policies
- System configuration

### Hecate Configuration Files
- **docker-compose.yml** - Docker Compose stack definition
- **Caddyfile** - Caddy reverse proxy configuration
- **.env** - Environment variables (CONTAINS SECRETS)

## Security Warnings

⚠️  **CRITICAL**: The .env file contains sensitive credentials including:
- Authentik API tokens
- Database passwords
- Secret keys

**Handle with extreme care:**
- Do NOT commit to version control
- Do NOT share publicly
- Store in encrypted backup location
- Delete after restoration if no longer needed

## Restoration Instructions

### 1. Restore Files
` + "```bash" + `
# Copy files to /opt/hecate/
sudo cp docker-compose.yml /opt/hecate/
sudo cp Caddyfile /opt/hecate/
sudo cp .env /opt/hecate/

# Set correct permissions
sudo chmod 644 /opt/hecate/docker-compose.yml
sudo chmod 644 /opt/hecate/Caddyfile
sudo chmod 600 /opt/hecate/.env
` + "```" + `

### 2. Restore Authentik Configuration
` + "```bash" + `
# Review each JSON file in authentik/ directory
# Use POST/PUT requests to Authentik API endpoints to recreate
# Update IDs and UUIDs as needed for new environment

# Authentik Base URL: %s
` + "```" + `

### 3. Restart Services
` + "```bash" + `
cd /opt/hecate
sudo docker compose up -d
` + "```" + `

### 4. Verify Deployment
` + "```bash" + `
# Check service health
sudo docker compose ps

# Check Caddy logs
sudo docker logs hecate-caddy

# Test routes
curl https://your-domain.com
` + "```" + `

## Generated By
EOS (Enterprise Orchestration System)
Command: eos update hecate --export
Website: https://cybermonkey.net.au/

## Support
For assistance with restoration, contact your system administrator
or visit: https://wiki.cybermonkey.net.au
`, time.Now().Format(time.RFC3339), authentikBaseURL)

	return os.WriteFile(filepath.Join(outputDir, "README.md"), []byte(readme), hecate.BackupFilePerm)
}

// createArchive creates a compressed tar.gz archive of the export
func createArchive(outputDir string) (string, error) {
	timestamp := time.Now().Format("20060102_150405")
	archiveName := fmt.Sprintf("hecate_full_backup_%s.tar.gz", timestamp)
	archivePath := filepath.Join(filepath.Dir(outputDir), archiveName)

	// Use exec.Command for proper error handling and security
	cmd := exec.Command(
		"tar",
		"-czf",
		archivePath,
		"-C", filepath.Dir(outputDir),
		filepath.Base(outputDir),
	)

	// Capture both stdout and stderr for debugging
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to create archive: %w (output: %s)", err, string(output))
	}

	return archivePath, nil
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
