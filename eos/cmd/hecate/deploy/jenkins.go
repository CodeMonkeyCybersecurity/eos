// cmd/heacte/deploy/jenkins.go

package jenkins

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"eos/pkg/certs"
	"eos/pkg/config"
	"eos/pkg/docker"
	"eos/pkg/logger"
	"eos/pkg/utils"
)

var log = logger.L()

// NewDeployJenkinsCmd returns the Jenkins-specific deploy command.
func NewDeployJenkinsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jenkins",
		Short: "Deploy reverse proxy for Jenkins",
		Long: `Deploy the reverse proxy configuration for Jenkins using Hecate.

This command stops the Hecate container (if running) and then organizes assets by moving files 
that are not relevant to Jenkins into the "other" directory at the project root.`,
		Run: func(cmd *cobra.Command, args []string) {
			log.Info("Starting Jenkins deployment")

			// Stop the container if it's running.
			if err := docker.StopContainersBySubstring("hecate"); err != nil {
				log.Error("Error stopping container", zap.String("substring", "hecate"), zap.Error(err))
				fmt.Printf("Error stopping container: %v\n", err)
				return
			}
			log.Info("Containers with 'hecate' in the name stopped successfully")

			// Organize assets for Jenkins.
			if err := utils.OrganizeAssetsForDeployment("jenkins"); err != nil {
				log.Error("Failed to organize assets", zap.Error(err))
				fmt.Printf("Failed to organize assets: %v\n", err)
				return
			}
			log.Info("Assets organized successfully for Jenkins")

			// Load configuration from .hecate.conf.
			cfg, err := config.LoadConfig("jenkins")
			if err != nil {
				log.Error("Configuration error", zap.Error(err))
				fmt.Printf("Configuration error: %v\n", err)
				return
			}
			log.Info("Configuration loaded", zap.Any("config", cfg))
			fmt.Printf("Configuration loaded:\n  Base Domain: %s\n  Backend IP: %s\n  Subdomain: %s\n  Email: %s\n",
				cfg.BaseDomain, cfg.BackendIP, cfg.Subdomain, cfg.Email)

			assetsDir := "./assets" // or the appropriate directory
			if err := utils.ReplaceTokensInAllFiles(assetsDir, cfg.BaseDomain, cfg.BackendIP); err != nil {
				log.Error("Failed to replace tokens in assets", zap.Error(err))
				fmt.Printf("Error replacing tokens: %v\n", err)
				return
			}
			log.Info("Tokens replaced successfully in all files under assets")

			// Define fullDomain using subdomain and base domain.
			fullDomain := fmt.Sprintf("%s.%s", cfg.Subdomain, cfg.BaseDomain)

			if err := certs.EnsureCertificates(cfg.Subdomain, cfg.BaseDomain, cfg.Email); err != nil {
				log.Error("Certificate generation failed", zap.Error(err))
				fmt.Printf("Certificate generation failed: %v\n", err)
				return
			}
			log.Info("Certificate retrieved successfully", zap.String("domain", fullDomain))

			// Uncomment lines in docker-compose.yml relevant to Jenkins.
			if err := docker.UncommentSegment("uncomment if using Jenkins behind Hecate"); err != nil {
				log.Error("Failed to uncomment Jenkins section", zap.Error(err))
				fmt.Printf("Failed to uncomment Jenkins section: %v\n", err)
				return
			}
			log.Info("Successfully uncommented Jenkins lines")

			// Now use the compose file for starting the services.
			if err := docker.RunDockerComposeAllServices(config.DefaultComposeYML, "jenkins"); err != nil {
				log.Error("Failed to start Docker services", zap.Error(err))
				fmt.Printf("Failed to run docker-compose up: %v\n", err)
				return
			}

			fmt.Println("🎉 Jenkins reverse proxy deployed successfully.")
		},
	}
	return cmd
}

func OrganizeAssetsForDeployment(app string) error {
	assetsDir := "assets"
	otherDir := "other" // "other" is at the project root

	// Ensure the "other" directory exists.
	if err := os.MkdirAll(otherDir, 0755); err != nil {
		return fmt.Errorf("failed to create 'other' directory: %w", err)
	}
	log.Info("OrganizeAssetsForDeployment: 'other' directory verified", zap.String("other_Dir", otherDir))

	// Define the generic allowed filenames (lowercase).
	allowedGenerics := map[string]bool{
		"http.conf":   true,
		"stream.conf": true,
		"nginx.conf":  true,
	}

	// Walk the assets directory.
	err := filepath.Walk(assetsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Error("Error accessing path", zap.String("path", path), zap.Error(err))
			return err
		}

		// Skip directories.
		if info.IsDir() {
			log.Debug("Skipping directory", zap.String("dir", path))
			return nil
		}

		// Compute the file's relative path from assetsDir.
		relPath, err := filepath.Rel(assetsDir, path)
		if err != nil {
			log.Error("Failed to compute relative path", zap.String("path", path), zap.Error(err))
			return err
		}
		log.Debug("Processing file", zap.String("relativePath", relPath))

		// Get the base filename in lowercase.
		base := strings.ToLower(filepath.Base(path))
		log.Debug("Base filename", zap.String("base", base))

		// Check if the file is relevant.
		if allowedGenerics[base] || strings.Contains(base, strings.ToLower(app)) {
			log.Debug("File is relevant; leaving it in assets", zap.String("file", path))
			return nil
		}

		// File is not relevant; log that it will be moved.
		dest := filepath.Join(otherDir, relPath)
		log.Debug("File not relevant; preparing to move", zap.String("file", path), zap.String("destination", dest))

		// Ensure the destination directory exists.
		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			log.Error("Failed to create destination directory", zap.String("destDir", filepath.Dir(dest)), zap.Error(err))
			return fmt.Errorf("failed to create destination directory %s: %w", filepath.Dir(dest), err)
		}

		// Move (rename) the file.
		if err := os.Rename(path, dest); err != nil {
			log.Error("Failed to move file to 'other'", zap.String("from", path), zap.String("to", dest), zap.Error(err))
			return fmt.Errorf("failed to move file %s to %s: %w", path, dest, err)
		}

		log.Info("Moved unused asset file to 'other'", zap.String("from", path), zap.String("to", dest))
		return nil
	})
	if err != nil {
		log.Error("Error during asset organization", zap.Error(err))
	}
	return err
}
