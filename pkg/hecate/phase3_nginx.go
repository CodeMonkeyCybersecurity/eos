// pkg/hecate/phase3_nginx.go

package hecate

import (
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"
)

// SetupNginxEnvironment sets up Nginx configs for Hecate (stream + include templates)
func SetupNginxEnvironment(backendIP string) error {
	log := zap.L().Named("hecate-nginx-orchestrator")
	log.Info("🚀 Starting full Nginx setup for Hecate...")

	// Ensure directories exist
	streamDir := "/opt/hecate/assets/conf.d/stream"
	if err := ensureDir("/opt/hecate/assets/conf.d"); err != nil {
		return err
	}
	if err := ensureDir(streamDir); err != nil {
		return err
	}

	// Render and save StreamIncludeTemplate (this is your global stream include block)
	includePath := "/opt/hecate/assets/conf.d/stream_include.conf"
	if err := os.WriteFile(includePath, []byte(StreamIncludeTemplate), 0644); err != nil {
		log.Error("Failed to write stream include config", zap.Error(err))
		return err
	}
	log.Info("✅ Wrote stream include config", zap.String("path", includePath))

	// Define all services that need rendering
	services := []struct {
		Name       string
		Blocks     []NginxStreamBlock
		OutputFile string
	}{
		{
			Name:       "mailcow",
			Blocks:     MailcowStreamBlocks,
			OutputFile: filepath.Join(streamDir, "mailcow.conf"),
		},
		{
			Name:       "jenkins",
			Blocks:     JenkinsStreamBlocks,
			OutputFile: filepath.Join(streamDir, "jenkins.conf"),
		},
		{
			Name:       "wazuh",
			Blocks:     WazuhStreamBlocks,
			OutputFile: filepath.Join(streamDir, "wazuh.conf"),
		},
	}

	// Render each service’s stream config and write to file
	for _, svc := range services {
		log.Info("Rendering Nginx stream config", zap.String("service", svc.Name))
		rendered, err := RenderStreamBlocks(backendIP, svc.Blocks)
		if err != nil {
			log.Error("Failed to render Nginx stream config", zap.String("service", svc.Name), zap.Error(err))
			return err
		}

		if err := os.WriteFile(svc.OutputFile, []byte(rendered), 0644); err != nil {
			log.Error("Failed to write Nginx config", zap.String("path", svc.OutputFile), zap.Error(err))
			return err
		}
		log.Info("✅ Rendered and wrote Nginx config", zap.String("file", svc.OutputFile))
	}

	log.Info("✅ Full Nginx setup completed successfully!")
	return nil
}

// ensureDir ensures a directory exists (creates it if missing)
func ensureDir(path string) error {
	log := zap.L().Named("hecate-nginx-setup")
	log.Info("Checking directory...", zap.String("path", path))

	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Info("Creating directory...", zap.String("path", path))
		if err := os.MkdirAll(path, 0755); err != nil {
			log.Error("Failed to create directory", zap.String("path", path), zap.Error(err))
			return fmt.Errorf("failed to create directory %s: %w", path, err)
		}
		log.Info("✅ Directory created", zap.String("path", path))
	} else {
		log.Info("Directory already exists", zap.String("path", path))
	}
	return nil
}
