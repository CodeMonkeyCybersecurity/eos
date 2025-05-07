// pkg/hecate/phase3_nginx.go

package hecate

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"go.uber.org/zap"
)

// SetupNginxEnvironment sets up Nginx configs for Hecate (stream + include templates)
func SetupNginxEnvironment(backendIP string) error {
	log := zap.L().Named("hecate-nginx-orchestrator")
	log.Info("🚀 Starting full Nginx setup for Hecate...")

	// Ensure directories exist
	if err := system.EnsureDir(HecateConfDDir); err != nil {
		return err
	}
	if err := system.EnsureDir(HecateStreamDir); err != nil {
		return err
	}

	// Render and save StreamIncludeTemplate
	if err := os.WriteFile(HecateStreamIncludePath, []byte(StreamIncludeTemplate), 0644); err != nil {
		log.Error("Failed to write stream include config", zap.Error(err))
		return err
	}
	log.Info("✅ Wrote stream include config", zap.String("path", HecateStreamIncludePath))

	// Define services
	services := []struct {
		Name       string
		Blocks     []NginxStreamBlock
		OutputFile string
	}{
		{
			Name:       "mailcow",
			Blocks:     MailcowStreamBlocks,
			OutputFile: filepath.Join(HecateStreamDir, "mailcow.conf"),
		},
		{
			Name:       "jenkins",
			Blocks:     JenkinsStreamBlocks,
			OutputFile: filepath.Join(HecateStreamDir, "jenkins.conf"),
		},
		{
			Name:       "wazuh",
			Blocks:     WazuhStreamBlocks,
			OutputFile: filepath.Join(HecateStreamDir, "wazuh.conf"),
		},
	}

	// Render each service’s stream config
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

// CollateNginxFragments handles collation + writing of nginx.conf (only if fragments exist).
func CollateNginxFragments() error {
	if len(nginxFragments) > 0 {
		return CollateAndWriteFile(
			"hecate-nginx-collation",
			nginxFragments,
			HecateNginxConfig,
			BaseNginxConf,
			"",
			func(_ NginxFragment) string { return "" },
		)
	}
	zap.L().Named("hecate-nginx-collation").Info("No Nginx fragments to write; skipping nginx.conf")
	return nil
}
