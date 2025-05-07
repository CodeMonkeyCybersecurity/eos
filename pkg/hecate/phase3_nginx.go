// pkg/hecate/phase3_nginx.go

package hecate

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"go.uber.org/zap"
)

// PhaseNginx sets up Nginx configs as phase 3 of Hecate.
// This is the thin wrapper that can be called by the lifecycle orchestrator.
func PhaseNginx(backendIP string) error {
	log := zap.L().Named("hecate-phase-nginx")
	log.Info("🚀 Starting Phase 3: Build and setup Nginx...")

	// Always ensure directory structure first.
	if err := EnsureNginxDirs(); err != nil {
		return fmt.Errorf("failed to ensure Nginx dirs: %w", err)
	}

	// If backend IP is empty, skip full config generation (allows noop runs)
	if backendIP == "" {
		log.Info("No backend IP provided; skipping Nginx stream block generation")
		return nil
	}

	// Actually build and deploy the Nginx configs.
	return BuildNginxEnvironment(backendIP)
}

// BuildNginxEnvironment sets up Nginx configs (stream + include templates).
// This matches the "build phase" pattern.
func BuildNginxEnvironment(backendIP string) error {
	log := zap.L().Named("hecate-nginx-builder")
	log.Info("🚀 Building Nginx configs for Hecate...")

	// Step 1: Render and save StreamIncludeTemplate
	if err := os.WriteFile(HecateStreamIncludePath, []byte(StreamIncludeTemplate), 0644); err != nil {
		log.Error("Failed to write stream include config", zap.Error(err))
		return err
	}
	log.Info("✅ Wrote stream include config", zap.String("path", HecateStreamIncludePath))

	// Step 2: Define services
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

	// Step 3: Render each service’s stream config
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

	log.Info("✅ Full Nginx build completed successfully!")
	return nil
}

// EnsureNginxDirs ensures necessary Nginx directories exist.
func EnsureNginxDirs() error {
	log := zap.L().Named("hecate-nginx-setup")

	dirs := []string{HecateConfDDir, HecateStreamDir}
	if err := system.EnsureDirs(dirs); err != nil {
		log.Error("Failed to ensure Nginx directories", zap.Error(err))
		return err
	}

	log.Info("✅ Nginx directory structure ready")
	return nil
}

// CollateNginxFragments handles collation + writing of nginx.conf (only if fragments exist).
func CollateNginxFragments() error {
	log := zap.L().Named("hecate-nginx-collation")

	if len(nginxFragments) > 0 {
		return CollateAndWriteFile(
			"hecate-nginx-collation",
			nginxFragments,
			HecateNginxConfig,
			BaseNginxConf,
			"",
			func(_ NginxFragment) string { return "" }, // TODO: Add proper rendering if needed
		)
	}

	log.Info("No Nginx fragments to write; skipping nginx.conf")
	return nil
}
