// pkg/hecate/phase3_nginx.go

package hecate

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"go.uber.org/zap"
)

// SetupNginxEnvironment sets up the full Nginx configuration: directories, rendering, and placement.
func SetupNginxEnvironment(backendIP string) error {
	log := zap.L().Named("hecate-nginx-orchestrator")
	log.Info("🚀 Starting full Nginx setup for Hecate...")

	// Step 1: Ensure the directory structure is ready
	if err := EnsureNginxDirs(); err != nil {
		log.Error("Failed to set up Nginx directories", zap.Error(err))
		return err
	}

	// Step 2: Render the Nginx config files
	log.Info("Rendering Nginx config templates...")
	rendered, err := RenderNginxConfigs(backendIP)
	if err != nil {
		log.Error("Failed to render Nginx configs", zap.Error(err))
		return err
	}

	// Step 3: Move rendered configs into /opt/hecate
	log.Info("Moving Nginx config files to /opt/hecate...")
	if err := MoveNginxConfigsToHecate(rendered); err != nil {
		log.Error("Failed to move Nginx configs", zap.Error(err))
		return err
	}

	log.Info("✅ Full Nginx setup completed successfully!")
	return nil
}

func EnsureNginxDirs() error {
	baseDir := "/opt/hecate/assets/conf.d"
	streamDir := filepath.Join(baseDir, "stream")

	log := zap.L().Named("hecate-nginx-setup")

	dirs := []string{
		baseDir,
		streamDir,
	}

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

func RenderNginxConfigs(backendIP string) (map[string]string, error) {
	log := zap.L().Named("hecate-nginx-render")

	type cfg struct {
		BackendIP string
	}

	data := cfg{BackendIP: backendIP}

	templates := map[string]string{
		"mailcow.conf": MailcowStreamTemplate,
		"jenkins.conf": JenkinsStreamTemplate,
		"wazuh.conf":   WazuhStreamTemplate,
		// This one goes in conf.d (not in stream/)
		"delphi.stream.conf": StreamIncludeTemplate,
	}

	renderedFiles := make(map[string]string)

	for filename, tmplStr := range templates {
		tmpl, err := template.New(filename).Parse(tmplStr)
		if err != nil {
			log.Error("Failed to parse template", zap.String("file", filename), zap.Error(err))
			return nil, err
		}

		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, data); err != nil {
			log.Error("Failed to render template", zap.String("file", filename), zap.Error(err))
			return nil, err
		}

		renderedFiles[filename] = buf.String()
		log.Info("✅ Rendered Nginx config", zap.String("file", filename))
	}

	return renderedFiles, nil
}

func MoveNginxConfigsToHecate(rendered map[string]string) error {
	baseDir := "/opt/hecate/assets/conf.d"
	streamDir := filepath.Join(baseDir, "stream")

	log := zap.L().Named("hecate-nginx-move")

	for filename, content := range rendered {
		var destPath string
		if filename == "delphi.stream.conf" {
			// This goes in conf.d
			destPath = filepath.Join(baseDir, filename)
		} else {
			// All others go in stream/
			destPath = filepath.Join(streamDir, filename)
		}

		file, err := os.Create(destPath)
		if err != nil {
			log.Error("Failed to create config file", zap.String("path", destPath), zap.Error(err))
			return fmt.Errorf("failed to create %s: %w", destPath, err)
		}

		if _, err := file.WriteString(content); err != nil {
			log.Error("Failed to write config file", zap.String("path", destPath), zap.Error(err))
			file.Close()
			return fmt.Errorf("failed to write %s: %w", destPath, err)
		}

		file.Close()
		log.Info("✅ Wrote Nginx config to /opt/hecate", zap.String("path", destPath))
	}

	return nil
}
