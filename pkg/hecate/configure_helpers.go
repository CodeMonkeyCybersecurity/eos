package hecate

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConfigureBackend configures a backend route for Hecate
func ConfigureBackend(rc *eos_io.RuntimeContext, config *BackendConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Detect which backend is installed
	backend := DetectInstalledBackend()
	if backend == "" {
		return fmt.Errorf("no reverse proxy backend found")
	}
	
	logger.Info("Configuring backend route",
		zap.String("name", config.Name),
		zap.String("domain", config.Domain),
		zap.String("backend", backend))
	
	switch backend {
	case "nginx":
		return configureNginxBackend(rc, config)
	case "caddy":
		return configureCaddyBackend(rc, config)
	default:
		return fmt.Errorf("unsupported backend: %s", backend)
	}
}

// configureNginxBackend configures an nginx backend
func configureNginxBackend(rc *eos_io.RuntimeContext, config *BackendConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Simple nginx upstream configuration template
	const nginxTemplate = `# Backend: {{ .Name }}
upstream {{ .Name }}_backend {
    {{- range .Upstreams }}
    server {{ . }};
    {{- end }}
}

server {
    listen 80;
    server_name {{ .Domain }};
    
    location / {
        proxy_pass http://{{ .Name }}_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
`
	
	// Parse and execute template
	tmpl, err := template.New("nginx").Parse(nginxTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse nginx template: %w", err)
	}
	
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, config); err != nil {
		return fmt.Errorf("failed to execute nginx template: %w", err)
	}
	
	// Write configuration file
	configFile := fmt.Sprintf("/etc/nginx/sites-available/%s", config.Name)
	if err := os.WriteFile(configFile, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write nginx config: %w", err)
	}
	
	// Enable site
	enabledFile := fmt.Sprintf("/etc/nginx/sites-enabled/%s", config.Name)
	if err := os.Symlink(configFile, enabledFile); err != nil && !os.IsExist(err) {
		return fmt.Errorf("failed to enable nginx site: %w", err)
	}
	
	// Test configuration
	if err := TestNginxConfig(rc); err != nil {
		// Remove the bad configuration
		os.Remove(enabledFile)
		os.Remove(configFile)
		return fmt.Errorf("nginx configuration test failed: %w", err)
	}
	
	// Reload nginx
	if err := ReloadNginx(rc); err != nil {
		return fmt.Errorf("failed to reload nginx: %w", err)
	}
	
	logger.Info("Nginx backend configured successfully", 
		zap.String("name", config.Name),
		zap.String("config_file", configFile))
	
	return nil
}

// configureCaddyBackend configures a Caddy backend
func configureCaddyBackend(rc *eos_io.RuntimeContext, config *BackendConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Simple Caddyfile template
	const caddyTemplate = `# Backend: {{ .Name }}
{{ .Domain }} {
    reverse_proxy {{ range .Upstreams }}{{ . }} {{ end }}
}
`
	
	// Parse and execute template
	tmpl, err := template.New("caddy").Parse(caddyTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse caddy template: %w", err)
	}
	
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, config); err != nil {
		return fmt.Errorf("failed to execute caddy template: %w", err)
	}
	
	// Write configuration file
	configFile := fmt.Sprintf("/etc/caddy/sites/%s.caddy", config.Name)
	configDir := filepath.Dir(configFile)
	
	// Create sites directory if it doesn't exist
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create caddy sites directory: %w", err)
	}
	
	if err := os.WriteFile(configFile, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write caddy config: %w", err)
	}
	
	// Update main Caddyfile to import sites
	mainCaddyfile := "/etc/caddy/Caddyfile"
	importLine := "import /etc/caddy/sites/*.caddy\n"
	
	// Check if import already exists
	content, err := os.ReadFile(mainCaddyfile)
	if err == nil && !bytes.Contains(content, []byte(importLine)) {
		// Append import line
		f, err := os.OpenFile(mainCaddyfile, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open Caddyfile: %w", err)
		}
		defer f.Close()
		
		if _, err := f.WriteString("\n" + importLine); err != nil {
			return fmt.Errorf("failed to update Caddyfile: %w", err)
		}
	}
	
	// Reload Caddy
	if err := ReloadCaddy(rc); err != nil {
		return fmt.Errorf("failed to reload caddy: %w", err)
	}
	
	logger.Info("Caddy backend configured successfully", 
		zap.String("name", config.Name),
		zap.String("config_file", configFile))
	
	return nil
}

// ReloadCaddy reloads the Caddy service
func ReloadCaddy(rc *eos_io.RuntimeContext) error {
	return EnableService(rc, "caddy")
}

// RemoveBackend removes a backend configuration
func RemoveBackend(rc *eos_io.RuntimeContext, name string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	backend := DetectInstalledBackend()
	if backend == "" {
		return fmt.Errorf("no reverse proxy backend found")
	}
	
	logger.Info("Removing backend configuration",
		zap.String("name", name),
		zap.String("backend", backend))
	
	switch backend {
	case "nginx":
		// Remove nginx configuration
		configFile := fmt.Sprintf("/etc/nginx/sites-available/%s", name)
		enabledFile := fmt.Sprintf("/etc/nginx/sites-enabled/%s", name)
		
		os.Remove(enabledFile)
		os.Remove(configFile)
		
		// Reload nginx
		if err := ReloadNginx(rc); err != nil {
			logger.Warn("Failed to reload nginx after removing backend", zap.Error(err))
		}
		
	case "caddy":
		// Remove caddy configuration
		configFile := fmt.Sprintf("/etc/caddy/sites/%s.caddy", name)
		os.Remove(configFile)
		
		// Reload caddy
		if err := ReloadCaddy(rc); err != nil {
			logger.Warn("Failed to reload caddy after removing backend", zap.Error(err))
		}
	}
	
	logger.Info("Backend configuration removed", zap.String("name", name))
	return nil
}

// ListBackends lists all configured backends
func ListBackends() ([]string, error) {
	backend := DetectInstalledBackend()
	if backend == "" {
		return nil, fmt.Errorf("no reverse proxy backend found")
	}
	
	var configDir string
	var pattern string
	
	switch backend {
	case "nginx":
		configDir = "/etc/nginx/sites-enabled"
		pattern = "*"
	case "caddy":
		configDir = "/etc/caddy/sites"
		pattern = "*.caddy"
	default:
		return nil, fmt.Errorf("unsupported backend: %s", backend)
	}
	
	matches, err := filepath.Glob(filepath.Join(configDir, pattern))
	if err != nil {
		return nil, fmt.Errorf("failed to list backends: %w", err)
	}
	
	var backends []string
	for _, match := range matches {
		base := filepath.Base(match)
		// Remove extension for caddy files
		if backend == "caddy" {
			base = base[:len(base)-6] // Remove .caddy
		}
		// Skip default site for nginx
		if backend == "nginx" && base == "default" {
			continue
		}
		backends = append(backends, base)
	}
	
	return backends, nil
}

