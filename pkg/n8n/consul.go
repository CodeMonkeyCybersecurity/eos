package n8n

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"go.uber.org/zap"
)

// ConsulProxyConfig represents the configuration stored in Consul KV for reverse proxies
type ConsulProxyConfig struct {
	Service     string                 `json:"service"`
	Domain      string                 `json:"domain"`
	Backend     ConsulBackendConfig    `json:"backend"`
	SSL         ConsulSSLConfig        `json:"ssl"`
	Headers     map[string]string      `json:"headers"`
	Auth        ConsulAuthConfig       `json:"auth"`
	HealthCheck ConsulHealthCheckConfig `json:"health_check"`
}

type ConsulBackendConfig struct {
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
}

type ConsulSSLConfig struct {
	Enabled  bool `json:"enabled"`
	Redirect bool `json:"redirect"`
}

type ConsulAuthConfig struct {
	BasicAuth ConsulBasicAuthConfig `json:"basic_auth"`
}

type ConsulBasicAuthConfig struct {
	Enabled  bool   `json:"enabled"`
	Username string `json:"username"`
	Realm    string `json:"realm"`
}

type ConsulHealthCheckConfig struct {
	Path     string `json:"path"`
	Interval string `json:"interval"`
	Timeout  string `json:"timeout"`
}

// registerWithConsul registers n8n services with Consul using the CLI
func (m *Manager) registerWithConsul(ctx context.Context) error {
	logger := zap.L().With(zap.String("context", "consul_registration"))
	
	// Register n8n main service
	if err := m.registerConsulService(ctx, "n8n", m.config.Port, []string{"n8n", "workflow", "web"}); err != nil {
		return fmt.Errorf("failed to register n8n service: %w", err)
	}
	
	// Register PostgreSQL service
	if err := m.registerConsulService(ctx, "n8n-postgres", m.config.PostgresPort, []string{"postgres", "database"}); err != nil {
		return fmt.Errorf("failed to register postgres service: %w", err)
	}
	
	// Register Redis service
	if err := m.registerConsulService(ctx, "n8n-redis", m.config.RedisPort, []string{"redis", "cache"}); err != nil {
		return fmt.Errorf("failed to register redis service: %w", err)
	}
	
	logger.Info("All n8n services registered with Consul successfully")
	return nil
}

// registerConsulService registers a single service with Consul
func (m *Manager) registerConsulService(ctx context.Context, name string, port int, tags []string) error {
	logger := zap.L().With(zap.String("context", "consul_registration"))
	
	// Create service definition JSON
	serviceDef := map[string]interface{}{
		"ID":      fmt.Sprintf("%s-%s", name, m.config.Environment),
		"Name":    name,
		"Tags":    tags,
		"Address": "127.0.0.1",
		"Port":    port,
		"Check": map[string]interface{}{
			"HTTP":     fmt.Sprintf("http://127.0.0.1:%d/health", port),
			"Interval": "30s",
			"Timeout":  "10s",
		},
	}
	
	// Convert to JSON
	serviceJSON, err := json.Marshal(serviceDef)
	if err != nil {
		return fmt.Errorf("failed to marshal service definition: %w", err)
	}
	
	// Execute consul command to register service
	cmd := exec.CommandContext(ctx, "consul", "services", "register", "-")
	cmd.Stdin = strings.NewReader(string(serviceJSON))
	
	if err := cmd.Run(); err != nil {
		logger.Warn("Failed to register service with Consul CLI, this is expected if Consul is not running",
			zap.String("service", name),
			zap.Error(err))
		// Don't fail the deployment if Consul registration fails
		return nil
	}
	
	logger.Info("Service registered with Consul",
		zap.String("service", name),
		zap.Int("port", port),
		zap.Strings("tags", tags))
	
	return nil
}

// storeProxyConfig stores reverse proxy configuration in Consul KV
func (m *Manager) storeProxyConfig(ctx context.Context) error {
	logger := zap.L().With(zap.String("context", "consul_registration"))
	
	// Create proxy configuration
	config := ConsulProxyConfig{
		Service: "n8n",
		Domain:  m.config.Domain,
		Backend: ConsulBackendConfig{
			Protocol: "http",
			Host:     "n8n.service.consul",
			Port:     m.config.Port,
		},
		SSL: ConsulSSLConfig{
			Enabled:  true,
			Redirect: true,
		},
		Headers: map[string]string{
			"X-Frame-Options":           "DENY",
			"X-Content-Type-Options":    "nosniff",
			"X-XSS-Protection":          "1; mode=block",
			"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		},
		Auth: ConsulAuthConfig{
			BasicAuth: ConsulBasicAuthConfig{
				Enabled:  m.config.BasicAuthEnabled,
				Username: m.config.BasicAuthUser,
				Realm:    "n8n Access",
			},
		},
		HealthCheck: ConsulHealthCheckConfig{
			Path:     "/healthz",
			Interval: "30s",
			Timeout:  "10s",
		},
	}
	
	// Convert to JSON
	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal proxy config: %w", err)
	}
	
	// Store in Consul KV
	kvPath := fmt.Sprintf("proxy/services/%s", m.config.Domain)
	
	cmd := exec.CommandContext(ctx, "consul", "kv", "put", kvPath, string(configJSON))
	if err := cmd.Run(); err != nil {
		logger.Warn("Failed to store proxy config in Consul KV, this is expected if Consul is not running",
			zap.String("kv_path", kvPath),
			zap.Error(err))
		// Don't fail the deployment if Consul KV storage fails
		return nil
	}
	
	logger.Info("Reverse proxy configuration stored in Consul KV",
		zap.String("kv_path", kvPath),
		zap.String("domain", m.config.Domain))
	
	return nil
}

// GetNginxConfigFromConsul generates nginx configuration from Consul data
// This is an example of how a reverse proxy could consume the Consul configuration
func GetNginxConfigFromConsul(domain string) (string, error) {
	// This would typically be called by a separate nginx configuration manager
	// that watches Consul KV for changes
	
	kvPath := fmt.Sprintf("proxy/services/%s", domain)
	
	// Get configuration from Consul KV
	cmd := exec.Command("consul", "kv", "get", kvPath)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get proxy config from Consul: %w", err)
	}
	
	// Parse configuration
	var config ConsulProxyConfig
	if err := json.Unmarshal(output, &config); err != nil {
		return "", fmt.Errorf("failed to parse proxy config: %w", err)
	}
	
	// Generate nginx configuration
	nginxConfig := fmt.Sprintf(`
# Auto-generated nginx configuration for %s from Consul
upstream %s_backend {
    server %s:%d;
}

server {
    listen 80;
    server_name %s;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name %s;
    
    # SSL configuration would go here
    # ssl_certificate /etc/ssl/certs/%s.crt;
    # ssl_certificate_key /etc/ssl/private/%s.key;
    
    # Security headers
    add_header X-Frame-Options "%s";
    add_header X-Content-Type-Options "%s";
    add_header X-XSS-Protection "%s";
    add_header Strict-Transport-Security "%s";
    
    # Basic auth (if enabled)
    %s
    
    # Health check endpoint
    location %s {
        proxy_pass %s://%s:%d%s;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Main application
    location / {
        proxy_pass %s://%s:%d;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # WebSocket support for n8n
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_read_timeout 86400;
    }
}
`,
		config.Service,
		config.Service,
		config.Backend.Host,
		config.Backend.Port,
		config.Domain,
		config.Domain,
		config.Domain,
		config.Domain,
		config.Headers["X-Frame-Options"],
		config.Headers["X-Content-Type-Options"],
		config.Headers["X-XSS-Protection"],
		config.Headers["Strict-Transport-Security"],
		generateBasicAuthConfig(config.Auth.BasicAuth),
		config.HealthCheck.Path,
		config.Backend.Protocol,
		config.Backend.Host,
		config.Backend.Port,
		config.HealthCheck.Path,
		config.Backend.Protocol,
		config.Backend.Host,
		config.Backend.Port,
	)
	
	return nginxConfig, nil
}

func generateBasicAuthConfig(auth ConsulBasicAuthConfig) string {
	if !auth.Enabled {
		return "# Basic auth disabled"
	}
	
	return fmt.Sprintf(`auth_basic "%s";
    auth_basic_user_file /etc/nginx/.htpasswd;`, auth.Realm)
}
