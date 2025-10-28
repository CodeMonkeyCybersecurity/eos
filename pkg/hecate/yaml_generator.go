// pkg/hecate/yaml_generator.go

package hecate

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/docker"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/secrets"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// HecateSecrets holds generated secrets for Hecate services
type HecateSecrets struct {
	PGPass                     string
	PGUser                     string
	PGDatabase                 string
	AuthentikSecretKey         string
	AuthentikTag               string
	ComposePortHTTP            string
	ComposePortHTTPS           string
	AuthentikWorkerThreads     string
	AuthentikBootstrapEmail    string
	AuthentikBootstrapPassword string
	AuthentikBootstrapToken    string
}

// generateYAMLHecateSecrets generates or retrieves all required secrets for Hecate YAML mode
// generateSimpleSecrets generates secrets locally without Vault storage
// TEMPORARY (2025-10-28): Simple secret generation for 6-month deferral period
// See ROADMAP.md "Hecate Consul KV + Vault Integration" for migration plan
func generateSimpleSecrets(rc *eos_io.RuntimeContext, config *YAMLHecateConfig) (*HecateSecrets, *string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Fetch latest Authentik version
	authentikVersion, err := GetLatestAuthentikVersion(rc)
	if err != nil {
		logger.Warn("Failed to fetch latest Authentik version, using default",
			zap.Error(err),
			zap.String("default", DefaultAuthentikVersion))
		authentikVersion = DefaultAuthentikVersion
	}

	logger.Info("Using Authentik version",
		zap.String("version", authentikVersion),
		zap.String("image", fmt.Sprintf("%s:%s", AuthentikImage, authentikVersion)))

	// Populate HecateSecrets with generated secrets
	hecateSecrets := &HecateSecrets{
		PGUser:                 "authentik",
		PGDatabase:             "authentik",
		AuthentikTag:           authentikVersion,
		ComposePortHTTP:        "9000",
		ComposePortHTTPS:       "9443",
		AuthentikWorkerThreads: "4",
	}

	if config.HasAuthentik {
		// Generate secrets using crypto package (same as Vault would do)
		pgPass, err := crypto.GeneratePassword(32)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate postgres password: %w", err)
		}
		hecateSecrets.PGPass = pgPass

		authKey, err := crypto.GeneratePassword(64)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate authentik secret key: %w", err)
		}
		hecateSecrets.AuthentikSecretKey = authKey

		bootstrapPass, err := crypto.GeneratePassword(32)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate bootstrap password: %w", err)
		}
		hecateSecrets.AuthentikBootstrapPassword = bootstrapPass

		bootstrapToken, err := crypto.GenerateToken(32)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate bootstrap token: %w", err)
		}
		hecateSecrets.AuthentikBootstrapToken = bootstrapToken
		hecateSecrets.AuthentikBootstrapEmail = "admin@localhost"

		logger.Info("Generated Authentik secrets locally",
			zap.String("postgres_user", hecateSecrets.PGUser),
			zap.String("postgres_db", hecateSecrets.PGDatabase),
			zap.String("storage", ".env files"))
	}

	var coturnSecret *string
	if config.NeedsCoturn {
		secret, err := crypto.GeneratePassword(32)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate coturn secret: %w", err)
		}
		coturnSecret = &secret
		logger.Info("Generated Coturn static auth secret")
	}

	logger.Info("All Hecate secrets generated successfully (stored in .env files)",
		zap.Bool("has_authentik", config.HasAuthentik),
		zap.Bool("has_coturn", config.NeedsCoturn))

	return hecateSecrets, coturnSecret, nil
}

func generateYAMLHecateSecrets(rc *eos_io.RuntimeContext, secretManager *secrets.SecretManager, config *YAMLHecateConfig) (*HecateSecrets, *string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Define all required secrets
	requiredSecrets := make(map[string]secrets.SecretType)

	if config.HasAuthentik {
		requiredSecrets["pg_pass"] = secrets.SecretTypePassword
		requiredSecrets["authentik_secret_key"] = secrets.SecretTypePassword
		requiredSecrets["authentik_bootstrap_password"] = secrets.SecretTypePassword
		requiredSecrets["authentik_bootstrap_token"] = secrets.SecretTypeToken
	}

	var coturnSecret *string
	if config.NeedsCoturn {
		requiredSecrets["coturn_static_auth_secret"] = secrets.SecretTypePassword
	}

	// Generate or retrieve secrets
	logger.Info("Generating Hecate secrets",
		zap.Int("secret_count", len(requiredSecrets)))

	serviceSecrets, err := secretManager.GetOrGenerateServiceSecrets("hecate", requiredSecrets)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to manage secrets: %w", err)
	}

	// Fetch latest Authentik version
	authentikVersion, err := GetLatestAuthentikVersion(rc)
	if err != nil {
		logger.Warn("Failed to fetch latest Authentik version, using default",
			zap.Error(err),
			zap.String("default", DefaultAuthentikVersion))
		authentikVersion = DefaultAuthentikVersion
	}

	logger.Info("Using Authentik version",
		zap.String("version", authentikVersion),
		zap.String("image", fmt.Sprintf("%s:%s", AuthentikImage, authentikVersion)))

	// Populate HecateSecrets using the existing type structure
	hecateSecrets := &HecateSecrets{
		PGUser:                 "authentik",
		PGDatabase:             "authentik",
		AuthentikTag:           authentikVersion,
		ComposePortHTTP:        "9000",
		ComposePortHTTPS:       "9443",
		AuthentikWorkerThreads: "4",
	}

	if config.HasAuthentik {
		pgPass, ok := serviceSecrets.Secrets["pg_pass"].(string)
		if !ok {
			pgPass = fmt.Sprintf("%v", serviceSecrets.Secrets["pg_pass"])
		}
		// Trim whitespace and newlines to prevent corruption in .env file
		hecateSecrets.PGPass = strings.TrimSpace(pgPass)

		authKey, ok := serviceSecrets.Secrets["authentik_secret_key"].(string)
		if !ok {
			authKey = fmt.Sprintf("%v", serviceSecrets.Secrets["authentik_secret_key"])
		}
		hecateSecrets.AuthentikSecretKey = strings.TrimSpace(authKey)

		bootstrapPass, ok := serviceSecrets.Secrets["authentik_bootstrap_password"].(string)
		if !ok {
			bootstrapPass = fmt.Sprintf("%v", serviceSecrets.Secrets["authentik_bootstrap_password"])
		}
		hecateSecrets.AuthentikBootstrapPassword = strings.TrimSpace(bootstrapPass)

		bootstrapToken, ok := serviceSecrets.Secrets["authentik_bootstrap_token"].(string)
		if !ok {
			bootstrapToken = fmt.Sprintf("%v", serviceSecrets.Secrets["authentik_bootstrap_token"])
		}
		hecateSecrets.AuthentikBootstrapToken = strings.TrimSpace(bootstrapToken)
		hecateSecrets.AuthentikBootstrapEmail = "admin@localhost"

		logger.Info("Generated Authentik secrets",
			zap.String("postgres_user", hecateSecrets.PGUser),
			zap.String("postgres_db", hecateSecrets.PGDatabase),
			zap.String("backend", serviceSecrets.Backend))
	}

	if config.NeedsCoturn {
		secret, ok := serviceSecrets.Secrets["coturn_static_auth_secret"].(string)
		if !ok {
			secret = fmt.Sprintf("%v", serviceSecrets.Secrets["coturn_static_auth_secret"])
		}
		trimmedSecret := strings.TrimSpace(secret)
		coturnSecret = &trimmedSecret
		logger.Info("Generated Coturn static auth secret")
	}

	logger.Info("All Hecate secrets generated successfully",
		zap.String("backend", serviceSecrets.Backend),
		zap.Bool("has_authentik", config.HasAuthentik),
		zap.Bool("has_coturn", config.NeedsCoturn))

	return hecateSecrets, coturnSecret, nil
}

const caddyfileTemplate = `# Hecate Caddyfile - Generated by EOS
# Global logging configuration
{
	log {
		output file /var/log/caddy/access.log
		format json
		level INFO
	}
}

# Security snippet - Block scanners and malicious patterns
(security) {
	@blocked {
		header Cf-Worker *
		header Cf-Connecting-Ip *
		header Cf-Ray *
	}
	respond @blocked 404

	@scanners {
		path /wp-admin/* /wp-login.php /wordpress/* /.git/* /.env /phpmyadmin/*
		path /config.json /.DS_Store /info.php /phpinfo.php /test.php
		path /telescope/* /horizon/* /pulse/*
		path /.well-known/security.txt /.svn/* /.hg/*
		path /backup/* /old/* /temp/* /tmp/* /sql/*
		path /admin/* /manager/* /shell.php
		path_regexp (/(vendor|node_modules|bower_components)/|\.(sql|bak|backup|log|old|orig|original|save|swp|tmp)$|\?rest_route=)
	}
	respond @scanners 404

	@suspicious_agents {
		header_regexp User-Agent (?i)(bot|crawler|spider|scraper|scan|exploit|nikto|sqlmap|havij|acunetix)
		header User-Agent "Go-http-client/1.1"
	}
	respond @suspicious_agents 444
}

# Common headers and settings
(cybermonkey_common) {
	import security
	encode gzip

	log {
		format json
		level INFO
	}

	header {
		X-Frame-Options "SAMEORIGIN"
		X-Content-Type-Options "nosniff"
		Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
		Referrer-Policy "strict-origin-when-cross-origin"
		X-XSS-Protection "1; mode=block"
		-Server
	}
}

{{range $name, $app := .Apps}}
# {{$name}} ({{$app.Type}})
{{$app.Domain}} {
	import cybermonkey_common
	{{if eq $app.LogLevel "DEBUG"}}
	log {
		output file /var/log/caddy/{{$name}}-{{$app.Type}}.log
		format json
		level DEBUG
	}
	{{end}}
	{{if $app.SSO}}
	# Authentik SSO forward auth
	forward_auth hecate-server-1:9000 {
		uri /outpost.goauthentik.io/auth/caddy
		copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Email
	}
	{{if $app.SSOPublicPaths}}
	# Public paths (no authentication required)
	@public {
		path {{range $app.SSOPublicPaths}}{{.}}* {{end}}
	}
	handle @public {
		{{if and (eq $app.BackendProtocol "https") $app.TLSSkipVerify}}
		reverse_proxy {{$app.BackendProtocol}}://{{$app.Backend}}:{{$app.BackendPort}} {
			transport http {
				tls
				tls_insecure_skip_verify
			}
		}
		{{else}}
		reverse_proxy {{$app.BackendProtocol}}://{{$app.Backend}}:{{$app.BackendPort}}
		{{end}}
	}
	{{end}}
	{{end}}
	{{if and (eq $app.BackendProtocol "https") $app.TLSSkipVerify}}
	reverse_proxy {{$app.BackendProtocol}}://{{$app.Backend}}:{{$app.BackendPort}} {
		transport http {
			tls
			tls_insecure_skip_verify
		}
	}
	{{else}}
	reverse_proxy {{$app.BackendProtocol}}://{{$app.Backend}}:{{$app.BackendPort}}
	{{end}}
}

{{end}}
`

const dockerComposeTemplate = `# Hecate Docker Compose - Generated by EOS
services:
  caddy:
    image: caddy:latest
    container_name: hecate-caddy
    restart: always
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
      - "127.0.0.1:2019:2019"  # Admin API (localhost-only for security)
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ./logs/caddy:/var/log/caddy:rw
      - caddy_data:/data
      - caddy_config:/config
    networks:
      - hecate-net

{{if .NeedsNginx}}
  nginx:
    image: nginx
    container_name: hecate-nginx
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./conf.d:/etc/nginx/conf.d:ro
      - ./logs/nginx:/var/log/nginx
    ports:
{{range .TCPPorts}}      - "{{.}}:{{.}}"
{{end}}
    restart: always
    networks:
      - hecate-net
{{end}}

{{if .NeedsCoturn}}
  coturn:
    image: coturn/coturn
    restart: always
    container_name: hecate-coturn
    ports:
      - "3478:3478"
      - "3478:3478/udp"
      - "5349:5349"
      - "5349:5349/udp"
      - "49160-49200:49160-49200/udp"
    environment:
      DETECT_EXTERNAL_IP: "yes"
      DETECT_RELAY_IP: "yes"
    volumes:
      - ./certs:/etc/coturn/certs:ro
      - ./logs/coturn:/var/log
    command: >
      turnserver
      --listening-port=3478
      --listening-ip=0.0.0.0
      --fingerprint
      --no-cli
      --min-port=49160
      --max-port=49200
      --log-file=/var/log/coturn.log
      --static-auth-secret={{.CoturnSecret}}
      --verbose
    networks:
      - hecate-net
{{end}}

{{if .HasAuthentik}}
  postgresql:
    image: docker.io/library/postgres:16-alpine
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -d ${PG_DB} -U ${PG_USER}"]
      start_period: 20s
      interval: 30s
      retries: 5
      timeout: 5s
    volumes:
      - database:/var/lib/postgresql/data
    environment:
      POSTGRES_PASSWORD: ${PG_PASS:?database password required}
      POSTGRES_USER: ${PG_USER:-authentik}
      POSTGRES_DB: ${PG_DB:-authentik}
    env_file:
      - .env
    networks:
      - hecate-net

  redis:
    image: docker.io/library/redis:alpine
    command: --save 60 1 --loglevel warning
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "redis-cli ping | grep PONG"]
      start_period: 20s
      interval: 30s
      retries: 5
      timeout: 3s
    volumes:
      - redis:/data
    networks:
      - hecate-net

  server:
    image: ${AUTHENTIK_IMAGE:-ghcr.io/goauthentik/server}:${AUTHENTIK_TAG:-2025.8}
    restart: unless-stopped
    command: server
    container_name: hecate-server-1
    environment:
      AUTHENTIK_SECRET_KEY: ${AUTHENTIK_SECRET_KEY:?secret key required}
      AUTHENTIK_REDIS__HOST: redis
      AUTHENTIK_POSTGRESQL__HOST: postgresql
      AUTHENTIK_POSTGRESQL__USER: ${PG_USER:-authentik}
      AUTHENTIK_POSTGRESQL__NAME: ${PG_DB:-authentik}
      AUTHENTIK_POSTGRESQL__PASSWORD: ${PG_PASS}
      AUTHENTIK_WORKER__THREADS: ${AUTHENTIK_WORKER__THREADS:-4}
    volumes:
      - ./media:/media
      - ./custom-templates:/templates
    env_file:
      - .env
    ports:
      - "${COMPOSE_PORT_HTTP:-9000}:9000"
      - "${COMPOSE_PORT_HTTPS:-9443}:9443"
    depends_on:
      postgresql:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - hecate-net

  worker:
    image: ${AUTHENTIK_IMAGE:-ghcr.io/goauthentik/server}:${AUTHENTIK_TAG:-2025.8}
    restart: unless-stopped
    command: worker
    environment:
      AUTHENTIK_SECRET_KEY: ${AUTHENTIK_SECRET_KEY:?secret key required}
      AUTHENTIK_REDIS__HOST: redis
      AUTHENTIK_POSTGRESQL__HOST: postgresql
      AUTHENTIK_POSTGRESQL__USER: ${PG_USER:-authentik}
      AUTHENTIK_POSTGRESQL__NAME: ${PG_DB:-authentik}
      AUTHENTIK_POSTGRESQL__PASSWORD: ${PG_PASS}
      AUTHENTIK_WORKER__THREADS: ${AUTHENTIK_WORKER__THREADS:-4}
    user: root
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./media:/media
      - ./certs:/certs
      - ./custom-templates:/templates
    env_file:
      - .env
    depends_on:
      postgresql:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - hecate-net
{{end}}

networks:
  hecate-net:

volumes:
{{if .HasAuthentik}}  database:
    driver: local
  redis:
{{end}}  caddy_data:
  caddy_config:
`

type dockerComposeData struct {
	*YAMLHecateConfig
	TCPPorts     []int
	CoturnSecret string
}

// GenerateFromYAML creates all infrastructure configuration files from a YAML config
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Validate output directory and YAML config, discover environment
// - Intervene: Generate docker-compose.yml, Caddyfile, and optional nginx configs with secrets
// - Evaluate: Verify all files were created successfully
func GenerateFromYAML(rc *eos_io.RuntimeContext, config *YAMLHecateConfig, outputDir string, envConfig interface{}) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Generating Hecate infrastructure from YAML",
		zap.String("output_dir", outputDir),
		zap.Int("app_count", len(config.Apps)))

	// Pre-operation diagnostics
	logger.Debug("Pre-generation diagnostics",
		zap.String("output_dir", outputDir),
		zap.Int("app_count", len(config.Apps)),
		zap.Bool("has_authentik", config.HasAuthentik),
		zap.Bool("needs_coturn", config.NeedsCoturn),
		zap.Bool("needs_nginx", config.NeedsNginx))

	// ASSESS - Check and create output directory with idempotency
	if stat, err := os.Stat(outputDir); err == nil {
		if !stat.IsDir() {
			return fmt.Errorf("output path exists but is not a directory: %s\n"+
				"Please specify a different output path with --output", outputDir)
		}
		logger.Info("Output directory already exists", zap.String("path", outputDir))
	} else if os.IsNotExist(err) {
		logger.Info("Creating output directory", zap.String("path", outputDir))
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory %s: %w\n"+
				"Possible causes:\n"+
				"  - Permission denied (try: sudo eos create hecate ...)\n"+
				"  - Parent directory doesn't exist\n"+
				"  - Disk full", outputDir, err)
		}
	} else {
		return fmt.Errorf("failed to check output directory: %w", err)
	}

	// Create logs directories
	logsDir := filepath.Join(outputDir, "logs")
	if err := os.MkdirAll(filepath.Join(logsDir, "caddy"), 0755); err != nil {
		return fmt.Errorf("failed to create logs directory: %w", err)
	}

	// Initialize secrets if we need them (Authentik or Coturn)
	// DEFERRED (2025-10-28): Vault integration deferred to April-May 2026
	var hecateSecrets *HecateSecrets
	var coturnSecret *string

	if config.HasAuthentik || config.NeedsCoturn {
		// DEFERRED (2025-10-28): Vault/Consul integration deferred to April-May 2026
		// See ROADMAP.md "Hecate Consul KV + Vault Integration" section
		// For now, generate secrets directly without Vault storage
		logger.Info("Generating secrets locally (Vault integration deferred to 2026)")

		// Simple secret generation without Vault
		var err error
		hecateSecrets, coturnSecret, err = generateSimpleSecrets(rc, config)
		if err != nil {
			return fmt.Errorf("failed to generate secrets: %w", err)
		}

		logger.Info("Secrets generated successfully (stored in .env files)")
	}

	// INTERVENE - Generate docker-compose.yml
	if err := generateYAMLDockerCompose(config, outputDir, coturnSecret); err != nil {
		return fmt.Errorf("failed to generate docker-compose.yml: %w", err)
	}
	logger.Info("Generated docker-compose.yml")

	// Generate Caddyfile
	if err := generateYAMLCaddyfile(config, outputDir); err != nil {
		return fmt.Errorf("failed to generate Caddyfile: %w", err)
	}
	logger.Info("Generated Caddyfile")

	// Generate Nginx configs if needed
	if config.NeedsNginx {
		if err := generateYAMLNginxConfig(config, outputDir); err != nil {
			return fmt.Errorf("failed to generate nginx config: %w", err)
		}
		logger.Info("Generated nginx.conf")
	}

	// Generate .env file with real secrets if Authentik is present
	// CRITICAL: This must be generated BEFORE validation since docker-compose.yml references it
	if config.HasAuthentik {
		if err := generateYAMLEnvFile(rc, outputDir, hecateSecrets); err != nil {
			return fmt.Errorf("failed to generate .env file: %w", err)
		}
		logger.Info("Generated .env file with secure credentials")
	}

	// Configure system-level sysctl parameters for Caddy UDP buffer optimization
	// Required for QUIC/HTTP3 performance with large numbers of connections
	logger.Info("Configuring sysctl parameters for Caddy UDP buffer optimization")
	if err := configureCaddySysctl(rc); err != nil {
		// Non-fatal - log warning and continue
		logger.Warn("Failed to configure sysctl parameters (Caddy will work but QUIC/HTTP3 may be slower)",
			zap.Error(err),
			zap.String("remediation", "Run manually: sudo sysctl -w net.core.rmem_max=2500000 && sudo sysctl -w net.core.wmem_max=2500000"))
	} else {
		logger.Info("✓ System UDP buffers configured for Caddy QUIC/HTTP3 performance")
	}

	// Configure firewall rules for Hecate (HTTP, HTTPS, QUIC/HTTP3)
	// CRITICAL: UDP/443 required for QUIC/HTTP3 support
	logger.Info("Configuring firewall rules for Hecate")
	if err := configureHecateFirewall(rc); err != nil {
		// Non-fatal - log warning and continue
		logger.Warn("Failed to configure firewall rules (Hecate will work but may not be accessible)",
			zap.Error(err),
			zap.String("remediation", "Configure manually: sudo ufw allow 80/tcp && sudo ufw allow 443/tcp && sudo ufw allow 443/udp"))
	} else {
		logger.Info("✓ Firewall rules configured (TCP/80, TCP/443, UDP/443 for QUIC/HTTP3)")
	}

	// EVALUATE: Validate docker-compose.yml AFTER all files are generated
	// This validation is informational only - we don't fail the operation since files are already written
	logger.Debug("Validating docker-compose.yml syntax")
	composeFile := filepath.Join(outputDir, "docker-compose.yml")
	envFile := filepath.Join(outputDir, ".env")
	if err := docker.ValidateComposeWithShellFallback(rc.Ctx, composeFile, envFile); err != nil {
		logger.Warn("Docker compose validation found issues (continuing anyway)",
			zap.Error(err))
		// Don't show terminal prompt here - this is handled by ValidateGeneratedFiles in cmd/
	} else {
		logger.Debug("Docker compose validation passed")
	}

	logger.Info("Successfully generated all configuration files")
	return nil
}

// generateDockerCompose creates the docker-compose.yml file
func generateYAMLDockerCompose(config *YAMLHecateConfig, outputDir string, coturnSecret *string) error {
	// Collect all TCP ports
	tcpPortsMap := make(map[int]bool)
	for _, app := range config.Apps {
		for port := range app.TCPPorts {
			tcpPortsMap[port] = true
		}
	}

	// Convert to sorted slice
	tcpPorts := make([]int, 0, len(tcpPortsMap))
	for port := range tcpPortsMap {
		tcpPorts = append(tcpPorts, port)
	}
	sort.Ints(tcpPorts)

	// Prepare data for template
	data := dockerComposeData{
		YAMLHecateConfig: config,
		TCPPorts:         tcpPorts,
	}

	// Add Coturn secret if needed
	if config.NeedsCoturn && coturnSecret != nil {
		data.CoturnSecret = *coturnSecret
	}

	tmpl, err := template.New("docker-compose").Parse(dockerComposeTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	outputPath := filepath.Join(outputDir, "docker-compose.yml")
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	return nil
}

// generateCaddyfile creates the Caddyfile
func generateYAMLCaddyfile(config *YAMLHecateConfig, outputDir string) error {
	tmpl, err := template.New("caddyfile").Parse(caddyfileTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	outputPath := filepath.Join(outputDir, "Caddyfile")
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err := tmpl.Execute(f, config); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	return nil
}

const nginxConfTemplate = `user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

stream {
    include /etc/nginx/conf.d/stream/*.conf;
}
`

const nginxStreamTemplate = `# {{.AppName}} TCP/UDP streams

{{range $extPort, $backendPort := .TCPPorts}}
upstream {{$.AppName}}_{{$extPort}} {
    server {{$.Backend}}:{{$backendPort}};
}
server {
    listen {{$extPort}};
    proxy_pass {{$.AppName}}_{{$extPort}};
}
{{end}}
`

type nginxStreamData struct {
	AppName  string
	Backend  string
	TCPPorts map[int]int
}

// generateNginxConfig creates nginx.conf and stream configs
func generateYAMLNginxConfig(config *YAMLHecateConfig, outputDir string) error {
	// Create nginx.conf
	nginxConfPath := filepath.Join(outputDir, "nginx.conf")
	if err := os.WriteFile(nginxConfPath, []byte(nginxConfTemplate), 0644); err != nil {
		return fmt.Errorf("failed to write nginx.conf: %w", err)
	}

	// Create stream directory
	streamDir := filepath.Join(outputDir, "conf.d", "stream")
	if err := os.MkdirAll(streamDir, 0755); err != nil {
		return fmt.Errorf("failed to create stream dir: %w", err)
	}

	// Create stream config for each app with TCP/UDP ports
	tmpl, err := template.New("nginx-stream").Parse(nginxStreamTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	for appName, app := range config.Apps {
		if len(app.TCPPorts) == 0 {
			continue
		}

		data := nginxStreamData{
			AppName:  appName,
			Backend:  app.Backend,
			TCPPorts: app.TCPPorts,
		}

		streamPath := filepath.Join(streamDir, fmt.Sprintf("%s.conf", appName))
		f, err := os.Create(streamPath)
		if err != nil {
			return fmt.Errorf("failed to create stream config: %w", err)
		}

		if err := tmpl.Execute(f, data); err != nil {
			_ = f.Close()
			return fmt.Errorf("failed to execute template: %w", err)
		}
		_ = f.Close()
	}

	return nil
}

// escapeEnvValue escapes special characters in .env values to prevent Docker Compose variable expansion
// Docker Compose interprets $VAR as variable references, so we need to escape $ as $$
func escapeEnvValue(value string) string {
	// Escape $ as $$ for Docker Compose .env files
	// https://docs.docker.com/compose/environment-variables/env-file/#syntax
	return strings.ReplaceAll(value, "$", "$$")
}

// generateEnvFile creates a .env file with real secrets from SecretManager
func generateYAMLEnvFile(rc *eos_io.RuntimeContext, outputDir string, hecateSecrets *HecateSecrets) error {
	logger := otelzap.Ctx(rc.Ctx)

	if hecateSecrets == nil {
		return fmt.Errorf("hecateSecrets is nil - cannot generate .env file")
	}

	// Generate .env content with real secrets (escape $ characters to prevent variable expansion)
	envContent := fmt.Sprintf(`# Hecate Environment Variables - Generated by EOS
# Secrets managed by SecretManager (Vault/Consul/File)
# DO NOT commit this file to version control!

# PostgreSQL Database
PG_PASS=%s
PG_USER=%s
PG_DB=%s

# Authentik
AUTHENTIK_SECRET_KEY=%s
AUTHENTIK_TAG=%s
AUTHENTIK_IMAGE=ghcr.io/goauthentik/server
AUTHENTIK_WORKER__THREADS=%s

# Authentik Bootstrap Credentials - ADMIN LOGIN CREDENTIALS
# Use these to login to Authentik admin UI: https://hera.your-domain/if/admin/
#
# NOTE: If these values are missing, retrieve from Consul KV:
#   consul kv get hecate/secrets/authentik/bootstrap_email
#   consul kv get hecate/secrets/authentik/bootstrap_password
#
AUTHENTIK_BOOTSTRAP_EMAIL=%s
AUTHENTIK_BOOTSTRAP_PASSWORD=%s
AUTHENTIK_BOOTSTRAP_TOKEN=%s

# Authentik API Token (REQUIRED for automated service integration)
# This token is used by 'eos update hecate --add <service>' to configure SSO automatically
#
# To create this token (one-time setup):
#   1. Login to Authentik admin UI: https://hera.your-domain/if/admin/
#   2. Use bootstrap credentials above (email + password)
#   3. Navigate to: Directory → Tokens → Create
#   4. Set: User = admin, Intent = API, Expiry = Never (or 365 days)
#   5. Copy the generated token and replace the placeholder below
#
# Leave empty if you don't plan to use automated SSO integration
AUTHENTIK_API_TOKEN=

# Ports
COMPOSE_PORT_HTTP=%s
COMPOSE_PORT_HTTPS=%s
`,
		escapeEnvValue(hecateSecrets.PGPass),
		escapeEnvValue(hecateSecrets.PGUser),
		escapeEnvValue(hecateSecrets.PGDatabase),
		escapeEnvValue(hecateSecrets.AuthentikSecretKey),
		escapeEnvValue(hecateSecrets.AuthentikTag),
		escapeEnvValue(hecateSecrets.AuthentikWorkerThreads),
		escapeEnvValue(hecateSecrets.AuthentikBootstrapEmail),
		escapeEnvValue(hecateSecrets.AuthentikBootstrapPassword),
		escapeEnvValue(hecateSecrets.AuthentikBootstrapToken),
		escapeEnvValue(hecateSecrets.ComposePortHTTP),
		escapeEnvValue(hecateSecrets.ComposePortHTTPS),
	)

	envPath := filepath.Join(outputDir, ".env")

	// Check if .env file already exists
	if _, err := os.Stat(envPath); err == nil {
		logger.Warn(".env file already exists, will overwrite",
			zap.String("path", envPath))
		logger.Info("terminal prompt:   Overwriting existing .env file with new secrets")
	}

	// Write with restricted permissions (0600 = owner read/write only)
	if err := os.WriteFile(envPath, []byte(envContent), 0600); err != nil {
		return fmt.Errorf("failed to write .env file %s: %w\n"+
			"Ensure you have write permissions to the output directory", envPath, err)
	}

	logger.Info(".env file created with secure permissions",
		zap.String("path", envPath),
		zap.String("permissions", "0600"))
	logger.Info("terminal prompt:   IMPORTANT: Authentik bootstrap credentials saved in .env file")
	logger.Info("terminal prompt:    Email: " + hecateSecrets.AuthentikBootstrapEmail)
	logger.Info("terminal prompt:    Password: " + hecateSecrets.AuthentikBootstrapPassword)

	return nil
}

// configureCaddySysctl configures kernel network parameters for optimal Caddy QUIC/HTTP3 performance
// Sets UDP buffer sizes to handle high connection volumes without packet loss
//
// RATIONALE: Caddy's QUIC/HTTP3 implementation requires larger UDP buffers than Linux defaults
// SECURITY: These are performance tuning parameters with no security implications
// THREAT MODEL: Default UDP buffers (212992 bytes) cause packet loss under load, degrading user experience
func configureCaddySysctl(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Check if already configured
	logger.Debug("Checking current sysctl UDP buffer settings")

	// Target values (recommended by Caddy documentation)
	const (
		targetRMemMax = 2500000 // 2.5MB receive buffer
		targetWMemMax = 2500000 // 2.5MB send buffer
	)

	// INTERVENE: Apply sysctl settings (runtime)
	logger.Info("Applying sysctl settings for Caddy UDP buffer optimization")

	sysctlCommands := []struct {
		name  string
		value int
	}{
		{"net.core.rmem_max", targetRMemMax},
		{"net.core.wmem_max", targetWMemMax},
	}

	for _, cmd := range sysctlCommands {
		// Apply runtime setting
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "sysctl",
			Args:    []string{"-w", fmt.Sprintf("%s=%d", cmd.name, cmd.value)},
			Capture: true,
		})

		if err != nil {
			return fmt.Errorf("failed to apply sysctl setting %s=%d: %w\nOutput: %s",
				cmd.name, cmd.value, err, output)
		}

		logger.Debug("Applied sysctl setting",
			zap.String("parameter", cmd.name),
			zap.Int("value", cmd.value),
			zap.String("output", strings.TrimSpace(output)))
	}

	// INTERVENE: Persist settings across reboots
	sysctlConfPath := "/etc/sysctl.d/99-caddy-udp-buf.conf"
	sysctlContent := `# Caddy UDP buffer optimization for QUIC/HTTP3
# Generated by Eos - DO NOT EDIT MANUALLY
# See: https://caddyserver.com/docs/install#linux-service

# Increase UDP buffer sizes for QUIC/HTTP3 performance
# Default values are often too small for high-throughput reverse proxies
net.core.rmem_max = 2500000
net.core.wmem_max = 2500000
`

	logger.Debug("Writing persistent sysctl configuration",
		zap.String("path", sysctlConfPath))

	if err := os.WriteFile(sysctlConfPath, []byte(sysctlContent), 0644); err != nil {
		return fmt.Errorf("failed to write sysctl config file %s: %w", sysctlConfPath, err)
	}

	logger.Debug("Persistent sysctl configuration written",
		zap.String("path", sysctlConfPath))

	// EVALUATE: Reload sysctl configuration to verify
	logger.Debug("Reloading sysctl configuration")
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "sysctl",
		Args:    []string{"--system"},
		Capture: true,
	})

	if err != nil {
		logger.Warn("Failed to reload sysctl configuration (settings applied but may not persist)",
			zap.Error(err),
			zap.String("output", output))
		// Non-fatal - runtime settings are already applied
	} else {
		logger.Debug("sysctl configuration reloaded successfully")
	}

	return nil
}

// configureHecateFirewall configures firewall rules for Hecate
// Opens TCP/80 (HTTP), TCP/443 (HTTPS), and UDP/443 (QUIC/HTTP3)
func configureHecateFirewall(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Configuring firewall rules for Hecate")

	// Define required ports for Hecate
	// CRITICAL: UDP/443 required for QUIC/HTTP3 support (enabled by sysctl UDP buffer tuning)
	ports := []string{
		"80/tcp",   // HTTP (redirects to HTTPS)
		"443/tcp",  // HTTPS (TLS 1.2/1.3)
		"443/udp",  // QUIC/HTTP3
	}

	logger.Debug("Opening firewall ports",
		zap.Strings("ports", ports))

	// Use platform.AllowPorts to handle UFW/firewalld automatically
	if err := platform.AllowPorts(rc, ports); err != nil {
		return fmt.Errorf("failed to configure firewall rules: %w\n"+
			"Manual configuration required:\n"+
			"  sudo ufw allow 80/tcp\n"+
			"  sudo ufw allow 443/tcp\n"+
			"  sudo ufw allow 443/udp  # CRITICAL for QUIC/HTTP3\n"+
			"  sudo ufw reload",
			err)
	}

	logger.Info("Firewall rules configured successfully",
		zap.Strings("ports", ports))

	return nil
}
