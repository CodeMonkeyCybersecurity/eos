// pkg/hecate/types.go

package hecate

var composeFragments []DockerComposeFragment

type DockerConfig struct {
	AppName               string
	TCPPorts              []string
	UDPPorts              []string
	NginxEnabled          bool
	CoturnEnabled         bool
	CoturnAuthSecret      string
	AuthentikEnabled      bool
	AuthentikDomain       string
	AuthentikDBName       string
	AuthentikDBUser       string
	AuthentikDBPassword   string
	AuthentikSecretKey    string
	AuthentikRedisPassword string
	// Deprecated: Use Authentik instead
	KeycloakEnabled       bool
	KeycloakDomain        string
	KeycloakDBName        string
	KeycloakDBUser        string
	KeycloakDBPassword    string
	KeycloakAdminUser     string
	KeycloakAdminPassword string
}

// ServiceSpec defines a service block for Docker Compose.
type ServiceSpec struct {
	Name            string
	FullServiceYAML string            // Full YAML block (used for standalone services)
	Ports           []string          // Ports to inject (e.g., into nginx)
	Environment     map[string]string // Optional: extra env vars
	DependsOn       []string
	Volumes         []string
	Networks        []string //  [optional] good to have for merges
}

// ComposeSpec holds the full Docker Compose spec across all services.
type ComposeSpec struct {
	Services map[string]*ServiceSpec
	Networks []string
	Volumes  []string
}

// DockerComposeFragment represents a section of Docker Compose content from a service.
type DockerComposeFragment struct {
	ServiceYAML string
}

const DockerComposeMasterTemplate = `
# hecate reverse proxy 
# docker-compose.yml

services:
{{ .CaddyService }}

{{ .DynamicServices }}

{{ .NetworksSection }}

{{ .VolumesSection }}
`

const DockerCaddyService = `
  caddy:
    image: caddy:latest
    container_name: hecate-caddy
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ./certs:/data/caddy/certs
      - ./assets/error_pages:/usr/share/caddy:ro
      - ./logs/caddy:/var/log/caddy
    ports:
      - "80:80"
      - "443:443"
    restart: always
    networks:
      - hecate-net
`

const DockerNginxService = `
  nginx:
    image: nginx
    container_name: hecate-nginx
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./assets/conf.d:/etc/nginx/conf.d:ro
      - ./assets/snippets:/etc/nginx/snippets:ro
      - ./certs:/etc/nginx/certs:ro
      - ./assets/error_pages:/usr/share/nginx/html:ro
      - ./logs:/var/log/nginx
    ports:
{{- range .TCPPorts }}
      - "{{ . }}:{{ . }}"
{{- end }}
{{- range .UDPPorts }}
      - "{{ . }}:{{ . }}/udp"
{{- end }}
    restart: always
    networks:
      - hecate-net
`

const DockerCoturnService = `
  coturn:
    image: coturn/coturn
    container_name: hecate-coturn
    restart: always
    ports:
      - "3478:3478"
      - "3478:3478/udp"
      - "5349:5349"
      - "5349:5349/udp"
      - "49160-49200:49160-49200/udp"
    environment:
      DETECT_EXTERNAL_IP: "yes"
      DETECT_RELAY_IP: "yes"
      DETECT_EXTERNAL_IPV6: "yes"
      DETECT_RELAY_IPV6: "yes"
    volumes:
      - ./certs:/etc/coturn/certs:ro
    command: >
      turnserver
      --listening-port=3478
      --listening-ip=0.0.0.0
      --fingerprint
      --no-cli
      --min-port=49160
      --max-port=49200
      --log-file=/var/log/coturn.log
      --cert=/etc/coturn/certs/hecate.fullchain.pem
      --pkey=/etc/coturn/certs/hecate.privkey.pem
      --static-auth-secret={{ .CoturnAuthSecret }}
      --verbose
    networks:
      - hecate-net
`

const DockerAuthentikService = `
  authentik-postgres:
    image: postgres:16
    container_name: hecate-authentik-postgres
    environment:
      POSTGRES_DB: {{ .AuthentikDBName }}
      POSTGRES_USER: {{ .AuthentikDBUser }}
      POSTGRES_PASSWORD: {{ .AuthentikDBPassword }}
    volumes:
      - authentik-postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -d $${POSTGRES_DB} -U $${POSTGRES_USER}"]
      start_period: 20s
      interval: 30s
      retries: 5
      timeout: 5s
    networks:
      - hecate-net

  authentik-redis:
    image: redis:alpine
    container_name: hecate-authentik-redis
    command: --save 60 1 --loglevel warning --requirepass {{ .AuthentikRedisPassword }}
    volumes:
      - authentik-redis-data:/data
    healthcheck:
      test: ["CMD-SHELL", "redis-cli --no-auth-warning -a $${AUTHENTIK_REDIS_PASSWORD:-{{ .AuthentikRedisPassword }}} ping | grep PONG"]
      start_period: 20s
      interval: 30s
      retries: 5
      timeout: 3s
    networks:
      - hecate-net

  authentik-server:
    image: ghcr.io/goauthentik/server:latest
    container_name: hecate-authentik-server
    restart: unless-stopped
    command: server
    environment:
      AUTHENTIK_REDIS__HOST: authentik-redis
      AUTHENTIK_REDIS__PASSWORD: {{ .AuthentikRedisPassword }}
      AUTHENTIK_POSTGRESQL__HOST: authentik-postgres
      AUTHENTIK_POSTGRESQL__USER: {{ .AuthentikDBUser }}
      AUTHENTIK_POSTGRESQL__NAME: {{ .AuthentikDBName }}
      AUTHENTIK_POSTGRESQL__PASSWORD: {{ .AuthentikDBPassword }}
      AUTHENTIK_SECRET_KEY: {{ .AuthentikSecretKey }}
      AUTHENTIK_DISABLE_UPDATE_CHECK: "true"
      AUTHENTIK_ERROR_REPORTING__ENABLED: "false"
      AUTHENTIK_LOG_LEVEL: info
    volumes:
      - ./authentik/media:/media
      - ./authentik/custom-templates:/templates
    depends_on:
      - authentik-postgres
      - authentik-redis
    networks:
      - hecate-net

  authentik-worker:
    image: ghcr.io/goauthentik/server:latest
    container_name: hecate-authentik-worker
    restart: unless-stopped
    command: worker
    environment:
      AUTHENTIK_REDIS__HOST: authentik-redis
      AUTHENTIK_REDIS__PASSWORD: {{ .AuthentikRedisPassword }}
      AUTHENTIK_POSTGRESQL__HOST: authentik-postgres
      AUTHENTIK_POSTGRESQL__USER: {{ .AuthentikDBUser }}
      AUTHENTIK_POSTGRESQL__NAME: {{ .AuthentikDBName }}
      AUTHENTIK_POSTGRESQL__PASSWORD: {{ .AuthentikDBPassword }}
      AUTHENTIK_SECRET_KEY: {{ .AuthentikSecretKey }}
      AUTHENTIK_DISABLE_UPDATE_CHECK: "true"
      AUTHENTIK_ERROR_REPORTING__ENABLED: "false"
      AUTHENTIK_LOG_LEVEL: info
    user: root
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./authentik/media:/media
      - ./authentik/certs:/certs
      - ./authentik/custom-templates:/templates
    depends_on:
      - authentik-postgres
      - authentik-redis
    networks:
      - hecate-net
`

// Deprecated: Use DockerAuthentikService instead
const DockerKeycloakService = `
  kc-db:
    image: postgres:15
    container_name: hecate-kc-db
    environment:
      POSTGRES_DB: {{ .KeycloakDBName }}
      POSTGRES_USER: {{ .KeycloakDBUser }}
      POSTGRES_PASSWORD: {{ .KeycloakDBPassword }}
    volumes:
      - kc-db-data:/var/lib/postgresql/data
    networks:
      - hecate-net

  keycloak:
    image: quay.io/keycloak/keycloak:22.0
    container_name: hecate-kc
    command: start-dev --hostname-strict=false --hostname-url=https://{{ .KeycloakDomain }} --proxy=edge
    environment:
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://hecate-kc-db:5432/{{ .KeycloakDBName }}
      KC_DB_USERNAME: {{ .KeycloakDBUser }}
      KC_DB_PASSWORD: {{ .KeycloakDBPassword }}
      KEYCLOAK_ADMIN: {{ .KeycloakAdminUser }}
      KEYCLOAK_ADMIN_PASSWORD: {{ .KeycloakAdminPassword }}
      KC_HOSTNAME_ADMIN_URL: https://{{ .KeycloakDomain }}
      KC_HOSTNAME_URL: https://{{ .KeycloakDomain }}
    depends_on:
      - kc-db
    networks:
      - hecate-net
`

// Centralized constants for Docker Compose sections
const (
	DockerNetworkName                = "hecate-net"
	DockerVolumeAuthentikPostgresName = "authentik-postgres-data"
	DockerVolumeAuthentikRedisName   = "authentik-redis-data"
	// Deprecated: Use Authentik volumes instead
	DockerVolumeKCDBName = "kc-db-data"

	DockerNetworkSection = `

networks:
  ` + DockerNetworkName + `:
`

	DockerVolumesSection = `

volumes:
  ` + DockerVolumeAuthentikPostgresName + `:
  ` + DockerVolumeAuthentikRedisName + `:
`

	// Deprecated: Use DockerVolumesSection instead
	DockerVolumesKeycloakSection = `

volumes:
  ` + DockerVolumeKCDBName + `:
`
)

// ToFragment renders the ServiceSpec into a DockerComposeFragment.
func (ss *ServiceSpec) ToFragment() (DockerComposeFragment, error) {
	rendered, err := renderTemplateFromString(ss.FullServiceYAML, ss.Environment)
	if err != nil {
		return DockerComposeFragment{}, err
	}
	return DockerComposeFragment{
		ServiceYAML: rendered,
	}, nil
}
