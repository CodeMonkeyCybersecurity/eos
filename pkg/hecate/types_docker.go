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
	Networks        []string // 💡 [optional] good to have for merges
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

networks:
{{ .NetworksSection }}

volumes:
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

const DockerNetworkSection = `

networks:
  hecate-net:
`

const DockerVolumesSection = `

volumes:
  kc-db-data:
`

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
