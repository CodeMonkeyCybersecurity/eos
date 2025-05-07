/* pkg/hecate/types.go */

package hecate

import (
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

// Constants for file locations.
// Constant file and directory names.
const (
	LastValuesFile    = ".hecate.conf"
	ConfDir           = "conf.d"
	DockerComposeFile = "docker-compose.yml"
	DstConf           = "conf.d"
	DstCerts          = "certs"
	DstCompose        = "docker-compose.yml"
)

const (
	SRC_CONF       = "conf.d"
	SRC_CERTS      = "certs"
	SRC_COMPOSE    = "docker-compose.yml"
	BACKUP_CONF    = "conf.d.bak"
	BACKUP_CERTS   = "certs.bak"
	BACKUP_COMPOSE = "docker-compose.yml.bak"
)

// Dynamic values computed at runtime.
var (
	Timestamp     = time.Now().Format("20060102-150405")
	BackupConf    = shared.DefaultConfDir + "." + Timestamp + ".bak"
	BackupCerts   = shared.DefaultCertsDir + "." + Timestamp + ".bak"
	BackupCompose = shared.DefaultComposeYML + "." + Timestamp + ".bak"
)

// AppSelection holds an app name and its configuration file.
type AppSelection struct {
	AppName  string
	ConfFile string
}

// Global mapping from option number to its corresponding AppSelection.
var AppsSelection = map[string]AppSelection{
	"1":  {"Static website", "base.conf"},
	"2":  {"Wazuh", "delphi.conf"},
	"3":  {"Mattermost", "collaborate.conf"},
	"4":  {"Nextcloud", "cloud.conf"},
	"5":  {"Mailcow", "mailcow.conf"},
	"6":  {"Jenkins", "jenkins.conf"},
	"7":  {"Grafana", "observe.conf"},
	"8":  {"Umami", "analytics.conf"},
	"9":  {"MinIO", "s3.conf"},
	"10": {"Wiki.js", "wiki.conf"},
	"11": {"ERPNext", "erp.conf"},
	"12": {"Jellyfin", "jellyfin.conf"},
	"13": {"Persephone", "persephone.conf"},
}

// supportedApps maps the app’s lowercase name to a list of port markers.
var SupportedApps = map[string][]string{
	"wazuh":     {"1515", "1514", "55000"},
	"mailcow":   {"25", "587", "465", "110", "995", "143", "993"},
	"nextcloud": {"3478"},
}

const (
	InstallDir = "/opt/hecate"
)

const HecateServiceTemplate = `
# Generated Hecate configuration for {{ .AppName }}
services:
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


{{- if .NginxEnabled }}
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
{{- end }}

{{- if .CoturnEnabled }}
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
{{- end }}

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

networks:
  hecate-net:

volumes:
  kc-db-data:
`

type DockerConfig struct {
	AppName               string
	TCPPorts              []string
	UDPPorts              []string
	CoturnEnabled         bool
	CoturnAuthSecret      string
	KeycloakEnabled       bool
	KeycloakDomain        string
	KeycloakDBName        string
	KeycloakDBUser        string
	KeycloakDBPassword    string
	KeycloakAdminUser     string
	KeycloakAdminPassword string
	NginxEnabled          bool
}

type CaddyConfig struct {
	AppName   string
	Domain    string
	BackendIP string
	Subdomain string
	Apps           []CaddyConfig
	KeycloakDomain string
}

