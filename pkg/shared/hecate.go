// pkg/shared/hecate.go

package shared

const (
	HecateRepoURL    = "https://github.com/CodeMonkeyCybersecurity/hecate.git" // TODO: update this to your real repo
	HecateInstallDir = "/opt/hecate"
)

const HecateServiceTemplate = `
# Generated Hecate configuration for {{ .AppName }}
services:
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
      - "80:80"
      - "443:443"
{{- range .TCPPorts }}
      - "{{ . }}:{{ . }}"
{{- end }}
{{- range .UDPPorts }}
      - "{{ . }}:{{ . }}/udp"
{{- end }}
    restart: always
    networks:
      - hecate-net

{{- if .CaddyEnabled }}
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
{{- end }}

networks:
  hecate-net:
`

type HecateAppConfig struct {
	AppName     string
	Domain      string
	BackendIP   string
	TCPPorts    []string
	UDPPorts    []string
	CaddyEnabled bool
}