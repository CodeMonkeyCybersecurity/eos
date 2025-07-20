# Configure Caddy for Hecate

# Setup Caddy admin API access
configure_caddy_admin:
  cmd.run:
    - name: |
        # Wait for Caddy to be running
        for i in {1..30}; do
          if curl -sf http://localhost:2019/config/; then
            echo "Caddy admin API is ready"
            break
          fi
          echo "Waiting for Caddy admin API..."
          sleep 5
        done

# Create Caddyfile from template
create_caddyfile:
  file.managed:
    - name: /opt/hecate/caddy/Caddyfile
    - source: salt://hecate/files/caddy/Caddyfile.j2
    - template: jinja
    - mode: 644
    - makedirs: True

# Configure automatic HTTPS with DNS challenge
configure_auto_https:
  cmd.run:
    - name: |
        # Check if DNS provider is configured
        {% if pillar.get('hecate:dns_provider') %}
        echo "DNS challenge configured for provider: {{ pillar.get('hecate:dns_provider') }}"
        {% else %}
        echo "WARNING: No DNS provider configured. HTTPS may not work properly on cloud deployments."
        echo "Please set hecate:dns_provider in pillar (e.g., cloudflare, hetzner, route53)"
        {% endif %}
    - require:
      - file: create_caddyfile

# Load automatic HTTPS configuration
load_auto_https_config:
  cmd.run:
    - name: |
        if [ -f /opt/hecate/caddy/auto-https.json ]; then
          curl -X POST http://localhost:2019/load \
            -H "Content-Type: application/json" \
            -d @/opt/hecate/caddy/auto-https.json
        fi
    - onlyif: test -f /opt/hecate/caddy/auto-https.json

# Create Consul template for dynamic routes
create_consul_template:
  file.managed:
    - name: /opt/hecate/consul-template/hecate-routes.ctmpl
    - makedirs: True
    - contents: |
        {{- range services -}}
        {{- if .Tags | contains "hecate-route" -}}
        {{- range service .Name -}}
        
        # Route for {{ .Name }}
        {{ .ServiceMeta.hostname }} {
          import common_headers
          {{- if .ServiceMeta.auth_required }}
          import authentik_auth
          {{- end }}
          
          reverse_proxy {{ .Address }}:{{ .Port }} {
            health_uri {{ .ServiceMeta.health_path | default "/health" }}
            health_interval 10s
            health_timeout 5s
          }
        }
        {{- end -}}
        {{- end -}}
        {{- end }}

# Configure Consul template to watch for route changes
configure_consul_template:
  file.managed:
    - name: /etc/consul-template.d/hecate-routes.hcl
    - makedirs: True
    - contents: |
        template {
          source = "/opt/hecate/consul-template/hecate-routes.ctmpl"
          destination = "/opt/hecate/caddy/routes/consul-routes.caddy"
          command = "curl -X POST http://localhost:2019/reload"
          perms = 0644
        }