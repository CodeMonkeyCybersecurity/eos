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

# Configure automatic HTTPS
configure_auto_https:
  file.managed:
    - name: /opt/hecate/caddy/auto-https.json
    - contents: |
        {
          "apps": {
            "tls": {
              "automation": {
                "policies": [{
                  "subjects": ["*.{{ grains.domain | default('example.com') }}"],
                  "issuers": [{
                    "module": "acme",
                    "challenges": {
                      "dns": {
                        "provider": {
                          "name": "hetzner",
                          "api_token": "{{ salt['vault'].read('secret/hecate/hetzner/dns_token').get('value', '') }}"
                        }
                      }
                    }
                  }]
                }]
              }
            }
          }
        }

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