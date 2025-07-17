# Install Caddy reverse proxy

# Create initial Caddyfile
create_caddyfile:
  file.managed:
    - name: /opt/hecate/caddy/Caddyfile
    - source: salt://hecate/files/nomad/caddy.nomad
    - template: jinja
    - mode: 644
    - makedirs: True
    - skip_verify: True
    - contents: |
        {
          admin :2019
          persist_config off
          
          log {
            output stdout
            format console
            level INFO
          }
        }

        # Health check endpoint
        :2019 {
          respond /health "OK" 200
        }

        # Global snippets for common configurations
        (authentik_auth) {
          forward_auth http://hecate-authentik-server.service.consul:9000 {
            uri /outpost.goauthentik.io/auth/caddy
            copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Email X-Authentik-Name X-Authentik-Uid
            trusted_proxies private_ranges
          }
        }

        (common_headers) {
          header {
            # Security headers
            X-Content-Type-Options "nosniff"
            X-Frame-Options "DENY"
            X-XSS-Protection "1; mode=block"
            Referrer-Policy "strict-origin-when-cross-origin"
            
            # Remove server header
            -Server
          }
        }

        # HTTP to HTTPS redirect
        :80 {
          redir https://{host}{uri} permanent
        }

        # Default HTTPS handler
        :443 {
          tls {
            on_demand
          }
          
          import common_headers
          
          # Default response for unconfigured domains
          respond "Hecate Reverse Proxy - Domain not configured" 404
        }

        # Import dynamic routes
        import /etc/caddy/routes/*.caddy

# Create routes directory
create_routes_directory:
  file.directory:
    - name: /opt/hecate/caddy/routes
    - mode: 755
    - makedirs: True

# Create example route file
create_example_route:
  file.managed:
    - name: /opt/hecate/caddy/routes/example.caddy.disabled
    - contents: |
        # Example route configuration
        # Rename to .caddy to enable
        
        app.example.com {
          import common_headers
          import authentik_auth
          
          reverse_proxy backend-service.service.consul:8080 {
            health_uri /health
            health_interval 10s
            health_timeout 5s
          }
        }