# Configure Caddy-Authentik integration
# This state sets up the authentication flow between Caddy and Authentik

# Create Caddy configuration snippets for Authentik integration
/opt/hecate/caddy/snippets/common_headers:
  file.managed:
    - makedirs: True
    - contents: |
        # Common security headers
        header {
            X-Content-Type-Options nosniff
            X-Frame-Options DENY
            X-XSS-Protection "1; mode=block"
            Referrer-Policy strict-origin-when-cross-origin
            Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
        }

/opt/hecate/caddy/snippets/authentik_auth:
  file.managed:
    - makedirs: True
    - contents: |
        # Authentik forward authentication
        forward_auth http://hecate-authentik-server.service.consul:9000 {
            uri /api/v3/outpost/proxy/auth/caddy
            copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Email X-Authentik-Name X-Authentik-Uid
            trusted_proxies private_ranges
        }

# Create main Caddyfile with Authentik integration
/opt/hecate/caddy/Caddyfile:
  file.managed:
    - makedirs: True
    - contents: |
        # Global options
        {
            admin 0.0.0.0:2019
            auto_https off
        }
        
        # Import all snippets
        import /opt/hecate/caddy/snippets/*
        
        # Import all route configurations
        import /opt/hecate/caddy/routes/*.caddy
        
        # Default handler for unknown hosts
        :80 {
            respond "404 Not Found" 404
        }

# Create routes directory
/opt/hecate/caddy/routes:
  file.directory:
    - makedirs: True
    - mode: 755

# Create example protected route
/opt/hecate/caddy/routes/example.caddy.disabled:
  file.managed:
    - contents: |
        # Example protected route
        # Rename to .caddy to enable
        example.local {
            import common_headers
            import authentik_auth
            
            reverse_proxy http://backend-service:8080 {
                health_uri /health
                health_interval 10s
            }
        }

# Update Nomad job to mount configuration
hecate_caddy_nomad_config:
  cmd.run:
    - name: |
        # Update Caddy Nomad job to use the configuration
        cat > /tmp/caddy-config-update.hcl << 'EOF'
        job "hecate-caddy" {
          datacenters = ["dc1"]
          
          group "caddy" {
            task "caddy" {
              config {
                mount {
                  type = "bind"
                  source = "/opt/hecate/caddy"
                  target = "/config"
                  readonly = true
                }
                
                args = ["caddy", "run", "--config", "/config/Caddyfile", "--adapter", "caddyfile"]
              }
            }
          }
        }
        EOF
        
        # Apply the update
        nomad job run /tmp/caddy-config-update.hcl
    - require:
      - file: /opt/hecate/caddy/Caddyfile
      - file: /opt/hecate/caddy/snippets/common_headers
      - file: /opt/hecate/caddy/snippets/authentik_auth

# Configure Authentik for Caddy integration
hecate_authentik_caddy_setup:
  cmd.run:
    - name: |
        # Wait for Authentik to be ready
        for i in {1..60}; do
          if curl -sf http://localhost:9000/-/health/ready/; then
            break
          fi
          sleep 5
        done
        
        # Note: Manual configuration required in Authentik UI:
        # 1. Create a Provider (Proxy Provider)
        # 2. Create an Application linked to the provider
        # 3. Create an Outpost linked to the application
        echo "Authentik is ready. Please complete manual configuration in the UI."
    - require:
      - cmd: hecate_caddy_nomad_config