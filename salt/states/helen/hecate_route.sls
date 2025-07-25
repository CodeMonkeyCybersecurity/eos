# Hecate reverse proxy route configuration for Helen
# Configures Caddy to route traffic to Helen service

{% set mode = salt['pillar.get']('helen:mode', 'static') %}
{% set environment = salt['pillar.get']('helen:environment', 'production') %}
{% set domain = salt['pillar.get']('helen:domain') %}
{% set port = salt['pillar.get']('helen:port', 8009) %}
{% set enable_auth = salt['pillar.get']('helen:enable_auth', false) %}

# Ensure Hecate route directory exists
helen_hecate_route_directory:
  file.directory:
    - name: /opt/hecate/caddy/routes
    - mode: 755
    - makedirs: True

# Create Caddy route configuration for Helen
helen_create_hecate_route:
  file.managed:
    - name: /opt/hecate/caddy/routes/helen-{{ environment }}.caddy
    - mode: 644
    - contents: |
        # Helen {{ mode }} route for {{ environment }} environment
        # Generated by eos at {{ salt['cmd.run']('date -u +%Y-%m-%dT%H:%M:%SZ') }}
        
        {{ domain }} {
            # Import common security headers
            import common_headers
            
            {% if enable_auth %}
            # Enable Authentik authentication
            import authentik_auth
            {% endif %}
            
            # Custom headers for Helen
            header {
                X-Helen-Environment "{{ environment }}"
                X-Helen-Mode "{{ mode }}"
                X-Helen-Version "{{ salt['pillar.get']('helen:git_commit', 'latest') }}"
            }
            
            {% if mode == 'ghost' %}
            # Ghost-specific configuration
            
            # Handle Ghost admin panel
            handle_path /ghost* {
                {% if enable_auth %}
                # Admin panel requires authentication
                import authentik_auth
                {% endif %}
                
                reverse_proxy helen-{{ mode }}-{{ environment }}.service.consul:{{ port }} {
                    # Ghost requires these headers
                    header_up X-Forwarded-Proto {scheme}
                    header_up X-Forwarded-Host {host}
                    header_up X-Real-IP {remote_host}
                    header_up X-Forwarded-For {remote_host}
                    
                    # Health check for Ghost admin
                    health_uri /ghost/api/admin/site/
                    health_interval 10s
                    health_timeout 5s
                    health_status 2xx
                    
                    # Timeouts for Ghost operations
                    transport http {
                        dial_timeout 30s
                        read_timeout 300s
                        write_timeout 300s
                    }
                }
            }
            
            # Handle Ghost content API
            handle_path /content/* {
                reverse_proxy helen-{{ mode }}-{{ environment }}.service.consul:{{ port }} {
                    header_up X-Forwarded-Proto {scheme}
                    header_up X-Forwarded-Host {host}
                    
                    # Cache content API responses
                    header Cache-Control "public, max-age=3600"
                }
            }
            
            # Handle Ghost members API (for subscriptions)
            handle_path /members/* {
                reverse_proxy helen-{{ mode }}-{{ environment }}.service.consul:{{ port }} {
                    header_up X-Forwarded-Proto {scheme}
                    header_up X-Forwarded-Host {host}
                    header_up X-Real-IP {remote_host}
                }
            }
            
            # Handle uploaded images and files
            handle_path /content/images/* {
                reverse_proxy helen-{{ mode }}-{{ environment }}.service.consul:{{ port }} {
                    # Long cache for images
                    header Cache-Control "public, max-age=31536000, immutable"
                }
            }
            
            {% else %}
            # Static mode configuration
            
            # Enable compression for static files
            encode gzip zstd
            
            # Security headers for static content
            header {
                Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;"
                X-Content-Type-Options "nosniff"
            }
            
            # Cache static assets
            @static {
                path *.css *.js *.jpg *.jpeg *.png *.gif *.svg *.woff *.woff2 *.ttf *.eot
            }
            header @static Cache-Control "public, max-age=31536000, immutable"
            
            {% endif %}
            
            # Main reverse proxy configuration
            reverse_proxy helen-{{ mode }}-{{ environment }}.service.consul:{{ port }} {
                # Standard proxy headers
                header_up Host {host}
                header_up X-Real-IP {remote_host}
                header_up X-Forwarded-For {remote_host}
                header_up X-Forwarded-Proto {scheme}
                
                # Health checking
                {% if mode == 'ghost' %}
                health_uri /ghost/api/admin/site/
                {% else %}
                health_uri /
                {% endif %}
                health_interval 10s
                health_timeout 5s
                health_status 2xx 3xx
                
                # Load balancing if multiple instances
                lb_policy round_robin
                lb_try_duration 30s
                lb_try_interval 5s
                
                # Circuit breaker
                fail_duration 30s
                max_fails 3
                unhealthy_request_count 3
                unhealthy_status 5xx
                unhealthy_latency 10s
                
                # Transport configuration
                transport http {
                    dial_timeout 10s
                    response_header_timeout 30s
                    {% if mode == 'ghost' %}
                    # Longer timeouts for Ghost
                    read_timeout 300s
                    write_timeout 300s
                    {% else %}
                    read_timeout 30s
                    write_timeout 30s
                    {% endif %}
                }
            }
            
            # Error handling
            handle_errors {
                @502 expression {http.error.status_code} == 502
                rewrite @502 /errors/502.html
                
                @503 expression {http.error.status_code} == 503
                rewrite @503 /errors/503.html
                
                # Serve custom error pages
                respond "{http.error.status_code} {http.error.status_text}"
            }
            
            # Logging
            log {
                output file /var/log/caddy/helen-{{ environment }}.log {
                    roll_size 100mb
                    roll_keep 7
                    roll_keep_for 168h
                }
                format json
                level INFO
            }
        }
        
        # Redirect www to non-www
        www.{{ domain }} {
            redir https://{{ domain }}{uri} permanent
        }
    - require:
      - file: helen_hecate_route_directory
      - sls: helen.consul_register

# Create custom error pages
helen_create_error_pages:
  file.directory:
    - name: /opt/hecate/caddy/errors
    - mode: 755
    - makedirs: True
    - require:
      - file: helen_hecate_route_directory

helen_error_page_502:
  file.managed:
    - name: /opt/hecate/caddy/errors/502.html
    - mode: 644
    - contents: |
        <!DOCTYPE html>
        <html>
        <head>
            <title>Service Temporarily Unavailable</title>
            <style>
                body { font-family: sans-serif; text-align: center; padding: 50px; }
                h1 { color: #e74c3c; }
                p { color: #7f8c8d; }
            </style>
        </head>
        <body>
            <h1>502 - Service Temporarily Unavailable</h1>
            <p>Helen {{ mode }} ({{ environment }}) is currently unavailable. Please try again in a few moments.</p>
            <p><small>If this persists, please contact the system administrator.</small></p>
        </body>
        </html>
    - require:
      - file: helen_create_error_pages

# Apply the route configuration to Caddy
helen_apply_hecate_route:
  cmd.run:
    - name: |
        echo "Applying Hecate route configuration..."
        
        # Validate the Caddy configuration
        caddy validate --config /opt/hecate/caddy/Caddyfile
        
        # Reload Caddy to apply the new route
        if systemctl is-active caddy; then
          caddy reload --config /opt/hecate/caddy/Caddyfile
        else
          # If Caddy is managed by Nomad, use the admin API
          curl -X POST "http://localhost:2019/load" \
            -H "Content-Type: application/json" \
            -d @/opt/hecate/caddy/Caddyfile
        fi
    - require:
      - file: helen_create_hecate_route

# Configure DNS if using Hetzner
{% if salt['pillar.get']('helen:dns:provider') == 'hetzner' and salt['pillar.get']('helen:dns:auto_configure', false) %}
helen_configure_dns:
  cmd.run:
    - name: |
        # Use eos to configure DNS
        eos create hetzner-wildcard --domain {{ domain }} --force
    - unless: dig +short {{ domain }} | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'
    - require:
      - cmd: helen_apply_hecate_route
{% endif %}

# Verify route is working
helen_verify_hecate_route:
  cmd.run:
    - name: |
        echo "Verifying Hecate route..."
        sleep 10  # Give Caddy time to reload
        
        # Check if Caddy has loaded the route
        if curl -s http://localhost:2019/config/apps/http/servers | jq -r '.. | .routes? | select(. != null) | .[].match[]?.host[]?' | grep -q "{{ domain }}"; then
          echo "Route successfully configured in Caddy"
        else
          echo "Route not found in Caddy configuration"
          exit 1
        fi
        
        # Test the route locally
        echo "Testing route connectivity..."
        {% if mode == 'ghost' %}
        HEALTH_URL="http://localhost:{{ port }}/ghost/api/admin/site/"
        {% else %}
        HEALTH_URL="http://localhost:{{ port }}/"
        {% endif %}
        
        if curl -s -o /dev/null -w "%{http_code}" "$HEALTH_URL" | grep -q "^[23]"; then
          echo "Helen service is responding correctly"
        else
          echo "Helen service health check failed"
          exit 1
        fi
    - require:
      - cmd: helen_apply_hecate_route

# Store route configuration in Consul KV
helen_store_route_config:
  consul.put:
    - name: helen/routes/{{ environment }}
    - value: |
        {
          "domain": "{{ domain }}",
          "backend": "helen-{{ mode }}-{{ environment }}.service.consul:{{ port }}",
          "authentication": {{ enable_auth | lower }},
          "mode": "{{ mode }}",
          "health_check": {
            {% if mode == 'ghost' %}
            "path": "/ghost/api/admin/site/",
            {% else %}
            "path": "/",
            {% endif %}
            "interval": "10s",
            "timeout": "5s"
          },
          "configured_at": "{{ salt['cmd.run']('date -u +%Y-%m-%dT%H:%M:%SZ') }}"
        }
    - require:
      - cmd: helen_verify_hecate_route