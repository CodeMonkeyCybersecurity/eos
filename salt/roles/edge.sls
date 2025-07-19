# salt/roles/edge.sls
# Configuration for edge server role

# Set role grain
edge_role_grain:
  grains.present:
    - name: role
    - value: edge

# Edge-specific packages
edge_packages:
  pkg.installed:
    - pkgs:
      - nginx
      - haproxy
      - varnish
      - keepalived

# Edge-specific storage configuration
edge_storage_config:
  file.managed:
    - name: /etc/eos/role-specific/edge.yaml
    - makedirs: True
    - contents: |
        role: edge
        storage:
          cache_size: 20G
          log_retention: 7d
          thresholds:
            # Edge nodes can use more aggressive thresholds
            warning: 70
            cleanup: 80
            critical: 90

# Nginx configuration for edge
nginx_edge_config:
  file.managed:
    - name: /etc/nginx/sites-available/edge-proxy
    - contents: |
        upstream backend {
            server core-1:8080;
            server core-2:8080;
        }
        
        server {
            listen 80;
            location / {
                proxy_pass http://backend;
                proxy_cache_valid 200 5m;
            }
        }
    - require:
      - pkg: edge_packages

nginx_edge_enable:
  file.symlink:
    - name: /etc/nginx/sites-enabled/edge-proxy
    - target: /etc/nginx/sites-available/edge-proxy
    - require:
      - file: nginx_edge_config

nginx_service:
  service.running:
    - name: nginx
    - enable: True
    - watch:
      - file: nginx_edge_config