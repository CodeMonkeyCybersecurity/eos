# Manage Caddy service

# Ensure Caddy is running
caddy_service_running:
  cmd.run:
    - name: |
        # Check if Caddy job is running
        if ! nomad job status hecate-caddy | grep -q "running"; then
          echo "Caddy is not running properly"
          exit 1
        fi

# Validate Caddy configuration
validate_caddy_config:
  cmd.run:
    - name: |
        # Test configuration via admin API
        CONFIG=$(curl -s http://localhost:2019/config/)
        if [ -z "$CONFIG" ]; then
          echo "Failed to get Caddy configuration"
          exit 1
        fi
        echo "Caddy configuration is valid"

# Setup log rotation for Caddy
caddy_log_rotation:
  file.managed:
    - name: /etc/logrotate.d/hecate-caddy
    - contents: |
        /opt/hecate/caddy/logs/*.log {
          daily
          rotate 7
          compress
          delaycompress
          missingok
          notifempty
          create 0644 root root
          postrotate
            curl -X POST http://localhost:2019/logging/reopen
          endscript
        }

# Create systemd service for auto-reload on certificate updates
caddy_cert_reload_service:
  file.managed:
    - name: /etc/systemd/system/hecate-caddy-reload.service
    - contents: |
        [Unit]
        Description=Reload Caddy when certificates are updated
        After=network.target
        
        [Service]
        Type=oneshot
        ExecStart=/usr/bin/curl -X POST http://localhost:2019/reload
        
        [Install]
        WantedBy=multi-user.target

caddy_cert_reload_path:
  file.managed:
    - name: /etc/systemd/system/hecate-caddy-reload.path
    - contents: |
        [Unit]
        Description=Watch for Caddy certificate changes
        
        [Path]
        PathModified=/opt/hecate/caddy/data/caddy/certificates
        
        [Install]
        WantedBy=multi-user.target

enable_caddy_reload_watcher:
  service.enabled:
    - names:
      - hecate-caddy-reload.path
    - require:
      - file: caddy_cert_reload_service
      - file: caddy_cert_reload_path