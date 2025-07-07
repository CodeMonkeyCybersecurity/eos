# salt/states/minio/service.sls
# MinIO service management

{% set minio = pillar.get('minio', {}) %}
{% set minio_user = minio.get('user', 'minio') %}
{% set minio_group = minio.get('group', 'minio') %}

# Create systemd service file for MinIO
minio_systemd_service:
  file.managed:
    - name: /etc/systemd/system/minio.service
    - contents: |
        [Unit]
        Description=MinIO Object Storage Server
        Documentation=https://docs.min.io
        Wants=network-online.target
        After=network-online.target docker.service
        Requires=docker.service
        AssertFileIsExecutable=/opt/minio/start-minio.sh
        
        [Service]
        Type=forking
        User={{ minio_user }}
        Group={{ minio_group }}
        
        # Security settings
        PrivateTmp=true
        ProtectKernelTunables=true
        ProtectKernelModules=true
        ProtectControlGroups=true
        RestrictRealtime=true
        RestrictNamespaces=true
        
        # Start and stop commands
        ExecStart=/opt/minio/start-minio.sh
        ExecStop=/opt/minio/stop-minio.sh
        
        # Restart policy
        Restart=always
        RestartSec=5
        
        # Environment
        Environment=MINIO_CONFIG_ENV_FILE=/etc/minio/minio.env
        
        [Install]
        WantedBy=multi-user.target
    - mode: 644
    - require:
      - file: minio_startup_script
      - file: minio_stop_script

# Reload systemd daemon
minio_systemd_reload:
  cmd.run:
    - name: systemctl daemon-reload
    - require:
      - file: minio_systemd_service

# Ensure MinIO service is enabled but not started automatically
# (let Nomad manage the actual service startup)
minio_service_enable:
  service.enabled:
    - name: minio
    - require:
      - cmd: minio_systemd_reload

# Create service status check script
minio_status_script:
  file.managed:
    - name: /opt/minio/status-minio.sh
    - contents: |
        #!/bin/bash
        # MinIO status check script
        
        echo "=== MinIO Status ==="
        
        # Check systemd service status
        echo "Systemd service status:"
        systemctl status minio --no-pager || true
        
        # Check Docker containers
        echo -e "\nDocker containers:"
        docker ps | grep minio || echo "No MinIO containers running"
        
        # Check port availability
        echo -e "\nPort status:"
        ss -tuln | grep -E ":(9123|9124)" || echo "MinIO ports not listening"
        
        # Check MinIO health if running
        echo -e "\nHealth check:"
        curl -s -f http://localhost:9123/minio/health/live >/dev/null 2>&1 && \
            echo "MinIO API is healthy" || \
            echo "MinIO API is not responding"
        
        curl -s -f http://localhost:9124 >/dev/null 2>&1 && \
            echo "MinIO Console is healthy" || \
            echo "MinIO Console is not responding"
    - user: {{ minio_user }}
    - group: {{ minio_group }}
    - mode: 755
    - require:
      - file: minio_systemd_service