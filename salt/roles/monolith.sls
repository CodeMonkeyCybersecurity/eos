# salt/roles/monolith.sls
# Configuration for single-node deployment (all roles combined)

# Set role grain
monolith_role_grain:
  grains.present:
    - name: role
    - value: monolith

# Install all necessary packages for monolith
monolith_packages:
  pkg.installed:
    - pkgs:
      # Edge packages
      - nginx
      - haproxy
      # Core packages
      - docker.io
      - docker-compose
      # Data packages
      - postgresql-14
      - redis-server
      # Monitoring
      - prometheus
      - grafana

# Monolith-specific storage configuration
monolith_storage_config:
  file.managed:
    - name: /etc/eos/role-specific/monolith.yaml
    - makedirs: True
    - contents: |
        role: monolith
        storage:
          # Single node needs aggressive cleanup
          thresholds:
            warning: 60
            compress: 70
            cleanup: 75
            degraded: 80
            emergency: 85
            critical: 90
          cleanup_policy: aggressive
          monitoring_interval: 5m
          
# Docker configuration for monolith
docker_daemon_monolith:
  file.managed:
    - name: /etc/docker/daemon.json
    - contents: |
        {
          "log-driver": "json-file",
          "log-opts": {
            "max-size": "50m",
            "max-file": "2"
          },
          "storage-driver": "overlay2"
        }

docker_service_monolith:
  service.running:
    - name: docker
    - enable: True
    - watch:
      - file: docker_daemon_monolith

# Create all necessary directories
monolith_directories:
  file.directory:
    - names:
      - /opt/apps
      - /opt/data
      - /var/lib/eos
      - /mnt/backups
    - makedirs: True
    - mode: 755

# Enable all services for monolith
monolith_services:
  service.running:
    - names:
      - nginx
      - docker
      - postgresql
      - redis
    - enable: True