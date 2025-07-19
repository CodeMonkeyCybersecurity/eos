# salt/roles/core.sls
# Configuration for core services role

# Set role grain
core_role_grain:
  grains.present:
    - name: role
    - value: core

# Core-specific packages
core_packages:
  pkg.installed:
    - pkgs:
      - docker.io
      - docker-compose
      - postgresql-client
      - redis-tools

# Core-specific storage configuration
core_storage_config:
  file.managed:
    - name: /etc/eos/role-specific/core.yaml
    - makedirs: True
    - contents: |
        role: core
        storage:
          docker_storage: /var/lib/docker
          app_data: /opt/apps
          thresholds:
            # Core nodes need more conservative thresholds
            warning: 65
            cleanup: 75
            critical: 85

# Docker daemon configuration for core
docker_daemon_config:
  file.managed:
    - name: /etc/docker/daemon.json
    - contents: |
        {
          "log-driver": "json-file",
          "log-opts": {
            "max-size": "100m",
            "max-file": "3"
          },
          "storage-driver": "overlay2",
          "metrics-addr": "0.0.0.0:9323",
          "experimental": true
        }
    - require:
      - pkg: core_packages

docker_service:
  service.running:
    - name: docker
    - enable: True
    - watch:
      - file: docker_daemon_config

# Create app directories
core_app_directories:
  file.directory:
    - names:
      - /opt/apps
      - /opt/apps/data
      - /opt/apps/config
    - user: root
    - group: docker
    - mode: 755
    - makedirs: True