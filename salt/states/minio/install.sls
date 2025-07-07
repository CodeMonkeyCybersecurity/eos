# salt/states/minio/install.sls
# MinIO installation and system setup

{% set minio = pillar.get('minio', {}) %}
{% set minio_user = minio.get('user', 'minio') %}
{% set minio_group = minio.get('group', 'minio') %}
{% set data_path = minio.get('data_path', '/var/lib/minio') %}
{% set config_path = minio.get('config_path', '/etc/minio') %}
{% set log_path = minio.get('log_path', '/var/log/minio') %}

# Install Docker if not already present
docker_packages:
  pkg.installed:
    - pkgs:
      - docker.io
      - docker-compose

# Ensure Docker service is running
docker_service:
  service.running:
    - name: docker
    - enable: True
    - require:
      - pkg: docker_packages

# Create minio user and group
minio_group:
  group.present:
    - name: {{ minio_group }}
    - system: True

minio_user:
  user.present:
    - name: {{ minio_user }}
    - group: {{ minio_group }}
    - system: True
    - home: {{ data_path }}
    - shell: /bin/false
    - createhome: False
    - require:
      - group: minio_group

# Create necessary directories
minio_directories:
  file.directory:
    - names:
      - {{ data_path }}
      - {{ config_path }}
      - {{ log_path }}
      - /opt/minio
    - user: {{ minio_user }}
    - group: {{ minio_group }}
    - mode: 755
    - makedirs: True
    - require:
      - user: minio_user

# Create MinIO data directory with proper permissions
minio_data_storage:
  file.directory:
    - name: {{ data_path }}/data
    - user: {{ minio_user }}
    - group: {{ minio_group }}
    - mode: 755
    - makedirs: True
    - require:
      - file: minio_directories

# Install MinIO client (mc) for management
minio_client:
  cmd.run:
    - name: |
        curl -fsSL https://dl.min.io/client/mc/release/linux-amd64/mc -o /usr/local/bin/mc
        chmod +x /usr/local/bin/mc
    - unless: test -f /usr/local/bin/mc
    - require:
      - file: minio_directories

# Verify MinIO client installation
minio_client_verify:
  cmd.run:
    - name: /usr/local/bin/mc --version
    - require:
      - cmd: minio_client