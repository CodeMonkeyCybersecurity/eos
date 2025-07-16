# salt/states/hashicorp/nomad/install.sls
# HashiCorp Nomad installation state

{% set nomad = pillar.get('nomad', {}) %}
{% set version = nomad.get('version', 'latest') %}
{% set nomad_user = nomad.get('user', 'nomad') %}
{% set nomad_group = nomad.get('group', 'nomad') %}
{% set install_dir = nomad.get('install_dir', '/opt/nomad') %}
{% set bin_dir = nomad.get('bin_dir', '/usr/local/bin') %}

# Create nomad user and group
nomad_group:
  group.present:
    - name: {{ nomad_group }}
    - system: True

nomad_user:
  user.present:
    - name: {{ nomad_user }}
    - group: {{ nomad_group }}
    - system: True
    - home: {{ install_dir }}
    - shell: /bin/false
    - createhome: False
    - require:
      - group: nomad_group

# Create directories
nomad_directories:
  file.directory:
    - names:
      - {{ install_dir }}
      - {{ nomad.get('config_path', '/etc/nomad.d') }}
      - {{ nomad.get('data_path', '/opt/nomad/data') }}
      - {{ nomad.get('log_path', '/var/log/nomad') }}
    - user: {{ nomad_user }}
    - group: {{ nomad_group }}
    - mode: 755
    - makedirs: True
    - require:
      - user: nomad_user

# Include shared HashiCorp repository setup
include:
  - hashicorp

# Update package cache after repository setup
update_package_cache:
  pkg.refresh_db:
    - require:
      - pkgrepo: hashicorp_repo

# Install Nomad
{% if version == 'latest' %}
nomad_package:
  pkg.installed:
    - name: nomad
    - require:
      - pkg: update_package_cache
{% else %}
nomad_package:
  pkg.installed:
    - name: nomad
    - version: {{ version }}
    - require:
      - pkg: update_package_cache
{% endif %}

# Install Docker for Nomad (recommended for container orchestration)
docker_package:
  pkg.installed:
    - name: docker.io
    - require:
      - pkg: update_package_cache

# Add nomad user to docker group
nomad_docker_group:
  group.present:
    - name: docker
    - addusers:
      - {{ nomad_user }}
    - require:
      - pkg: docker_package
      - user: nomad_user

# Create systemd environment file
nomad_environment:
  file.managed:
    - name: /etc/nomad.d/nomad.env
    - contents: |
        NOMAD_CONFIG_PATH={{ nomad.get('config_path', '/etc/nomad.d') }}
        NOMAD_DATA_PATH={{ nomad.get('data_path', '/opt/nomad/data') }}
        NOMAD_LOG_LEVEL={{ nomad.get('log_level', 'INFO') }}
    - user: {{ nomad_user }}
    - group: {{ nomad_group }}
    - mode: 640
    - require:
      - file: nomad_directories