# Install HashiCorp Nomad

{% set nomad = pillar.get('nomad', {}) %}
{% set version = nomad.get('version', 'latest') %}
{% set datacenter = nomad.get('datacenter', 'dc1') %}
{% set region = nomad.get('region', 'global') %}

# Add HashiCorp APT repository
hashicorp_apt_key:
  cmd.run:
    - name: |
        wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
    - unless: test -f /usr/share/keyrings/hashicorp-archive-keyring.gpg

# Update package list
update_package_list:
  cmd.run:
    - name: apt-get update
    - require:
      - cmd: hashicorp_apt_key

# Install Nomad
{% if version == 'latest' %}
install_nomad:
  pkg.installed:
    - name: nomad
    - require:
      - cmd: update_package_list
{% else %}
install_nomad:
  pkg.installed:
    - name: nomad
    - version: {{ version }}
    - require:
      - cmd: update_package_list
{% endif %}

# Create nomad user and group
nomad_user:
  user.present:
    - name: nomad
    - system: True
    - shell: /bin/false
    - home: /opt/nomad
    - createhome: False

nomad_group:
  group.present:
    - name: nomad
    - system: True

# Create required directories
nomad_config_dir:
  file.directory:
    - name: /etc/nomad.d
    - user: nomad
    - group: nomad
    - mode: 755
    - makedirs: True

nomad_data_dir:
  file.directory:
    - name: {{ nomad.get('data_dir', '/opt/nomad/data') }}
    - user: nomad
    - group: nomad
    - mode: 755
    - makedirs: True

nomad_log_dir:
  file.directory:
    - name: /var/log/nomad
    - user: nomad
    - group: nomad
    - mode: 755
    - makedirs: True

# Create TLS directory if TLS is enabled
{% if nomad.get('enable_tls', true) %}
nomad_tls_dir:
  file.directory:
    - name: /etc/nomad.d/tls
    - user: nomad
    - group: nomad
    - mode: 700
    - makedirs: True
{% endif %}

# Install Docker if Docker driver is enabled
{% if nomad.get('docker_enabled', true) %}
install_docker:
  pkg.installed:
    - pkgs:
      - docker.io
      - docker-compose

docker_service:
  service.running:
    - name: docker
    - enable: True
    - require:
      - pkg: install_docker

# Add nomad user to docker group
nomad_docker_group:
  user.present:
    - name: nomad
    - groups:
      - docker
    - require:
      - user: nomad_user
      - pkg: install_docker
{% endif %}

# Set up log rotation
nomad_logrotate:
  file.managed:
    - name: /etc/logrotate.d/nomad
    - contents: |
        /var/log/nomad/*.log {
            daily
            missingok
            rotate 7
            compress
            delaycompress
            copytruncate
            notifempty
            create 0644 nomad nomad
        }

# Create systemd service override directory
nomad_systemd_override_dir:
  file.directory:
    - name: /etc/systemd/system/nomad.service.d
    - makedirs: True

# Create systemd service override for security
nomad_systemd_override:
  file.managed:
    - name: /etc/systemd/system/nomad.service.d/override.conf
    - contents: |
        [Service]
        User=nomad
        Group=nomad
        ExecReload=/bin/kill -HUP $MAINPID
        KillMode=process
        Restart=on-failure
        LimitNOFILE=65536
        
        # Security settings
        NoNewPrivileges=true
        PrivateTmp=true
        ProtectSystem=strict
        ProtectHome=true
        ReadWritePaths={{ nomad.get('data_dir', '/opt/nomad/data') }}
        ReadWritePaths=/var/log/nomad
        ReadWritePaths=/etc/nomad.d
    - require:
      - file: nomad_systemd_override_dir

# Reload systemd after override
systemd_reload:
  cmd.run:
    - name: systemctl daemon-reload
    - require:
      - file: nomad_systemd_override