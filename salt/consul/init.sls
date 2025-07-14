# salt/consul/init.sls
# Main Consul installation and configuration state

{% set consul = salt['pillar.get']('consul', {}) %}
{% set datacenter = consul.get('datacenter', 'dc1') %}
{% set server_mode = consul.get('server', True) %}
{% set ui_enabled = consul.get('ui_config', {}).get('enabled', True) %}
{% set http_port = consul.get('ports', {}).get('http', 8161) %}
{% set dns_port = consul.get('ports', {}).get('dns', 8600) %}
{% set encrypt_key = consul.get('encrypt', '') %}
{% set tls_enabled = consul.get('tls', {}).get('enabled', False) %}

# Create consul user
consul_user:
  user.present:
    - name: consul
    - system: True
    - shell: /bin/false
    - home: /etc/consul.d
    - createhome: False
    - comment: Consul service account

# Create required directories
consul_directories:
  file.directory:
    - names:
      - /etc/consul.d
      - /etc/consul.d/scripts
      - /opt/consul
      - /opt/consul/data
      - /var/log/consul
    - user: consul
    - group: consul
    - mode: '0750'
    - makedirs: True
    - require:
      - user: consul_user

# Install Consul binary
consul_binary:
  file.managed:
    - name: /usr/local/bin/consul
    - source: salt://consul/files/consul
    - mode: '0755'
    - user: root
    - group: root
    - unless: test -f /usr/local/bin/consul && /usr/local/bin/consul version | grep -q {{ consul.get('version', '1.17.0') }}

# Main Consul configuration
consul_config:
  file.managed:
    - name: /etc/consul.d/consul.hcl
    - source: salt://consul/files/consul.hcl.j2
    - template: jinja
    - user: consul
    - group: consul
    - mode: '0640'
    - context:
        datacenter: {{ datacenter }}
        server_mode: {{ server_mode }}
        ui_enabled: {{ ui_enabled }}
        http_port: {{ http_port }}
        dns_port: {{ dns_port }}
        encrypt_key: {{ encrypt_key }}
        tls_enabled: {{ tls_enabled }}
    - require:
      - file: consul_directories

# Systemd service file
consul_service_file:
  file.managed:
    - name: /etc/systemd/system/consul.service
    - source: salt://consul/files/consul.service.j2
    - template: jinja
    - context:
        consul_user: consul
        consul_group: consul
    - require:
      - file: consul_binary
      - file: consul_config

# Reload systemd and start service
consul_systemd_reload:
  cmd.run:
    - name: systemctl daemon-reload
    - onchanges:
      - file: consul_service_file

consul_service_running:
  service.running:
    - name: consul
    - enable: True
    - watch:
      - file: consul_config
      - file: consul_service_file
    - require:
      - file: consul_binary
      - file: consul_config
      - file: consul_service_file
      - cmd: consul_systemd_reload

# Vault integration if enabled
{% if consul.get('vault', {}).get('enabled', False) %}
consul_vault_service:
  file.managed:
    - name: /etc/consul.d/vault-service.json
    - source: salt://consul/files/vault-service.json.j2
    - template: jinja
    - user: consul
    - group: consul
    - mode: '0640'
    - context:
        vault_addr: {{ consul.get('vault', {}).get('address', 'http://localhost:8200') }}
    - require:
      - file: consul_directories
    - watch_in:
      - service: consul_service_running
{% endif %}