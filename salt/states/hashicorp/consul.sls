# Consul Installation via Salt
# Manages HashiCorp Consul installation following Eos architectural principles

# Include shared HashiCorp repository setup
include:
  - hashicorp

consul_package:
  pkg.installed:
    - name: consul
    - require:
      - pkgrepo: hashicorp_repo

consul_user:
  user.present:
    - name: consul
    - system: true
    - shell: /bin/false
    - home: /var/lib/consul
    - require:
      - pkg: consul_package

consul_directories:
  file.directory:
    - names:
      - /etc/consul.d
      - /var/lib/consul
      - /var/log/consul
    - user: consul
    - group: consul
    - mode: 750
    - makedirs: true
    - require:
      - user: consul_user

consul_binary_verify:
  cmd.run:
    - name: consul version
    - require:
      - pkg: consul_package

# Pre-flight checks for Consul
consul_port_check:
  cmd.run:
    - name: |
        for port in {{ pillar.get('consul:http_port', '8161') }} {{ pillar.get('consul:dns_port', '8600') }} {{ pillar.get('consul:grpc_port', '8502') }}; do
          if lsof -i :$port > /dev/null 2>&1; then
            echo "ERROR: Port $port is already in use"
            lsof -i :$port
            exit 1
          fi
        done
        echo "All required ports are available"
    - require:
      - pkg: consul_package
    - require_in:
      - service: consul_service_running

# Ensure consul is in PATH
consul_binary_link:
  file.symlink:
    - name: /usr/local/bin/consul
    - target: /usr/bin/consul
    - makedirs: true
    - require:
      - pkg: consul_package
    - onlyif: test -f /usr/bin/consul && ! test -L /usr/local/bin/consul

# Basic consul configuration
consul_config:
  file.managed:
    - name: /etc/consul.d/consul.hcl
    - contents: |
        # Consul configuration managed by Salt
        datacenter = "{{ pillar.get('consul:datacenter', 'dc1') }}"
        data_dir = "/var/lib/consul"
        log_level = "{{ pillar.get('consul:log_level', 'INFO') }}"
        server = {{ pillar.get('consul:server_mode', 'false') }}
        bootstrap_expect = {{ pillar.get('consul:bootstrap_expect', '1') }}
        {% set bind_addr = pillar.get('consul:bind_addr', '0.0.0.0') %}
        {% if bind_addr == '0.0.0.0' %}
          {% set ipv4_addrs = grains.get('ipv4', []) %}
          {% if ipv4_addrs and ipv4_addrs|length > 0 %}
            {% set bind_addr = ipv4_addrs|reject('equalto', '127.0.0.1')|first|default(ipv4_addrs[0]) %}
          {% else %}
            {% set bind_addr = '127.0.0.1' %}
          {% endif %}
        {% endif %}
        bind_addr = "{{ bind_addr }}"
        client_addr = "{{ pillar.get('consul:client_addr', '127.0.0.1') }}"
        ui_config {
          enabled = {{ pillar.get('consul:ui_enabled', 'true') }}
        }
        connect {
          enabled = {{ pillar.get('consul:connect_enabled', 'true') }}
        }
        ports {
          http = {{ pillar.get('consul:http_port', '8161') }}
          dns = {{ pillar.get('consul:dns_port', '8600') }}
          grpc = {{ pillar.get('consul:grpc_port', '8502') }}
        }
        {% if pillar.get('consul:vault_integration', false) %}
        # Vault integration enabled
        auto_reload_config = true
        {% endif %}
    - user: consul
    - group: consul
    - mode: 640
    - require:
      - file: consul_directories
      - pkg: consul_package

# Validate Consul configuration before starting
consul_config_validate:
  cmd.run:
    - name: consul validate /etc/consul.d/
    - runas: consul
    - require:
      - file: consul_config
      - file: consul_directories
    - require_in:
      - service: consul_service_running

# Systemd service for consul
consul_service:
  file.managed:
    - name: /etc/systemd/system/consul.service
    - contents: |
        [Unit]
        Description=Consul
        Documentation=https://www.consul.io/
        Requires=network-online.target
        After=network-online.target
        ConditionFileNotEmpty=/etc/consul.d/consul.hcl

        [Service]
        Type=notify
        User=consul
        Group=consul
        ExecStart=/usr/bin/consul agent -config-dir=/etc/consul.d/
        ExecReload=/bin/kill -HUP $MAINPID
        KillMode=process
        Restart=on-failure
        LimitNOFILE=65536

        [Install]
        WantedBy=multi-user.target
    - require:
      - pkg: consul_package
      - file: consul_config
  cmd.run:
    - name: systemctl daemon-reload
    - require:
      - file: consul_service

# Enable and start consul service
consul_service_enabled:
  service.enabled:
    - name: consul
    - require:
      - file: consul_service
      - cmd: consul_service

consul_service_running:
  service.running:
    - name: consul
    - enable: True
    - restart: True
    - retry:
        attempts: 3
        interval: 5
    - watch:
      - file: consul_config
      - file: consul_service
    - require:
      - service: consul_service_enabled
      - cmd: consul_config_validate
      - cmd: consul_port_check

# Debug output on failure
consul_debug_on_failure:
  cmd.run:
    - name: |
        echo "=== Consul Service Status ==="
        systemctl status consul.service
        echo ""
        echo "=== Consul Journal Logs ==="
        journalctl -xeu consul.service -n 50 --no-pager
        echo ""
        echo "=== Consul Configuration ==="
        cat /etc/consul.d/consul.hcl
        echo ""
        echo "=== Consul Validation ==="
        consul validate /etc/consul.d/ || true
        echo ""
        echo "=== Port Usage ==="
        lsof -i :{{ pillar.get('consul:http_port', '8161') }} || true
        lsof -i :{{ pillar.get('consul:dns_port', '8600') }} || true
        lsof -i :{{ pillar.get('consul:grpc_port', '8502') }} || true
    - onfail:
      - service: consul_service_running