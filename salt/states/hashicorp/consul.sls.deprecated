# Consul Installation via Salt
# Manages HashiCorp Consul installation following Eos architectural principles
# Implements idempotent operations with force/clean options

# Include shared HashiCorp repository setup
include:
  - hashicorp

# Get pillar values for control flow
{% set force_reinstall = pillar.get('consul:force_reinstall', False) %}
{% set clean_install = pillar.get('consul:clean_install', False) %}

# Pre-flight status check
consul_preflight_check:
  cmd.run:
    - name: |
        #!/bin/bash
        set -e
        
        echo "=== Consul Pre-flight Checks ==="
        echo "Force reinstall: {{ force_reinstall }}"
        echo "Clean install: {{ clean_install }}"
        
        # Initialize status variables
        CONSUL_INSTALLED=false
        CONSUL_RUNNING=false
        CONSUL_FAILED=false
        CONFIG_VALID=false
        
        # Check if Consul binary exists
        if command -v consul >/dev/null 2>&1; then
          CONSUL_INSTALLED=true
          echo "Consul binary found: $(which consul)"
          echo "Version: $(consul version | head -1)"
        fi
        
        # Check service status
        if systemctl is-active consul.service >/dev/null 2>&1; then
          CONSUL_RUNNING=true
          echo "Consul service is running"
        elif systemctl is-failed consul.service >/dev/null 2>&1; then
          CONSUL_FAILED=true
          echo "Consul service is in failed state"
        fi
        
        # Check config validity if Consul is installed
        if [ "$CONSUL_INSTALLED" = "true" ] && [ -f /etc/consul.d/consul.hcl ]; then
          if consul validate /etc/consul.d/ >/dev/null 2>&1; then
            CONFIG_VALID=true
            echo "Consul configuration is valid"
          else
            echo "Consul configuration is invalid"
          fi
        fi
        
        # Decision logic
        if [ "$CONSUL_RUNNING" = "true" ] && [ "$CONFIG_VALID" = "true" ]; then
          if [ "{{ force_reinstall }}" != "True" ] && [ "{{ clean_install }}" != "True" ]; then
            echo ""
            echo "=== Consul is already running successfully ==="
            echo "Consul version: $(consul version | head -1)"
            echo "Service status: active"
            echo ""
            echo "To force reinstallation, run with --force"
            echo "To clean install, run with --clean"
            exit 0
          fi
        fi
        
        # If Consul is failed and no force flags
        if [ "$CONSUL_FAILED" = "true" ]; then
          if [ "{{ force_reinstall }}" != "True" ] && [ "{{ clean_install }}" != "True" ]; then
            echo ""
            echo "=== ERROR: Consul service is in failed state ==="
            echo "Last 10 lines of logs:"
            journalctl -u consul.service -n 10 --no-pager || true
            echo ""
            echo "Options:"
            echo "1. Fix the issue manually and restart"
            echo "2. Run with --force to reconfigure"
            echo "3. Run with --clean to start fresh"
            exit 1
          fi
        fi
        
        echo ""
        echo "=== Proceeding with Consul installation ==="
    - stateful: False

# Clean up if requested
{% if clean_install %}
consul_cleanup_stop_service:
  service.dead:
    - name: consul
    - enable: False
    - onlyif: systemctl list-unit-files | grep -q consul.service

consul_cleanup_processes:
  cmd.run:
    - name: pkill -f consul || true
    - require:
      - service: consul_cleanup_stop_service

consul_cleanup_config:
  file.absent:
    - names:
      - /etc/consul.d
      - /etc/consul
    - require:
      - cmd: consul_cleanup_processes

consul_cleanup_data:
  cmd.run:
    - name: |
        echo "WARNING: Cleaning Consul data directory"
        rm -rf /var/lib/consul/*
    - onlyif: test -d /var/lib/consul
    - require:
      - file: consul_cleanup_config

consul_cleanup_logs:
  file.absent:
    - name: /var/log/consul
    - require:
      - cmd: consul_cleanup_data

consul_reset_systemd:
  cmd.run:
    - name: systemctl reset-failed consul.service || true
    - require:
      - service: consul_cleanup_stop_service
{% endif %}

# Stop service if force reinstall
{% if force_reinstall and not clean_install %}
consul_force_stop_service:
  service.dead:
    - name: consul
    - onlyif: systemctl is-active consul.service
{% endif %}

# Backup existing configuration if not clean install
{% if not clean_install %}
consul_backup_config:
  cmd.run:
    - name: |
        if [ -f /etc/consul.d/consul.hcl ]; then
          BACKUP_FILE="/etc/consul.d/consul.hcl.backup.$(date +%Y%m%d_%H%M%S)"
          cp /etc/consul.d/consul.hcl "$BACKUP_FILE"
          echo "Backed up existing config to $BACKUP_FILE"
        fi
    - onlyif: test -f /etc/consul.d/consul.hcl
{% endif %}

consul_package:
  pkg.installed:
    - name: consul
    - require:
      - pkgrepo: hashicorp_repo
      - cmd: consul_preflight_check

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
    - unless: systemctl is-active consul.service

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
        server = {{ pillar.get('consul:server_mode', false)|lower }}
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

# Final verification
consul_final_verification:
  cmd.run:
    - name: |
        echo "=== Consul Installation Verification ==="
        
        # Check service status
        if systemctl is-active consul.service >/dev/null 2>&1; then
          echo "✓ Consul service is running"
        else
          echo "✗ Consul service is not running"
          systemctl status consul.service --no-pager || true
          exit 1
        fi
        
        # Check cluster health
        if timeout 5 consul members >/dev/null 2>&1; then
          echo "✓ Consul cluster is responding"
          consul members
        else
          echo "✗ Consul cluster is not responding"
          exit 1
        fi
        
        # Check API
        if curl -sf http://localhost:{{ pillar.get('consul:http_port', '8161') }}/v1/status/leader >/dev/null; then
          echo "✓ Consul API is accessible"
        else
          echo "✗ Consul API is not accessible"
          exit 1
        fi
        
        echo ""
        echo "=== Consul Successfully Installed ==="
        consul version
    - require:
      - service: consul_service_running