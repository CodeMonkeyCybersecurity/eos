# Nomad Installation and Configuration via Salt
# Comprehensive idempotent installation with server/client modes

{% set server_mode = salt['pillar.get']('nomad:server_mode', False) %}
{% set client_mode = salt['pillar.get']('nomad:client_mode', True) %}
{% set datacenter = salt['pillar.get']('nomad:datacenter', 'dc1') %}
{% set region = salt['pillar.get']('nomad:region', 'global') %}
{% set bootstrap_expect = salt['pillar.get']('nomad:bootstrap_expect', 1) %}
{% set bind_addr = salt['pillar.get']('nomad:bind_addr', '0.0.0.0') %}
{% set advertise_addr = salt['pillar.get']('nomad:advertise_addr', '') %}
{% set log_level = salt['pillar.get']('nomad:log_level', 'INFO') %}
{% set enable_acl = salt['pillar.get']('nomad:enable_acl', False) %}
{% set enable_docker = salt['pillar.get']('nomad:enable_docker', True) %}
{% set enable_raw_exec = salt['pillar.get']('nomad:enable_raw_exec', False) %}
{% set consul_integration = salt['pillar.get']('nomad:consul_integration', False) %}
{% set vault_integration = salt['pillar.get']('nomad:vault_integration', False) %}
{% set join_addrs = salt['pillar.get']('nomad:join_addrs', []) %}
{% set client_servers = salt['pillar.get']('nomad:client_servers', []) %}
{% set force = salt['pillar.get']('nomad:force', False) %}
{% set clean = salt['pillar.get']('nomad:clean', False) %}

# Include pre-flight checks
include:
  - hashicorp.nomad_preflight

# Add HashiCorp GPG key
nomad_add_hashicorp_key:
  cmd.run:
    - name: |
        if [ ! -f /usr/share/keyrings/hashicorp-archive-keyring.gpg ]; then
          wget -O- https://apt.releases.hashicorp.com/gpg | \
          gpg --dearmor | \
          tee /usr/share/keyrings/hashicorp-archive-keyring.gpg > /dev/null
        fi
    - unless: test -f /usr/share/keyrings/hashicorp-archive-keyring.gpg

# Add HashiCorp repository
nomad_add_hashicorp_repo:
  pkgrepo.managed:
    - name: deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com {{ grains['oscodename'] }} main
    - file: /etc/apt/sources.list.d/hashicorp.list
    - require:
      - cmd: nomad_add_hashicorp_key
    - unless: grep -q "apt.releases.hashicorp.com" /etc/apt/sources.list.d/hashicorp.list

# Update package cache
nomad_update_apt_cache:
  cmd.run:
    - name: apt-get update
    - require:
      - pkgrepo: nomad_add_hashicorp_repo

# Clean installation if requested
{% if clean %}
nomad_clean_existing:
  cmd.run:
    - name: |
        echo "Performing clean Nomad removal..."
        
        # Stop service if running
        systemctl stop nomad.service 2>/dev/null || true
        
        # Remove package
        apt-get remove -y nomad 2>/dev/null || true
        
        # Remove data and config
        rm -rf /var/lib/nomad
        rm -rf /etc/nomad.d
        rm -rf /opt/nomad
        rm -f /etc/systemd/system/nomad.service
        
        # Remove user and group
        userdel -r nomad 2>/dev/null || true
        groupdel nomad 2>/dev/null || true
        
        echo "Clean removal completed"
    - require:
      - cmd: nomad_update_apt_cache
    - onlyif: test -f /usr/bin/nomad || test -d /etc/nomad.d
{% endif %}

# Install Nomad package
nomad_install:
  pkg.installed:
    - name: nomad
    - require:
      - cmd: nomad_update_apt_cache
      {% if clean %}
      - cmd: nomad_clean_existing
      {% endif %}

# Create Nomad user and group
nomad_user:
  user.present:
    - name: nomad
    - system: True
    - shell: /bin/false
    - home: /var/lib/nomad
    - createhome: False
    - require:
      - pkg: nomad_install

nomad_group:
  group.present:
    - name: nomad
    - system: True
    - require:
      - pkg: nomad_install

# Create required directories
nomad_directories:
  file.directory:
    - names:
      - /etc/nomad.d
      - /var/lib/nomad
      - /var/log/nomad
      - /opt/nomad
      - /opt/nomad/data
    - user: nomad
    - group: nomad
    - mode: 755
    - makedirs: True
    - require:
      - user: nomad_user
      - group: nomad_group

# Get network configuration
nomad_get_network_info:
  cmd.run:
    - name: |
        # Load network info from preflight check
        if [ -f /tmp/nomad_network_info ]; then
          source /tmp/nomad_network_info
        else
          # Fallback to getting it again
          PRIMARY_IFACE=$(ip route | grep default | head -1 | awk '{print $5}')
          PRIMARY_IP=$(ip -4 addr show $PRIMARY_IFACE | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
        fi
        
        # Determine advertise address
        ADVERTISE_ADDR="{{ advertise_addr }}"
        if [ -z "$ADVERTISE_ADDR" ]; then
          ADVERTISE_ADDR="$PRIMARY_IP"
        fi
        
        # Store for configuration
        echo "ADVERTISE_ADDR=$ADVERTISE_ADDR" > /tmp/nomad_advertise_addr
    - require:
      - file: nomad_directories

# Create Nomad configuration
nomad_config:
  file.managed:
    - name: /etc/nomad.d/nomad.hcl
    - source: salt://hashicorp/files/nomad.hcl.jinja
    - template: jinja
    - user: nomad
    - group: nomad
    - mode: 640
    - defaults:
        server_mode: {{ server_mode }}
        client_mode: {{ client_mode }}
        datacenter: {{ datacenter }}
        region: {{ region }}
        bootstrap_expect: {{ bootstrap_expect }}
        bind_addr: {{ bind_addr }}
        log_level: {{ log_level }}
        enable_acl: {{ enable_acl }}
        enable_docker: {{ enable_docker }}
        enable_raw_exec: {{ enable_raw_exec }}
        consul_integration: {{ consul_integration }}
        vault_integration: {{ vault_integration }}
        join_addrs: {{ join_addrs }}
        client_servers: {{ client_servers }}
    - require:
      - cmd: nomad_get_network_info

# Create systemd service file
nomad_service_file:
  file.managed:
    - name: /etc/systemd/system/nomad.service
    - source: salt://hashicorp/files/nomad.service
    - user: root
    - group: root
    - mode: 644
    - require:
      - file: nomad_config

# Reload systemd
nomad_systemd_reload:
  cmd.run:
    - name: systemctl daemon-reload
    - onchanges:
      - file: nomad_service_file

# Validate configuration
nomad_validate_config:
  cmd.run:
    - name: |
        echo "Validating Nomad configuration..."
        if ! nomad config validate /etc/nomad.d/nomad.hcl; then
          echo "ERROR: Invalid Nomad configuration"
          exit 1
        fi
        echo "✓ Configuration is valid"
    - require:
      - file: nomad_config

# Stop service if force mode (for reconfiguration)
{% if force %}
nomad_stop_for_reconfig:
  service.dead:
    - name: nomad
    - require:
      - cmd: nomad_validate_config
    - prereq:
      - service: nomad_service
{% endif %}

# Start and enable Nomad service
nomad_service:
  service.running:
    - name: nomad
    - enable: True
    - require:
      - cmd: nomad_systemd_reload
      - cmd: nomad_validate_config
    - watch:
      - file: nomad_config
      - file: nomad_service_file

# Wait for service to stabilize
nomad_wait_for_service:
  cmd.run:
    - name: |
        echo "Waiting for Nomad to start..."
        for i in {1..30}; do
          if nomad status >/dev/null 2>&1; then
            echo "✓ Nomad is responding"
            break
          fi
          echo "Waiting... ($i/30)"
          sleep 2
        done
        
        if ! nomad status >/dev/null 2>&1; then
          echo "ERROR: Nomad failed to start properly"
          journalctl -u nomad -n 50 --no-pager
          exit 1
        fi
    - require:
      - service: nomad_service

# Join cluster if addresses provided
{% if server_mode and join_addrs %}
nomad_join_servers:
  cmd.run:
    - name: |
        echo "Joining Nomad server cluster..."
        {% for addr in join_addrs %}
        nomad server join {{ addr }} || echo "Failed to join {{ addr }}"
        {% endfor %}
        
        # Show cluster status
        sleep 2
        nomad server members
    - require:
      - cmd: nomad_wait_for_service
{% endif %}

{% if client_mode and client_servers %}
nomad_configure_client_servers:
  cmd.run:
    - name: |
        echo "Client configured to connect to servers:"
        {% for server in client_servers %}
        echo "  - {{ server }}"
        {% endfor %}
        
        # Restart to pick up server configuration
        systemctl restart nomad
        sleep 5
        
        # Check node status
        nomad node status
    - require:
      - cmd: nomad_wait_for_service
{% endif %}

# Bootstrap ACL if enabled
{% if enable_acl and server_mode and bootstrap_expect == 1 %}
nomad_bootstrap_acl:
  cmd.run:
    - name: |
        echo "Bootstrapping Nomad ACL system..."
        
        # Check if already bootstrapped
        if nomad acl bootstrap 2>&1 | grep -q "already bootstrapped"; then
          echo "ACL system already bootstrapped"
        else
          # Bootstrap and save token
          BOOTSTRAP_OUTPUT=$(nomad acl bootstrap)
          echo "$BOOTSTRAP_OUTPUT"
          
          # Extract and save management token
          MGMT_TOKEN=$(echo "$BOOTSTRAP_OUTPUT" | grep "Secret ID" | awk '{print $4}')
          if [ -n "$MGMT_TOKEN" ]; then
            echo "$MGMT_TOKEN" > /opt/nomad/management.token
            chmod 600 /opt/nomad/management.token
            chown nomad:nomad /opt/nomad/management.token
            echo ""
            echo "Management token saved to: /opt/nomad/management.token"
            echo "IMPORTANT: Save this token securely!"
          fi
        fi
    - require:
      - cmd: nomad_wait_for_service
{% endif %}

# Final verification
nomad_verify_installation:
  cmd.run:
    - name: |
        echo ""
        echo "=== Nomad Installation Verification ==="
        echo "Version: $(nomad version | head -n1)"
        echo "Status: $(systemctl is-active nomad)"
        
        # Get agent info
        echo ""
        echo "Agent Information:"
        nomad agent-info | grep -E "(region|datacenter|server|client)" || true
        
        {% if server_mode %}
        echo ""
        echo "Server Members:"
        nomad server members 2>/dev/null || echo "Unable to get server members"
        {% endif %}
        
        {% if client_mode %}
        echo ""
        echo "Node Status:"
        nomad node status 2>/dev/null || echo "Unable to get node status"
        {% endif %}
        
        echo ""
        echo "✓ Nomad installation completed successfully!"
    - require:
      - cmd: nomad_wait_for_service
      {% if enable_acl and server_mode and bootstrap_expect == 1 %}
      - cmd: nomad_bootstrap_acl
      {% endif %}