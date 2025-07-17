# Configure HashiCorp Nomad

{% set nomad = pillar.get('nomad', {}) %}
{% set datacenter = nomad.get('datacenter', 'dc1') %}
{% set region = nomad.get('region', 'global') %}
{% set node_role = nomad.get('node_role', 'both') %}
{% set data_dir = nomad.get('data_dir', '/opt/nomad/data') %}
{% set config_dir = nomad.get('config_dir', '/etc/nomad.d') %}
{% set log_level = nomad.get('log_level', 'INFO') %}

# Generate Nomad configuration
nomad_config:
  file.managed:
    - name: {{ config_dir }}/nomad.hcl
    - user: nomad
    - group: nomad
    - mode: 640
    - contents: |
        # Nomad Configuration
        datacenter = "{{ datacenter }}"
        region = "{{ region }}"
        data_dir = "{{ data_dir }}"
        log_level = "{{ log_level }}"
        
        # Bind configuration
        bind_addr = "0.0.0.0"
        
        # Ports configuration
        ports {
          http = {{ nomad.get('http_port', 4646) }}
          rpc = {{ nomad.get('rpc_port', 4647) }}
          serf = {{ nomad.get('serf_port', 4648) }}
        }
        
        {% if node_role in ['server', 'both'] %}
        # Server configuration
        server {
          enabled = true
          bootstrap_expect = {{ nomad.get('server_bootstrap_expect', 1) }}
          
          {% if nomad.get('enable_ui', true) %}
          ui_config {
            enabled = true
          }
          {% endif %}
        }
        {% endif %}
        
        {% if node_role in ['client', 'both'] %}
        # Client configuration
        client {
          enabled = true
          
          # Network configuration
          network_interface = "{{ nomad.get('network_interface', 'eth0') }}"
          
          # Reserved resources
          reserved {
            cpu = {{ nomad.get('client_reserved', {}).get('cpu', 100) }}
            memory = {{ nomad.get('client_reserved', {}).get('memory', 256) }}
            disk = {{ nomad.get('client_reserved', {}).get('disk', 1024) }}
            reserved_ports = "{{ nomad.get('client_reserved', {}).get('ports', '22') }}"
          }
          
          # Plugin configuration
          plugin "docker" {
            config {
              enabled = {{ nomad.get('docker_enabled', true) | lower }}
              {% if nomad.get('docker_enabled', true) %}
              allow_privileged = false
              allow_caps = ["chown", "dac_override", "fsetid", "fowner", "mknod", "net_raw", "setgid", "setuid", "setfcap", "setpcap", "net_bind_service", "sys_chroot", "kill", "audit_write"]
              {% endif %}
            }
          }
          
          plugin "exec" {
            config {
              enabled = {{ nomad.get('exec_enabled', true) | lower }}
            }
          }
          
          plugin "raw_exec" {
            config {
              enabled = {{ nomad.get('raw_exec_enabled', false) | lower }}
            }
          }
        }
        {% endif %}
        
        {% if nomad.get('consul_integration', true) %}
        # Consul integration
        consul {
          address = "{{ nomad.get('consul_address', '127.0.0.1:8500') }}"
          server_service_name = "nomad"
          client_service_name = "nomad-client"
          auto_advertise = true
          server_auto_join = true
          client_auto_join = true
        }
        {% endif %}
        
        {% if nomad.get('vault_integration', true) %}
        # Vault integration
        vault {
          enabled = true
          address = "{{ nomad.get('vault_address', 'http://127.0.0.1:8200') }}"
          create_from_role = "nomad-cluster"
        }
        {% endif %}
        
        {% if nomad.get('enable_tls', true) %}
        # TLS configuration
        tls {
          http = true
          rpc = true
          
          ca_file = "{{ config_dir }}/tls/ca.pem"
          cert_file = "{{ config_dir }}/tls/nomad.pem"
          key_file = "{{ config_dir }}/tls/nomad-key.pem"
          
          verify_server_hostname = true
          verify_https_client = true
        }
        {% endif %}
        
        {% if nomad.get('enable_acl', true) %}
        # ACL configuration
        acl {
          enabled = true
          token_ttl = "30s"
          policy_ttl = "30s"
        }
        {% endif %}
        
        {% if nomad.get('enable_telemetry', true) %}
        # Telemetry configuration
        telemetry {
          collection_interval = "10s"
          disable_hostname = false
          prometheus_metrics = true
          publish_allocation_metrics = true
          publish_node_metrics = true
        }
        {% endif %}
        
        # Logging configuration
        log_rotate_duration = "24h"
        log_rotate_max_files = 5
    - require:
      - file: nomad_config_dir

# Generate TLS certificates if TLS is enabled
{% if nomad.get('enable_tls', true) %}
generate_nomad_tls:
  cmd.run:
    - name: |
        cd {{ config_dir }}/tls
        
        # Generate CA if it doesn't exist
        if [ ! -f ca.pem ]; then
          nomad tls ca create
        fi
        
        # Generate server certificate
        if [ ! -f nomad.pem ]; then
          nomad tls cert create -server -region {{ region }} -domain {{ datacenter }}
        fi
        
        # Generate client certificate
        if [ ! -f nomad-client.pem ]; then
          nomad tls cert create -client -region {{ region }} -domain {{ datacenter }}
        fi
        
        # Set correct permissions
        chown nomad:nomad *.pem
        chmod 600 *.pem
    - require:
      - file: nomad_tls_dir
      - file: nomad_config
    - unless: test -f {{ config_dir }}/tls/nomad.pem
{% endif %}

# Create environment file
nomad_env_file:
  file.managed:
    - name: /etc/default/nomad
    - contents: |
        # Nomad environment variables
        NOMAD_ADDR=http://127.0.0.1:{{ nomad.get('http_port', 4646) }}
        NOMAD_REGION={{ region }}
        NOMAD_DATACENTER={{ datacenter }}
        {% if nomad.get('enable_tls', true) %}
        NOMAD_ADDR=https://127.0.0.1:{{ nomad.get('http_port', 4646) }}
        NOMAD_CACERT={{ config_dir }}/tls/ca.pem
        NOMAD_CLIENT_CERT={{ config_dir }}/tls/nomad-client.pem
        NOMAD_CLIENT_KEY={{ config_dir }}/tls/nomad-client-key.pem
        {% endif %}

# Create Nomad policy for Vault integration
{% if nomad.get('vault_integration', true) %}
nomad_vault_policy:
  file.managed:
    - name: /tmp/nomad-cluster-policy.hcl
    - contents: |
        # Allow creating tokens under "nomad-cluster" token role
        path "auth/token/create/nomad-cluster" {
          capabilities = ["update"]
        }
        
        # Allow looking up "nomad-cluster" token role
        path "auth/token/roles/nomad-cluster" {
          capabilities = ["read"]
        }
        
        # Allow looking up the token passed to Nomad to validate
        path "auth/token/lookup-self" {
          capabilities = ["read"]
        }
        
        # Allow looking up incoming tokens to validate they have permissions
        path "auth/token/lookup" {
          capabilities = ["update"]
        }
        
        # Allow revoking tokens that should no longer exist
        path "auth/token/revoke-accessor" {
          capabilities = ["update"]
        }
        
        # Allow checking the capabilities of our own token
        path "sys/capabilities-self" {
          capabilities = ["update"]
        }
        
        # Allow our own token to be renewed
        path "auth/token/renew-self" {
          capabilities = ["update"]
        }

# Apply the policy to Vault (if Vault is running)
apply_nomad_vault_policy:
  cmd.run:
    - name: |
        if systemctl is-active --quiet vault; then
          vault policy write nomad-cluster /tmp/nomad-cluster-policy.hcl
          vault write auth/token/roles/nomad-cluster \
            allowed_policies=nomad-cluster \
            explicit_max_ttl=0 \
            name=nomad-cluster \
            orphan=false \
            period=259200 \
            renewable=true
        fi
    - require:
      - file: nomad_vault_policy
    - onlyif: systemctl is-active --quiet vault
{% endif %}