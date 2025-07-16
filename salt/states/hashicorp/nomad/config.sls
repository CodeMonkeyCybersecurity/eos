# salt/states/hashicorp/nomad/config.sls
# HashiCorp Nomad configuration state

{% set nomad = pillar.get('nomad', {}) %}
{% set nomad_user = nomad.get('user', 'nomad') %}
{% set nomad_group = nomad.get('group', 'nomad') %}
{% set config_path = nomad.get('config_path', '/etc/nomad.d') %}
{% set data_path = nomad.get('data_path', '/opt/nomad/data') %}
{% set log_level = nomad.get('log_level', 'INFO') %}
{% set datacenter = nomad.get('datacenter', 'dc1') %}
{% set region = nomad.get('region', 'global') %}
{% set server_mode = nomad.get('server_mode', True) %}
{% set client_mode = nomad.get('client_mode', True) %}
{% set bootstrap_expect = nomad.get('bootstrap_expect', 1) %}
{% set encrypt_key = nomad.get('encrypt_key', '') %}

# Main Nomad configuration
nomad_config:
  file.managed:
    - name: {{ config_path }}/nomad.hcl
    - contents: |
        # Nomad Configuration
        datacenter = "{{ datacenter }}"
        data_dir   = "{{ data_path }}"
        log_level  = "{{ log_level }}"
        
        bind_addr = "0.0.0.0"
        
        # Server configuration
        {% if server_mode %}
        server {
          enabled          = true
          bootstrap_expect = {{ bootstrap_expect }}
          
          {% if encrypt_key %}
          encrypt = "{{ encrypt_key }}"
          {% endif %}
        }
        {% endif %}
        
        # Client configuration
        {% if client_mode %}
        client {
          enabled       = true
          network_interface = "{{ nomad.get('network_interface', 'eth0') }}"
          
          servers = [
            {% for server in nomad.get('servers', ['127.0.0.1:4647']) %}
            "{{ server }}",
            {% endfor %}
          ]
          
          # Enable raw exec driver (use with caution)
          options = {
            "driver.raw_exec.enable" = "{{ nomad.get('enable_raw_exec', 'false') }}"
          }
        }
        {% endif %}
        
        # ACL configuration
        {% if nomad.get('acl_enabled', False) %}
        acl {
          enabled = true
        }
        {% endif %}
        
        # Consul integration
        {% if nomad.get('consul_enabled', False) %}
        consul {
          address = "{{ nomad.get('consul_address', '127.0.0.1:8500') }}"
        }
        {% endif %}
        
        # Vault integration
        {% if nomad.get('vault_enabled', False) %}
        vault {
          enabled = true
          address = "{{ nomad.get('vault_address', 'https://127.0.0.1:8200') }}"
          token   = "{{ nomad.get('vault_token', '') }}"
          
          {% if nomad.get('vault_ca_cert') %}
          ca_cert = "{{ nomad.get('vault_ca_cert') }}"
          {% endif %}
          
          create_from_role = "{{ nomad.get('vault_role', 'nomad-cluster') }}"
        }
        {% endif %}
        
        # TLS configuration
        {% if nomad.get('tls_enabled', False) %}
        tls {
          http = true
          rpc  = true
          
          ca_file   = "{{ nomad.get('ca_file', '/etc/nomad.d/ca.pem') }}"
          cert_file = "{{ nomad.get('cert_file', '/etc/nomad.d/server.pem') }}"
          key_file  = "{{ nomad.get('key_file', '/etc/nomad.d/server-key.pem') }}"
          
          verify_server_hostname = {{ nomad.get('verify_server_hostname', 'true') }}
          verify_https_client    = {{ nomad.get('verify_https_client', 'false') }}
        }
        {% endif %}
        
        # Telemetry configuration
        {% if nomad.get('telemetry_enabled', False) %}
        telemetry {
          collection_interval = "{{ nomad.get('telemetry_interval', '1s') }}"
          disable_hostname    = {{ nomad.get('telemetry_disable_hostname', 'false') }}
          
          {% if nomad.get('prometheus_metrics', False) %}
          prometheus_metrics = true
          {% endif %}
        }
        {% endif %}
        
        # Ports configuration
        ports {
          http = {{ nomad.get('http_port', 4646) }}
          rpc  = {{ nomad.get('rpc_port', 4647) }}
          serf = {{ nomad.get('serf_port', 4648) }}
        }
        
        # Plugin configuration
        plugin "docker" {
          config {
            enabled = {{ nomad.get('docker_enabled', 'true') }}
            
            volumes {
              enabled = {{ nomad.get('docker_volumes_enabled', 'true') }}
            }
            
            {% if nomad.get('docker_allow_privileged', False) %}
            allow_privileged = true
            {% endif %}
          }
        }
        
    - user: {{ nomad_user }}
    - group: {{ nomad_group }}
    - mode: 640
    - require:
      - file: nomad_directories

# Create systemd service file
nomad_systemd_service:
  file.managed:
    - name: /etc/systemd/system/nomad.service
    - contents: |
        [Unit]
        Description=Nomad Server (Eos)
        Documentation=https://www.nomadproject.io/
        Requires=network-online.target
        After=network-online.target
        ConditionFileNotEmpty={{ config_path }}/nomad.hcl
        
        [Service]
        Type=notify
        User={{ nomad_user }}
        Group={{ nomad_group }}
        ExecStart=/usr/local/bin/nomad agent -config={{ config_path }}
        ExecReload=/bin/kill -HUP $MAINPID
        KillMode=process
        Restart=on-failure
        LimitNOFILE=65536
        
        [Install]
        WantedBy=multi-user.target
    - mode: 644
    - require:
      - file: nomad_config

# Reload systemd daemon
nomad_systemd_reload:
  cmd.run:
    - name: systemctl daemon-reload
    - require:
      - file: nomad_systemd_service