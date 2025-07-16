# Vault Service Management for Eos
# Replicates functionality from phase5_start_service.go
# Uses Eos-specific systemd configuration and port 8179

{% set vault = pillar.get('vault', {}) %}
{% set vault_user = vault.get('user', 'vault') %}
{% set vault_group = vault.get('group', 'vault') %}
{% set port = vault.get('port', '8179') %}
{% set hostname = grains.get('fqdn', grains.get('id', 'localhost')) %}

# Ensure prerequisites
include:
  - hashicorp.vault.config_eos

# Create Eos-specific systemd service file (replicating exact service from Go code)
vault_eos_systemd_service:
  file.managed:
    - name: /etc/systemd/system/vault.service
    - contents: |
        [Unit]
        Description=Vault Server (Eos)
        Documentation=https://www.vaultproject.io/docs/
        After=network.target
        
        [Service]
        User={{ vault_user }}
        Group={{ vault_group }}
        ExecStart=/usr/bin/vault server -config=/etc/vault.d/vault.hcl
        Restart=on-failure
        LimitNOFILE=65536
        
        # Environment file for VAULT_ADDR and VAULT_CACERT
        EnvironmentFile=-/etc/vault.d/vault.env
        
        [Install]
        WantedBy=multi-user.target
    - mode: 644
    - require:
      - file: vault_eos_config

# Reload systemd daemon
vault_systemd_daemon_reload:
  cmd.run:
    - name: systemctl daemon-reload
    - onchanges:
      - file: vault_eos_systemd_service

# Enable Vault service
vault_service_enable:
  service.enabled:
    - name: vault
    - require:
      - cmd: vault_systemd_daemon_reload

# Start Vault service
vault_service_start:
  service.running:
    - name: vault
    - enable: True
    - watch:
      - file: vault_eos_config
      - file: vault_eos_systemd_service
    - require:
      - service: vault_service_enable

# Health check with TCP connectivity test (replicating exact logic from Go code)
vault_health_check_tcp:
  cmd.run:
    - name: |
        # Wait for Vault to start and check TCP connectivity
        echo "Testing TCP connectivity to Vault on port {{ port }}"
        
        for i in {1..10}; do
          if timeout 3 bash -c "</dev/tcp/127.0.0.1/{{ port }}"; then
            echo "SUCCESS: Vault is responding on port {{ port }}"
            exit 0
          fi
          echo "Attempt $i: Waiting for Vault to start..."
          sleep 2
        done
        
        echo "FAILURE: Vault not responding on port {{ port }} after 20 seconds"
        echo "Checking service status:"
        systemctl status vault --no-pager || true
        echo "Recent logs:"
        journalctl -u vault -n 20 --no-pager || true
        exit 1
    - require:
      - service: vault_service_start

# Verify Vault binary and version
vault_binary_verification:
  cmd.run:
    - name: |
        if ! command -v vault >/dev/null 2>&1; then
          echo "ERROR: vault binary not found in PATH"
          exit 1
        fi
        
        echo "Vault binary verification:"
        which vault
        vault version
        echo "Vault installation verified successfully"
    - require:
      - service: vault_service_start

# Create status tracking file (for integration with existing Go code)
vault_service_status:
  file.managed:
    - name: /var/lib/eos/vault-service-status.json
    - contents: |
        {
          "service_started": "{{ salt['cmd.run']('date -Iseconds') }}",
          "port": {{ port }},
          "api_addr": "https://{{ hostname }}:{{ port }}",
          "health_check_passed": true,
          "managed_by": "salt"
        }
    - user: {{ vault_user }}
    - group: {{ vault_group }}
    - mode: 640
    - require:
      - cmd: vault_health_check_tcp
      - cmd: vault_binary_verification

# Create convenience script for Vault operations
vault_convenience_script:
  file.managed:
    - name: /usr/local/bin/eos-vault
    - contents: |
        #!/bin/bash
        # Eos Vault convenience script
        
        export VAULT_ADDR="https://{{ hostname }}:{{ port }}"
        export VAULT_CACERT="/etc/vault.d/ca.crt"
        
        case "$1" in
          status)
            vault status
            ;;
          health)
            /usr/local/bin/vault-health-check.sh
            ;;
          logs)
            journalctl -u vault -f
            ;;
          restart)
            sudo systemctl restart vault
            ;;
          *)
            echo "Usage: $0 {status|health|logs|restart}"
            echo "  status  - Show Vault status"
            echo "  health  - Run health check"
            echo "  logs    - Follow Vault logs"
            echo "  restart - Restart Vault service"
            exit 1
            ;;
        esac
    - mode: 755
    - require:
      - service: vault_service_start