# salt/states/hashicorp/vault/service.sls
# HashiCorp Vault service management state

{% set vault = pillar.get('vault', {}) %}
{% set vault_user = vault.get('user', 'vault') %}
{% set vault_group = vault.get('group', 'vault') %}
{% set config_path = vault.get('config_path', '/etc/vault.d') %}

include:
  - hashicorp.vault.config

# Systemd service file
vault_systemd_service:
  file.managed:
    - name: /etc/systemd/system/vault.service
    - contents: |
        [Unit]
        Description=HashiCorp Vault
        Documentation=https://www.vaultproject.io/docs/
        Requires=network-online.target
        After=network-online.target
        ConditionFileNotEmpty={{ config_path }}/vault.hcl

        [Service]
        Type=notify
        User={{ vault_user }}
        Group={{ vault_group }}
        ProtectSystem=full
        ProtectHome=read-only
        PrivateTmp=yes
        PrivateDevices=yes
        SecureBits=keep-caps
        AmbientCapabilities=CAP_IPC_LOCK
        Capabilities=CAP_IPC_LOCK+ep
        CapabilityBoundingSet=CAP_SYSLOG CAP_IPC_LOCK
        NoNewPrivileges=yes
        ExecStart=/usr/local/bin/vault server -config={{ config_path }}/vault.hcl
        ExecReload=/bin/kill --signal HUP $MAINPID
        KillMode=process
        Restart=on-failure
        RestartSec=5
        TimeoutStopSec=30
        StartLimitInterval=60
        StartLimitBurst=3
        LimitNOFILE=65536
        LimitMEMLOCK=infinity
        
        # Environment file
        EnvironmentFile=-{{ config_path }}/vault.env

        [Install]
        WantedBy=multi-user.target
    - mode: 644
    - require:
      - file: vault_config

# Reload systemd
vault_systemd_reload:
  cmd.run:
    - name: systemctl daemon-reload
    - onchanges:
      - file: vault_systemd_service

# Enable and start Vault service
vault_service:
  service.running:
    - name: vault
    - enable: True
    - reload: True
    - watch:
      - file: vault_config
      - file: vault_systemd_service
    - require:
      - cmd: vault_systemd_reload

# Wait for Vault to be ready
vault_wait_ready:
  cmd.run:
    - name: |
        for i in {1..30}; do
          if vault status >/dev/null 2>&1; then
            echo "Vault is ready"
            exit 0
          fi
          echo "Waiting for Vault to start... ($i/30)"
          sleep 2
        done
        echo "Vault failed to start within timeout"
        exit 1
    - env:
      - VAULT_ADDR: "{{ vault.get('api_addr', 'https://localhost:8200') }}"
    - require:
      - service: vault_service

# Create init status file to track initialization
vault_init_status:
  file.managed:
    - name: {{ config_path }}/vault-init-status.json
    - contents: |
        {
          "installed": "{{ salt['cmd.run']('date -Iseconds') }}",
          "version": "{{ salt['cmd.run']('vault version') }}",
          "initialized": false,
          "sealed": true
        }
    - user: {{ vault_user }}
    - group: {{ vault_group }}
    - mode: 640
    - replace: False
    - require:
      - cmd: vault_wait_ready

# Vault health check script
vault_health_check:
  file.managed:
    - name: /usr/local/bin/vault-health-check.sh
    - contents: |
        #!/bin/bash
        # Vault health check script
        
        VAULT_ADDR="{{ vault.get('api_addr', 'https://localhost:8200') }}"
        export VAULT_ADDR
        
        # Check if Vault is responding
        if ! vault status >/dev/null 2>&1; then
          echo "CRITICAL: Vault is not responding"
          exit 2
        fi
        
        # Get status
        STATUS=$(vault status -format=json 2>/dev/null)
        
        if [ $? -ne 0 ]; then
          echo "WARNING: Unable to get Vault status"
          exit 1
        fi
        
        SEALED=$(echo "$STATUS" | jq -r '.sealed')
        INITIALIZED=$(echo "$STATUS" | jq -r '.initialized')
        
        if [ "$INITIALIZED" = "false" ]; then
          echo "WARNING: Vault is not initialized"
          exit 1
        fi
        
        if [ "$SEALED" = "true" ]; then
          echo "CRITICAL: Vault is sealed"
          exit 2
        fi
        
        echo "OK: Vault is healthy and unsealed"
        exit 0
    - mode: 755
    - require:
      - service: vault_service

# Log rotation configuration
vault_logrotate:
  file.managed:
    - name: /etc/logrotate.d/vault
    - contents: |
        {{ vault.get('log_path', '/var/log/vault') }}/*.log {
            daily
            missingok
            rotate 30
            compress
            delaycompress
            notifempty
            create 644 {{ vault_user }} {{ vault_group }}
            postrotate
                systemctl reload vault
            endscript
        }
    - mode: 644
    - require:
      - service: vault_service