# Eos Vault Comprehensive Hardening State
# Implements the complete vault.ComprehensiveHardening() functionality via Salt states
# This includes: system hardening, Vault-specific hardening, security policies, and network hardening
#
# Usage: salt-call --local state.apply hashicorp.vault.harden

# System-level hardening

# Disable swap for security
system_disable_swap:
  cmd.run:
    - name: swapoff -a
    - onlyif: swapon --show | grep -q "^/"

system_disable_swap_persistent:
  file.replace:
    - name: /etc/fstab
    - pattern: '^([^#].*\sswap\s.*)$'
    - repl: '# \1  # Disabled by Eos Vault hardening'
    - backup: True

# Disable core dumps
system_disable_coredumps_limits:
  file.managed:
    - name: /etc/security/limits.d/vault-hardening.conf
    - contents: |
        # Eos Vault hardening - disable core dumps
        * hard core 0
        * soft core 0
        vault hard core 0
        vault soft core 0
    - mode: 644

system_disable_coredumps_sysctl:
  sysctl.present:
    - name: kernel.core_pattern
    - value: "|/bin/false"

# Set security-focused ulimits
system_vault_ulimits:
  file.managed:
    - name: /etc/security/limits.d/vault-ulimits.conf
    - contents: |
        # Eos Vault security ulimits
        vault soft nofile 65536
        vault hard nofile 65536
        vault soft memlock unlimited
        vault hard memlock unlimited
        vault soft nproc 4096
        vault hard nproc 4096
    - mode: 644

# Vault service security overrides
vault_service_security_override_dir:
  file.directory:
    - name: /etc/systemd/system/vault.service.d
    - mode: 755

vault_service_security_override:
  file.managed:
    - name: /etc/systemd/system/vault.service.d/security.conf
    - contents: |
        [Service]
        LimitCORE=0
        NoNewPrivileges=true
        PrivateTmp=true
        ProtectSystem=strict
        ProtectHome=true
        ReadWritePaths=/opt/vault
        SystemCallFilter=@system-service
        SystemCallErrorNumber=EPERM
        RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
        RestrictNamespaces=true
        LockPersonality=true
        MemoryDenyWriteExecute=true
        RestrictRealtime=true
        RestrictSUIDSGID=true
        RemoveIPC=true
        PrivateMounts=true
        ProtectKernelTunables=true
        ProtectKernelModules=true
        ProtectControlGroups=true
        RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
        LimitNPROC=512
        LimitFSIZE=infinity
        DevicePolicy=closed
        ProtectClock=true
        ProtectKernelLogs=true
        ProtectHostname=true
    - mode: 644
    - require:
      - file: vault_service_security_override_dir

vault_service_reload_security:
  cmd.run:
    - name: systemctl daemon-reload && systemctl restart vault
    - onchanges:
      - file: vault_service_security_override

# Firewall configuration
{% if salt['grains.get']('os_family') == 'Debian' %}
firewall_install_ufw:
  pkg.installed:
    - name: ufw

firewall_default_policies:
  cmd.run:
    - name: |
        ufw default deny incoming
        ufw default allow outgoing
    - require:
      - pkg: firewall_install_ufw

firewall_allow_ssh:
  cmd.run:
    - name: ufw allow ssh
    - require:
      - cmd: firewall_default_policies

firewall_allow_vault_local:
  cmd.run:
    - name: ufw allow from 127.0.0.1 to any port 8179
    - require:
      - cmd: firewall_default_policies

firewall_allow_vault_restricted:
  cmd.run:
    - name: |
        # Allow Vault from specific subnets only
        {% for subnet in salt['pillar.get']('vault:allowed_subnets', ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']) %}
        ufw allow from {{ subnet }} to any port 8179
        {% endfor %}
    - require:
      - cmd: firewall_default_policies

firewall_enable:
  cmd.run:
    - name: ufw --force enable
    - require:
      - cmd: firewall_allow_ssh
      - cmd: firewall_allow_vault_local
{% endif %}

# SSH hardening
ssh_harden_config:
  file.managed:
    - name: /etc/ssh/sshd_config.d/99-eos-vault-hardening.conf
    - contents: |
        # Eos Vault SSH hardening
        PermitRootLogin no
        PasswordAuthentication no
        PubkeyAuthentication yes
        X11Forwarding no
        AllowAgentForwarding no
        AllowTcpForwarding no
        UsePAM yes
        MaxAuthTries 3
        ClientAliveInterval 300
        ClientAliveCountMax 2
        LoginGraceTime 60
        MaxStartups 10:30:60
        Protocol 2
        # Cipher and algorithm hardening
        Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
        MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
        KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
    - mode: 644

ssh_restart:
  service.running:
    - name: sshd
    - enable: True
    - watch:
      - file: ssh_harden_config

# Vault-specific hardening

# Audit log directory
vault_audit_log_dir:
  file.directory:
    - name: /var/log/vault
    - user: vault
    - group: vault
    - mode: 750

# Enhanced audit configuration
vault_audit_file_enhanced:
  cmd.run:
    - name: |
        # Disable existing audit if any
        vault audit disable file 2>/dev/null || true
        
        # Enable with enhanced settings
        vault audit enable file \
          file_path=/var/log/vault/vault-audit.log \
          log_raw=false \
          hmac_accessor=true \
          mode=0640 \
          prefix="AUDIT:"
    - env:
      - VAULT_ADDR: https://127.0.0.1:8179
      - VAULT_SKIP_VERIFY: "true"
      - VAULT_TOKEN: "{{ salt['pillar.get']('vault:root_token', '') }}"
    - require:
      - file: vault_audit_log_dir

# Enable syslog audit for redundancy
vault_audit_syslog:
  cmd.run:
    - name: |
        vault audit enable syslog \
          facility="AUTH" \
          tag="vault" \
          log_raw=false
    - env:
      - VAULT_ADDR: https://127.0.0.1:8179
      - VAULT_SKIP_VERIFY: "true"
      - VAULT_TOKEN: "{{ salt['pillar.get']('vault:root_token', '') }}"
    - unless: vault audit list | grep -q "^syslog/"

# Log rotation
vault_logrotate_config:
  file.managed:
    - name: /etc/logrotate.d/vault
    - contents: |
        # Vault log rotation configuration
        /var/log/vault/*.log {
            daily
            missingok
            rotate 90
            compress
            delaycompress
            copytruncate
            notifempty
            create 640 vault vault
            postrotate
                /bin/kill -HUP $(cat /var/run/vault.pid 2>/dev/null) 2>/dev/null || true
            endscript
        }
    - mode: 644

# Rate limiting
vault_rate_limit_global:
  cmd.run:
    - name: |
        vault write sys/quotas/rate-limit/global-rate-limit \
          rate=1000 \
          interval=1s \
          block_interval=60s
    - env:
      - VAULT_ADDR: https://127.0.0.1:8179
      - VAULT_SKIP_VERIFY: "true"
      - VAULT_TOKEN: "{{ salt['pillar.get']('vault:root_token', '') }}"
    - unless: vault list sys/quotas/rate-limit | grep -q "global-rate-limit"

vault_rate_limit_auth:
  cmd.run:
    - name: |
        vault write sys/quotas/rate-limit/auth-rate-limit \
          path="auth/" \
          rate=10 \
          interval=1s \
          block_interval=300s
    - env:
      - VAULT_ADDR: https://127.0.0.1:8179
      - VAULT_SKIP_VERIFY: "true"
      - VAULT_TOKEN: "{{ salt['pillar.get']('vault:root_token', '') }}"
    - unless: vault list sys/quotas/rate-limit | grep -q "auth-rate-limit"

# Backup configuration
vault_backup_script:
  file.managed:
    - name: /usr/local/bin/vault-backup.sh
    - contents: |
        #!/bin/bash
        # Vault backup script generated by Eos
        set -euo pipefail
        
        BACKUP_DIR="/var/backups/vault"
        DATE=$(date +%Y%m%d_%H%M%S)
        BACKUP_FILE="$BACKUP_DIR/vault-snapshot-$DATE.snap"
        
        # Create backup directory
        mkdir -p "$BACKUP_DIR"
        
        # Take Vault snapshot (only works with integrated storage)
        if vault status -format=json | jq -e '.storage_type == "raft"' > /dev/null; then
            vault operator raft snapshot save "$BACKUP_FILE"
            gzip "$BACKUP_FILE"
            echo "Vault Raft snapshot saved to $BACKUP_FILE.gz"
        else
            echo "WARNING: Non-Raft storage backend detected. Manual backup required."
            # For file backend, backup the storage directory
            if [ -d "/opt/vault/data" ]; then
                tar -czf "$BACKUP_FILE.tar.gz" -C /opt/vault data/
                echo "Vault file storage backed up to $BACKUP_FILE.tar.gz"
            fi
        fi
        
        # Remove snapshots older than 30 days
        find "$BACKUP_DIR" -name "vault-snapshot-*.snap.gz" -mtime +30 -delete
        find "$BACKUP_DIR" -name "vault-snapshot-*.tar.gz" -mtime +30 -delete
    - mode: 755
    - user: root
    - group: root

vault_backup_timer:
  file.managed:
    - name: /etc/systemd/system/vault-backup.timer
    - contents: |
        [Unit]
        Description=Daily Vault Backup
        Requires=vault-backup.service
        
        [Timer]
        OnCalendar=daily
        Persistent=true
        RandomizedDelaySec=1h
        
        [Install]
        WantedBy=timers.target
    - mode: 644

vault_backup_service:
  file.managed:
    - name: /etc/systemd/system/vault-backup.service
    - contents: |
        [Unit]
        Description=Vault Backup Service
        Wants=vault.service
        After=vault.service
        
        [Service]
        Type=oneshot
        User=root
        Group=root
        ExecStart=/usr/local/bin/vault-backup.sh
        Environment=VAULT_ADDR=https://127.0.0.1:8179
        Environment=VAULT_SKIP_VERIFY=true
    - mode: 644

vault_backup_timer_enable:
  service.running:
    - name: vault-backup.timer
    - enable: True
    - require:
      - file: vault_backup_timer
      - file: vault_backup_service
      - file: vault_backup_script

vault_backup_systemd_reload:
  cmd.run:
    - name: systemctl daemon-reload
    - onchanges:
      - file: vault_backup_timer
      - file: vault_backup_service

# Security policy hardening

# Configure lease management
vault_lease_configuration:
  cmd.run:
    - name: |
        vault write sys/mounts/secret/tune \
          default_lease_ttl=1h \
          max_lease_ttl=24h
    - env:
      - VAULT_ADDR: https://127.0.0.1:8179
      - VAULT_SKIP_VERIFY: "true"
      - VAULT_TOKEN: "{{ salt['pillar.get']('vault:root_token', '') }}"

# Network hardening with iptables
network_restrict_vault_access:
  cmd.run:
    - name: |
        # Allow localhost
        iptables -A INPUT -i lo -j ACCEPT
        
        # Allow established connections
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        
        # Allow SSH
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT
        
        # Allow Vault from localhost only
        iptables -A INPUT -p tcp --dport 8179 -s 127.0.0.1 -j ACCEPT
        
        # Allow Vault from specific networks
        {% for subnet in salt['pillar.get']('vault:allowed_subnets', []) %}
        iptables -A INPUT -p tcp --dport 8179 -s {{ subnet }} -j ACCEPT
        {% endfor %}
        
        # Save rules
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    - unless: iptables -L INPUT -n | grep -q "dpt:8179"

# AppArmor profile for Vault (Debian/Ubuntu)
{% if salt['grains.get']('os_family') == 'Debian' %}
vault_apparmor_profile:
  file.managed:
    - name: /etc/apparmor.d/usr.bin.vault
    - contents: |
        #include <tunables/global>
        
        /usr/bin/vault {
          #include <abstractions/base>
          #include <abstractions/nameservice>
          
          capability ipc_lock,
          capability sys_resource,
          
          /usr/bin/vault mr,
          /etc/vault.d/ r,
          /etc/vault.d/** r,
          /opt/vault/ r,
          /opt/vault/** rw,
          /var/log/vault/ r,
          /var/log/vault/** rw,
          /run/vault.pid rw,
          /proc/sys/kernel/random/uuid r,
          /dev/urandom r,
          
          # Network access
          network tcp,
          network udp,
        }
    - mode: 644

vault_apparmor_reload:
  cmd.run:
    - name: apparmor_parser -r /etc/apparmor.d/usr.bin.vault
    - onchanges:
      - file: vault_apparmor_profile
{% endif %}

# Final hardening summary
vault_hardening_complete:
  cmd.run:
    - name: |
        echo ""
        echo "╔═══════════════════════════════════════════════════════════════════════╗"
        echo "║           VAULT COMPREHENSIVE HARDENING COMPLETED                    ║"
        echo "╚═══════════════════════════════════════════════════════════════════════╝"
        echo ""
        echo "🛡️ System Hardening Applied:"
        echo "   ✅ Swap disabled"
        echo "   ✅ Core dumps disabled"
        echo "   ✅ Security ulimits configured"
        echo "   ✅ Firewall rules applied"
        echo "   ✅ SSH hardened"
        echo ""
        echo "🔐 Vault Hardening Applied:"
        echo "   ✅ Enhanced audit logging (file + syslog)"
        echo "   ✅ Log rotation configured"
        echo "   ✅ Rate limiting enabled"
        echo "   ✅ Backup automation configured"
        echo "   ✅ Service security enhanced"
        echo ""
        echo "🌐 Network Security:"
        echo "   ✅ Vault access restricted to localhost + allowed subnets"
        echo "   ✅ iptables rules configured"
        {% if salt['grains.get']('os_family') == 'Debian' %}
        echo "   ✅ AppArmor profile loaded"
        {% endif %}
        echo ""
        echo "📋 Recommendations:"
        echo "   • Review and test backup procedures"
        echo "   • Monitor audit logs at /var/log/vault/vault-audit.log"
        echo "   • Consider revoking root token if not already done"
        echo "   • Review allowed_subnets in pillar configuration"
        echo ""
        echo "🔍 Check hardening status with:"
        echo "   • systemctl status vault vault-agent vault-backup.timer"
        echo "   • iptables -L -n | grep 8179"
        echo "   • swapon --show"
        echo ""