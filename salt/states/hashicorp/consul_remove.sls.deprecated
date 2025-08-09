# Consul Removal via Salt
# Comprehensive idempotent removal with graceful handling
# Supports selective preservation of data, config, and user

{% set keep_data = salt['pillar.get']('consul:keep_data', False) %}
{% set keep_config = salt['pillar.get']('consul:keep_config', False) %}
{% set keep_user = salt['pillar.get']('consul:keep_user', False) %}
{% set force = salt['pillar.get']('consul:force', False) %}
{% set timeout = salt['pillar.get']('consul:timeout', 30) %}

# Pre-removal status check
consul_removal_status:
  cmd.run:
    - name: |
        echo "=== Consul Removal Pre-Check ==="
        echo "Options:"
        echo "  Force: {{ force }}"
        echo "  Keep Data: {{ keep_data }}"
        echo "  Keep Config: {{ keep_config }}"
        echo "  Keep User: {{ keep_user }}"
        echo "  Timeout: {{ timeout }}s"
        echo ""
        
        # Check what exists
        EXISTS=""
        [ -f /usr/bin/consul ] && EXISTS="$EXISTS binary"
        [ -f /usr/local/bin/consul ] && EXISTS="$EXISTS symlink"
        [ -f /etc/systemd/system/consul.service ] && EXISTS="$EXISTS service"
        [ -d /etc/consul.d ] && EXISTS="$EXISTS config"
        [ -d /var/lib/consul ] && EXISTS="$EXISTS data"
        [ -d /var/log/consul ] && EXISTS="$EXISTS logs"
        getent passwd consul >/dev/null 2>&1 && EXISTS="$EXISTS user"
        getent group consul >/dev/null 2>&1 && EXISTS="$EXISTS group"
        
        if [ -z "$EXISTS" ]; then
          echo "Consul is not installed on this system"
          exit 0
        fi
        
        echo "Found Consul components:$EXISTS"
        echo ""
        
        # Check if service is running
        if systemctl is-active consul.service >/dev/null 2>&1; then
          echo "WARNING: Consul service is currently running"
          echo "Will attempt graceful shutdown..."
        fi
        
        # Check for active connections
        if command -v consul >/dev/null 2>&1; then
          if consul members >/dev/null 2>&1; then
            echo "WARNING: Consul cluster has active members:"
            consul members 2>/dev/null || true
          fi
        fi
    - stateful: False

# Step 1: Gracefully leave cluster (if possible)
consul_leave_cluster:
  cmd.run:
    - name: |
        if command -v consul >/dev/null 2>&1 && systemctl is-active consul.service >/dev/null 2>&1; then
          echo "Attempting to leave Consul cluster gracefully..."
          # Use timeout to prevent hanging
          if timeout {{ timeout }} consul leave; then
            echo "Successfully left Consul cluster"
            # Give it a moment to propagate
            sleep 2
          else
            echo "WARNING: Could not leave cluster gracefully (timeout after {{ timeout }}s)"
            echo "Proceeding with forceful removal..."
          fi
        else
          echo "Consul not running or not installed, skipping cluster leave"
        fi
    - require:
      - cmd: consul_removal_status
    - onlyif:
      - fun: cmd.run
        cmd: command -v consul

# Step 2: Stop the service (if it exists)
consul_service_stop:
  service.dead:
    - name: consul
    - enable: False
    - onlyif:
      - fun: service.available
        args:
          - consul
    - require:
      - cmd: consul_leave_cluster

# Wait for service to fully stop
consul_service_wait:
  cmd.run:
    - name: |
        # Wait up to 10 seconds for service to stop
        for i in {1..10}; do
          if ! systemctl is-active consul.service >/dev/null 2>&1; then
            echo "Consul service stopped"
            break
          fi
          echo "Waiting for Consul service to stop... ($i/10)"
          sleep 1
        done
    - require:
      - service: consul_service_stop
    - onlyif:
      - fun: service.available
        args:
          - consul

# Step 3: Kill any remaining consul processes
consul_kill_processes:
  cmd.run:
    - name: |
        PIDS=$(pgrep -x consul || true)
        if [ -n "$PIDS" ]; then
          echo "Found consul processes still running: $PIDS"
          kill $PIDS 2>/dev/null || true
          sleep 2
          # Force kill if still running
          PIDS=$(pgrep -x consul || true)
          if [ -n "$PIDS" ]; then
            echo "Force killing remaining processes: $PIDS"
            kill -9 $PIDS 2>/dev/null || true
          fi
          echo "All consul processes terminated"
        else
          echo "No consul processes found"
        fi
    - require:
      - cmd: consul_service_wait

# Step 4: Remove systemd service files
consul_service_files_remove:
  file.absent:
    - names:
      - /etc/systemd/system/consul.service
      - /lib/systemd/system/consul.service
      - /usr/lib/systemd/system/consul.service
    - require:
      - cmd: consul_kill_processes

# Step 5: Reload systemd after service removal
consul_systemd_reload:
  cmd.run:
    - name: systemctl daemon-reload
    - onchanges:
      - file: consul_service_files_remove

# Step 6: Backup and remove configuration (unless --keep-config)
{% if not keep_config %}
consul_backup_config:
  cmd.run:
    - name: |
        if [ -d /etc/consul.d ] && [ "$(ls -A /etc/consul.d 2>/dev/null)" ]; then
          BACKUP_DIR="/var/backups/consul/config-$(date +%Y%m%d-%H%M%S)"
          mkdir -p "$(dirname "$BACKUP_DIR")"
          if cp -r /etc/consul.d "$BACKUP_DIR"; then
            echo "Configuration backed up to: $BACKUP_DIR"
            # Create a manifest of what was backed up
            find "$BACKUP_DIR" -type f | sort > "$BACKUP_DIR.manifest"
          else
            echo "WARNING: Failed to backup configuration"
          fi
        else
          echo "No configuration to backup"
        fi
    - require:
      - cmd: consul_systemd_reload

consul_remove_config:
  file.absent:
    - names:
      - /etc/consul.d
      - /etc/consul
    - require:
      - cmd: consul_backup_config
{% else %}
consul_keep_config_notice:
  cmd.run:
    - name: |
        echo "Keeping Consul configuration in /etc/consul.d (--keep-config specified)"
        if [ -d /etc/consul.d ]; then
          echo "Configuration files:"
          ls -la /etc/consul.d/ 2>/dev/null || echo "  (empty or inaccessible)"
        fi
    - require:
      - cmd: consul_systemd_reload
{% endif %}

# Step 7: Backup and remove data directory (unless --keep-data)
{% if not keep_data %}
consul_backup_data:
  cmd.run:
    - name: |
        if [ -d /var/lib/consul ] && [ "$(ls -A /var/lib/consul 2>/dev/null)" ]; then
          DATA_SIZE=$(du -sh /var/lib/consul 2>/dev/null | cut -f1 || echo "unknown")
          echo "Consul data directory size: $DATA_SIZE"
          
          {% if not force %}
          # Interactive prompt only if not forcing
          if [ -t 0 ]; then
            read -p "Create backup of Consul data before removal? [Y/n] " -n 1 -r
            echo
          else
            REPLY="Y"
          fi
          {% else %}
          REPLY="Y"  # Always backup when forcing
          {% endif %}
          
          if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
            BACKUP_DIR="/var/backups/consul/data-$(date +%Y%m%d-%H%M%S)"
            mkdir -p "$(dirname "$BACKUP_DIR")"
            echo "Creating backup (this may take a while for large data sets)..."
            if tar -czf "$BACKUP_DIR.tar.gz" -C /var/lib consul 2>/dev/null; then
              echo "Data backed up to: $BACKUP_DIR.tar.gz"
              echo "Backup size: $(du -sh "$BACKUP_DIR.tar.gz" | cut -f1)"
            else
              echo "WARNING: Failed to create backup"
            fi
          else
            echo "Skipping data backup as requested"
          fi
        else
          echo "No data to backup"
        fi
    - require:
      - file: consul_remove_config

consul_remove_data:
  file.absent:
    - name: /var/lib/consul
    - require:
      - cmd: consul_backup_data
{% else %}
consul_keep_data_notice:
  cmd.run:
    - name: |
        echo "Keeping Consul data in /var/lib/consul (--keep-data specified)"
        if [ -d /var/lib/consul ]; then
          DATA_SIZE=$(du -sh /var/lib/consul 2>/dev/null | cut -f1 || echo "unknown")
          echo "Data directory size: $DATA_SIZE"
        fi
    - require:
      - file: consul_remove_config
{% endif %}

# Step 8: Remove logs
consul_remove_logs:
  file.absent:
    - name: /var/log/consul
    - require:
      {% if not keep_data %}
      - file: consul_remove_data
      {% else %}
      - cmd: consul_keep_data_notice
      {% endif %}

# Step 9: Remove Consul binaries
consul_remove_binaries:
  file.absent:
    - names:
      - /usr/bin/consul
      - /usr/local/bin/consul
      - /opt/consul/consul  # Alternative location
    - require:
      - file: consul_remove_logs

# Step 10: Remove the Consul package if installed via package manager
consul_remove_package:
  pkg.removed:
    - name: consul
    - require:
      - file: consul_remove_binaries
    - onlyif:
      - fun: pkg.version
        args:
          - consul

# Step 11: Remove user and group (unless --keep-user)
{% if not keep_user %}
# First remove the user (which usually removes the primary group)
consul_remove_user:
  user.absent:
    - name: consul
    - purge: True
    - force: True
    - require:
      - pkg: consul_remove_package

# Then ensure the group is also removed (in case it wasn't the primary group)
consul_remove_group:
  group.absent:
    - name: consul
    - require:
      - user: consul_remove_user
    - onlyif:
      - fun: cmd.run
        cmd: getent group consul
{% else %}
consul_keep_user_notice:
  cmd.run:
    - name: |
        echo "Keeping Consul user account (--keep-user specified)"
        if id consul >/dev/null 2>&1; then
          echo "User details:"
          id consul
        fi
    - require:
      - pkg: consul_remove_package
{% endif %}

# Step 12: Clean up miscellaneous files and references
consul_cleanup_misc:
  cmd.run:
    - name: |
        echo "Cleaning up miscellaneous Consul artifacts..."
        
        # Remove any consul-related temp files
        rm -f /tmp/consul* /var/tmp/consul* 2>/dev/null || true
        
        # Remove consul from PATH if it was added
        rm -f /etc/profile.d/consul.sh 2>/dev/null || true
        
        # Remove any consul-template files if they exist
        rm -rf /etc/consul-template.d 2>/dev/null || true
        
        # Clean up any consul environment files
        rm -f /etc/default/consul /etc/sysconfig/consul 2>/dev/null || true
        
        # Remove any consul DNS configurations
        if grep -q "consul" /etc/resolv.conf 2>/dev/null; then
          echo "WARNING: Found Consul DNS entries in /etc/resolv.conf"
          echo "Manual cleanup may be required for DNS settings"
        fi
        
        # Check for consul in dnsmasq configs
        if [ -d /etc/dnsmasq.d ]; then
          CONSUL_DNS=$(grep -l "consul" /etc/dnsmasq.d/* 2>/dev/null || true)
          if [ -n "$CONSUL_DNS" ]; then
            echo "WARNING: Found Consul references in dnsmasq configs:"
            echo "$CONSUL_DNS"
          fi
        fi
        
        echo "Miscellaneous cleanup completed"
    - require:
      {% if not keep_user %}
      - group: consul_remove_group
      {% else %}
      - cmd: consul_keep_user_notice
      {% endif %}

# Step 13: Remove HashiCorp repository if no other HashiCorp products are installed
{% set hashicorp_products = ['vault', 'nomad', 'terraform', 'packer', 'vagrant', 'boundary', 'waypoint'] %}
{% set other_products = [] %}
{% for product in hashicorp_products %}
  {% if salt['pkg.version'](product) %}
    {% do other_products.append(product) %}
  {% endif %}
{% endfor %}

{% if not other_products %}
consul_remove_hashicorp_repo:
  pkgrepo.absent:
    - name: deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com {{ grains['oscodename'] }} main
    - require:
      - cmd: consul_cleanup_misc

consul_remove_hashicorp_gpg:
  file.absent:
    - name: /usr/share/keyrings/hashicorp-archive-keyring.gpg
    - require:
      - pkgrepo: consul_remove_hashicorp_repo
{% else %}
consul_keep_hashicorp_repo:
  cmd.run:
    - name: |
        echo "Keeping HashiCorp repository (other products installed: {{ other_products|join(', ') }})"
    - require:
      - cmd: consul_cleanup_misc
{% endif %}

# Final verification and summary
consul_removal_verify:
  cmd.run:
    - name: |
        echo ""
        echo "=== Consul Removal Summary ==="
        
        # Check what remains
        REMAINING=""
        [ -f /usr/bin/consul ] && REMAINING="$REMAINING binary"
        [ -f /usr/local/bin/consul ] && REMAINING="$REMAINING symlink"
        [ -f /etc/systemd/system/consul.service ] && REMAINING="$REMAINING service"
        [ -d /etc/consul.d ] && REMAINING="$REMAINING config"
        [ -d /var/lib/consul ] && REMAINING="$REMAINING data"
        [ -d /var/log/consul ] && REMAINING="$REMAINING logs"
        getent passwd consul >/dev/null 2>&1 && REMAINING="$REMAINING user"
        getent group consul >/dev/null 2>&1 && REMAINING="$REMAINING group"
        pgrep -x consul >/dev/null 2>&1 && REMAINING="$REMAINING processes"
        
        if [ -z "$REMAINING" ]; then
          echo "✓ All Consul components successfully removed"
        else
          echo "⚠ The following components remain:$REMAINING"
          {% if keep_data or keep_config or keep_user %}
          echo "  (This is expected based on your --keep flags)"
          {% else %}
          echo "  (Manual intervention may be required)"
          {% endif %}
        fi
        
        # Check for backups
        if [ -d /var/backups/consul ]; then
          echo ""
          echo "Backups created during removal:"
          find /var/backups/consul -type f -name "*.tar.gz" -o -name "*.manifest" | sort
        fi
        
        # Provide next steps
        echo ""
        echo "Next steps:"
        {% if keep_data %}
        echo "- Consul data preserved in /var/lib/consul"
        echo "  To remove later: sudo rm -rf /var/lib/consul"
        {% endif %}
        {% if keep_config %}
        echo "- Consul config preserved in /etc/consul.d"
        echo "  To remove later: sudo rm -rf /etc/consul.d"
        {% endif %}
        {% if keep_user %}
        echo "- Consul user account preserved"
        echo "  To remove later: sudo userdel -r consul"
        {% endif %}
        echo "- You can now safely reinstall Consul with 'eos create consul'"
        
        # Final process check
        if pgrep -x consul >/dev/null 2>&1; then
          echo ""
          echo "WARNING: Consul processes are still running!"
          echo "This should not happen. Please check manually:"
          echo "  ps aux | grep consul"
        fi
    - require:
      {% if not other_products %}
      - file: consul_remove_hashicorp_gpg
      {% else %}
      - cmd: consul_keep_hashicorp_repo
      {% endif %}