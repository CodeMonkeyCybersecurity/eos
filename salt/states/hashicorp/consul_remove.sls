# Consul Removal via Salt
# Completely removes HashiCorp Consul and all associated data

# Stop and disable Consul service first
consul_service_stopped:
  service.dead:
    - name: consul
    - enable: False

# Kill any remaining consul processes
consul_processes_killed:
  cmd.run:
    - name: pkill -f consul || true
    - require:
      - service: consul_service_stopped

# Remove Consul package
consul_package_removed:
  pkg.removed:
    - name: consul
    - require:
      - cmd: consul_processes_killed

# Remove Consul binary files
consul_binaries_removed:
  file.absent:
    - names:
      - /usr/bin/consul
      - /usr/local/bin/consul
    - require:
      - pkg: consul_package_removed

# Remove all Consul configuration files
consul_config_removed:
  file.absent:
    - names:
      - /etc/consul.d
      - /etc/consul
    - require:
      - service: consul_service_stopped

# Remove Consul data directory
consul_data_removed:
  file.absent:
    - name: /var/lib/consul
    - require:
      - service: consul_service_stopped

# Remove Consul log directory
consul_logs_removed:
  file.absent:
    - name: /var/log/consul
    - require:
      - service: consul_service_stopped

# Remove any additional Consul directories
consul_opt_removed:
  file.absent:
    - name: /opt/consul
    - require:
      - service: consul_service_stopped

# Remove systemd service file
consul_systemd_service_removed:
  file.absent:
    - names:
      - /etc/systemd/system/consul.service
      - /lib/systemd/system/consul.service
    - require:
      - service: consul_service_stopped

# Reload systemd after removing service file
consul_systemd_reload:
  cmd.run:
    - name: systemctl daemon-reload
    - onchanges:
      - file: consul_systemd_service_removed

# Remove Consul user
consul_user_removed:
  user.absent:
    - name: consul
    - purge: True
    - force: True
    - require:
      - service: consul_service_stopped
      - file: consul_data_removed
      - file: consul_config_removed

# Remove Consul group (if it still exists after user removal)
consul_group_removed:
  group.absent:
    - name: consul
    - require:
      - user: consul_user_removed

# Clean up any consul-related files in root home
consul_root_cleanup:
  file.absent:
    - names:
      - /root/.consul
      - /root/.consul.d
    - require:
      - pkg: consul_package_removed

# Remove HashiCorp repository if no other HashiCorp products are installed
{% set hashicorp_products = ['vault', 'nomad', 'terraform', 'packer', 'vagrant', 'boundary', 'waypoint'] %}
{% set other_products_installed = [] %}
{% for product in hashicorp_products %}
  {% if salt['pkg.version'](product) %}
    {% do other_products_installed.append(product) %}
  {% endif %}
{% endfor %}

{% if not other_products_installed %}
# Remove HashiCorp repository since no other products are installed
hashicorp_repo_removed:
  pkgrepo.absent:
    - name: deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com {{ grains['oscodename'] }} main
    - require:
      - pkg: consul_package_removed

# Remove HashiCorp GPG key
hashicorp_gpg_removed:
  file.absent:
    - name: /usr/share/keyrings/hashicorp-archive-keyring.gpg
    - require:
      - pkgrepo: hashicorp_repo_removed
{% endif %}

# Final verification
consul_removal_verify:
  cmd.run:
    - name: |
        echo "=== Consul Removal Verification ==="
        if command -v consul >/dev/null 2>&1; then
          echo "WARNING: Consul binary still found in PATH"
          exit 1
        fi
        if [ -d "/etc/consul.d" ] || [ -d "/var/lib/consul" ]; then
          echo "WARNING: Consul directories still exist"
          exit 1
        fi
        if id consul >/dev/null 2>&1; then
          echo "WARNING: Consul user still exists"
          exit 1
        fi
        echo "Consul has been successfully removed from the system"
    - require:
      - file: consul_binaries_removed
      - file: consul_config_removed
      - file: consul_data_removed
      - file: consul_logs_removed
      - user: consul_user_removed
      - group: consul_group_removed