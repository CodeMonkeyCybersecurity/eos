# Volume management for Helen deployments
# Static deployments use bind mounts, Ghost uses persistent volumes

{% set mode = salt['pillar.get']('helen:mode', 'static') %}
{% set environment = salt['pillar.get']('helen:environment', 'production') %}
{% set namespace = salt['pillar.get']('helen:namespace', 'helen') %}

# Base directory structure for all Helen deployments
helen_create_base_directories:
  file.directory:
    - names:
      - /var/lib/helen
      - /var/lib/helen/{{ environment }}
      - /var/lib/helen/{{ environment }}/config
      - /var/lib/helen/{{ environment }}/logs
    - user: helen
    - group: helen
    - mode: 755
    - makedirs: True
    - require:
      - user: helen_user

{% if mode == 'static' %}
# Static mode volume setup

helen_static_content_directory:
  file.directory:
    - name: {{ salt['pillar.get']('helen:html_path', '/var/lib/helen/' ~ environment ~ '/public') }}
    - user: helen
    - group: helen
    - mode: 755
    - makedirs: True
    - require:
      - file: helen_create_base_directories

# Copy static files if repo path is provided
{% if salt['pillar.get']('helen:repo_path') %}
helen_copy_static_content:
  file.recurse:
    - name: {{ salt['pillar.get']('helen:html_path', '/var/lib/helen/' ~ environment ~ '/public') }}
    - source: {{ salt['pillar.get']('helen:repo_path') }}/{{ salt['pillar.get']('helen:static_source_dir', 'public') }}
    - user: helen
    - group: helen
    - file_mode: 644
    - dir_mode: 755
    - clean: {{ salt['pillar.get']('helen:clean_deploy', false) }}
    - require:
      - file: helen_static_content_directory
{% endif %}

# Create Nomad host volume for static content
helen_register_static_volume:
  cmd.run:
    - name: |
        cat > /tmp/helen-static-volume.json <<EOF
        {
          "ID": "helen-static-{{ environment }}",
          "Name": "helen-static-{{ environment }}",
          "Type": "host",
          "Source": "{{ salt['pillar.get']('helen:html_path', '/var/lib/helen/' ~ environment ~ '/public') }}",
          "ReadOnly": true,
          "Config": {
            "uid": "helen",
            "gid": "helen",
            "mode": "0755"
          }
        }
        EOF
        curl -X PUT http://localhost:4646/v1/volume/csi/helen-static-{{ environment }} -d @/tmp/helen-static-volume.json
    - unless: curl -s http://localhost:4646/v1/volume/csi/helen-static-{{ environment }} | grep -q helen-static-{{ environment }}
    - require:
      - file: helen_static_content_directory

{% elif mode == 'ghost' %}
# Ghost mode volume setup with persistent storage

helen_ghost_content_directory:
  file.directory:
    - name: /var/lib/helen/{{ environment }}/ghost-content
    - user: 1000  # Ghost runs as UID 1000
    - group: 1000
    - mode: 755
    - makedirs: True
    - require:
      - file: helen_create_base_directories

helen_ghost_data_directory:
  file.directory:
    - name: /var/lib/helen/{{ environment }}/ghost-data
    - user: 1000
    - group: 1000
    - mode: 755
    - makedirs: True
    - require:
      - file: helen_create_base_directories

# Create subdirectories for Ghost content
helen_ghost_content_subdirs:
  file.directory:
    - names:
      - /var/lib/helen/{{ environment }}/ghost-content/images
      - /var/lib/helen/{{ environment }}/ghost-content/themes
      - /var/lib/helen/{{ environment }}/ghost-content/apps
      - /var/lib/helen/{{ environment }}/ghost-content/data
      - /var/lib/helen/{{ environment }}/ghost-content/logs
      - /var/lib/helen/{{ environment }}/ghost-content/settings
    - user: 1000
    - group: 1000
    - mode: 755
    - makedirs: True
    - require:
      - file: helen_ghost_content_directory

# Create backup directory for Ghost
helen_ghost_backup_directory:
  file.directory:
    - name: /var/lib/helen/{{ environment }}/backups
    - user: helen
    - group: helen
    - mode: 755
    - makedirs: True
    - require:
      - file: helen_create_base_directories

# Copy custom themes if provided in repo
{% if salt['pillar.get']('helen:repo_path') and salt['file.directory_exists'](salt['pillar.get']('helen:repo_path') ~ '/themes') %}
helen_copy_custom_themes:
  file.recurse:
    - name: /var/lib/helen/{{ environment }}/ghost-content/themes
    - source: {{ salt['pillar.get']('helen:repo_path') }}/themes
    - user: 1000
    - group: 1000
    - file_mode: 644
    - dir_mode: 755
    - require:
      - file: helen_ghost_content_subdirs
{% endif %}

# Register Nomad host volumes for Ghost
helen_register_ghost_content_volume:
  cmd.run:
    - name: |
        nomad volume create - <<EOF
        id           = "helen-content-{{ environment }}"
        name         = "helen-content-{{ environment }}"
        type         = "host"
        plugin_id    = "local"
        
        capability {
          access_mode     = "single-node-writer"
          attachment_mode = "file-system"
        }
        
        mount_options {
          mount_flags = ["noatime"]
        }
        
        parameters {
          source = "/var/lib/helen/{{ environment }}/ghost-content"
        }
        EOF
    - unless: nomad volume status helen-content-{{ environment }} 2>/dev/null
    - require:
      - file: helen_ghost_content_subdirs

helen_register_ghost_data_volume:
  cmd.run:
    - name: |
        nomad volume create - <<EOF
        id           = "helen-data-{{ environment }}"
        name         = "helen-data-{{ environment }}"
        type         = "host"
        plugin_id    = "local"
        
        capability {
          access_mode     = "single-node-writer"
          attachment_mode = "file-system"
        }
        
        parameters {
          source = "/var/lib/helen/{{ environment }}/ghost-data"
        }
        EOF
    - unless: nomad volume status helen-data-{{ environment }} 2>/dev/null
    - require:
      - file: helen_ghost_data_directory

# Set up automated backup cron job
{% if salt['pillar.get']('helen:backup:enabled', true) %}
helen_ghost_backup_script:
  file.managed:
    - name: /usr/local/bin/helen-backup-{{ environment }}.sh
    - mode: 755
    - contents: |
        #!/bin/bash
        # Helen Ghost backup script for {{ environment }}
        set -e
        
        BACKUP_DIR="/var/lib/helen/{{ environment }}/backups"
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        BACKUP_NAME="helen-{{ environment }}-${TIMESTAMP}"
        
        echo "Starting backup: ${BACKUP_NAME}"
        
        # Create backup directory
        mkdir -p "${BACKUP_DIR}/${BACKUP_NAME}"
        
        # Backup Ghost content
        tar -czf "${BACKUP_DIR}/${BACKUP_NAME}/content.tar.gz" \
          -C /var/lib/helen/{{ environment }} ghost-content
        
        # Backup database if MySQL
        {% if salt['pillar.get']('helen:database', 'mysql') == 'mysql' %}
        MYSQL_PWD=$(vault kv get -field=password kv/helen/{{ environment }}/database) \
        mysqldump -h mysql.service.consul \
          -u helen_{{ environment }} \
          helen_{{ environment }} | gzip > "${BACKUP_DIR}/${BACKUP_NAME}/database.sql.gz"
        {% endif %}
        
        # Clean up old backups (keep last 7 days)
        find "${BACKUP_DIR}" -name "helen-{{ environment }}-*" -type d -mtime +7 -exec rm -rf {} +
        
        echo "Backup completed: ${BACKUP_NAME}"
    - require:
      - file: helen_ghost_backup_directory

helen_ghost_backup_cron:
  cron.present:
    - name: /usr/local/bin/helen-backup-{{ environment }}.sh
    - user: root
    - minute: 0
    - hour: 3
    - identifier: helen-backup-{{ environment }}
    - require:
      - file: helen_ghost_backup_script
{% endif %}

{% endif %}

# Set proper SELinux contexts if enabled
{% if salt['grains.get']('selinux:enabled', false) %}
helen_selinux_contexts:
  cmd.run:
    - name: |
        semanage fcontext -a -t container_file_t "/var/lib/helen(/.*)?"
        restorecon -Rv /var/lib/helen
    - onlyif: which semanage
{% endif %}