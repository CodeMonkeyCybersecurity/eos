# salt/roles/data.sls
# Configuration for data storage role

# Set role grain
data_role_grain:
  grains.present:
    - name: role
    - value: data

# Data-specific packages
data_packages:
  pkg.installed:
    - pkgs:
      - postgresql-14
      - mysql-server
      - redis-server
      - minio
      - zfsutils-linux

# Data-specific storage configuration
data_storage_config:
  file.managed:
    - name: /etc/eos/role-specific/data.yaml
    - makedirs: True
    - contents: |
        role: data
        storage:
          database_path: /var/lib/postgresql
          backup_path: /mnt/backups
          object_storage: /mnt/minio
          thresholds:
            # Data nodes need strictest thresholds
            warning: 60
            cleanup: 70
            critical: 80
          backup:
            enabled: true
            retention_days: 30

# PostgreSQL configuration
postgresql_config:
  file.managed:
    - name: /etc/postgresql/14/main/postgresql.conf
    - pattern: |
        ^#?shared_buffers.*
    - repl: |
        shared_buffers = 2GB
    - require:
      - pkg: data_packages

postgresql_service:
  service.running:
    - name: postgresql
    - enable: True
    - watch:
      - file: postgresql_config

# Create backup directories
data_backup_directories:
  file.directory:
    - names:
      - /mnt/backups
      - /mnt/backups/postgresql
      - /mnt/backups/mysql
      - /mnt/minio
    - user: root
    - group: root
    - mode: 755
    - makedirs: True

# Backup cron job
data_backup_cron:
  cron.present:
    - name: /usr/local/bin/eos backup create --type=database
    - hour: 3
    - minute: 0