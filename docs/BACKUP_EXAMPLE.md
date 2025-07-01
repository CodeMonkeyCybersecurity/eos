# Improved Eos Backup System - Usage Examples

## Key Improvements Demonstrated

### 1. CRUD-Based Architecture
```bash
# Create a repository
eos backup create repository local --backend local --path /var/lib/eos/backups

# Create a backup profile
eos backup create profile system \
  --repo local \
  --paths "/etc,/var,/opt" \
  --exclude "*.tmp,*.cache" \
  --retention-daily 7 \
  --retention-weekly 4

# Read configuration
eos backup read repository local
eos backup read profile system

# Update/run backups
eos backup update run system

# List resources
eos backup list repositories
eos backup list profiles
eos backup list snapshots

# Delete/prune
eos backup delete snapshot abc123
eos backup delete prune --profile system
```

### 2. Vault Integration for Security
```bash
# Passwords automatically stored in Vault at:
# eos/backup/repositories/{repo-name}

# Automatic fallback to local storage if Vault unavailable:
# /var/lib/eos/secrets/backup/{repo-name}.password
```

### 3. Multiple Backend Support
```bash
# Local filesystem
eos backup create repository local --backend local --path /backups

# SFTP/SSH
eos backup create repository remote \
  --backend sftp \
  --url "sftp:user@backup.example.com:/backups"

# Amazon S3
eos backup create repository s3 \
  --backend s3 \
  --url "s3:s3.amazonaws.com/mybucket" \
  --env "AWS_ACCESS_KEY_ID=key,AWS_SECRET_ACCESS_KEY=secret"

# Backblaze B2
eos backup create repository b2 \
  --backend b2 \
  --url "b2:mybucket" \
  --env "B2_ACCOUNT_ID=id,B2_ACCOUNT_KEY=key"
```

### 4. Backup Profiles with Rich Configuration
```yaml
# /etc/eos/backup.yaml
default_repository: local

repositories:
  local:
    name: local
    backend: local
    url: /var/lib/eos/backups
  remote:
    name: remote
    backend: sftp
    url: sftp:backup@backup.example.com:/srv/restic-repos
    environment:
      RESTIC_HOST: backup.example.com

profiles:
  system:
    name: system
    description: System configuration backup
    repository: local
    paths:
      - /etc
      - /var/lib/eos
      - /opt/eos
    excludes:
      - "*.tmp"
      - "*.cache"
      - "/etc/ssl/private"
    tags:
      - system
      - production
    retention:
      keep_last: 7
      keep_daily: 7
      keep_weekly: 4
      keep_monthly: 12
    schedule:
      cron: "0 2 * * *"  # Daily at 2 AM
    hooks:
      pre_backup:
        - "/usr/local/bin/pre-backup-system.sh"
      post_backup:
        - "/usr/local/bin/post-backup-system.sh"
```

### 5. Automated Scheduling
```bash
# Enable scheduled backups with systemd
eos backup schedule enable system

# Check status
eos backup schedule status

# Run immediately
eos backup schedule run system

# Disable scheduling
eos backup schedule disable system
```

### 6. Comprehensive Restore Operations
```bash
# Restore entire snapshot to original location (requires --force)
eos backup restore latest --force

# Restore to specific directory
eos backup restore abc123def --target /tmp/restore

# Restore specific paths only
eos backup restore latest \
  --include "/etc,/var/lib" \
  --target /tmp/restore

# Restore from specific repository
eos backup restore latest \
  --repo remote \
  --target /tmp/restore \
  --verify
```

### 7. Backup Verification and Testing
```bash
# Verify repository integrity
eos backup verify repository --repo local

# Verify with data checking (slower but thorough)
eos backup verify repository --repo local --read-data

# Verify specific snapshot
eos backup verify snapshot abc123def

# Check subset of data (faster)
eos backup verify repository --read-data-subset "1/5"
```

### 8. Advanced Management
```bash
# Prune old backups using profile retention policy
eos backup delete prune --profile system

# Prune with custom retention
eos backup delete prune \
  --repo local \
  --keep-last 5 \
  --keep-daily 7 \
  --keep-weekly 4

# Dry run to see what would be deleted
eos backup delete prune --profile system --dry-run

# Update profile configuration
eos backup update profile system \
  --add-paths "/srv" \
  --add-excludes "*.log" \
  --schedule "0 3 * * *"
```

## Key Architecture Benefits

1. **Security First**: Vault integration with secure fallbacks
2. **CRUD Consistency**: Predictable command patterns across all operations
3. **Structured Logging**: Complete visibility into all operations for debugging
4. **Restic Core**: Thin wrapper preserving restic's power while adding Eos patterns
5. **Configuration Management**: YAML-based config with validation
6. **Automation Ready**: Systemd timer integration for scheduling
7. **Multiple Backends**: Support for all major storage providers
8. **Operational Excellence**: Verification, testing, and disaster recovery ready

## Migration from Current Implementation

The improved system maintains backward compatibility while adding powerful new features:

1. Existing restic repositories can be imported
2. Current backup paths are preserved in default profiles
3. Vault integration is optional with local fallbacks
4. Enhanced logging provides better troubleshooting than current fmt.Print statements
5. CRUD architecture makes operations more predictable and scriptable