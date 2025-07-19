# EOS Storage Operations Guide

This guide provides comprehensive documentation for managing storage across our Ubuntu fleet infrastructure. It covers filesystem selection, container storage patterns, backup strategies, and automatic scaling based on environment size.


## CLI Command Structure
```
# Main storage operations commands
eos storage analyze                    # Analyze current storage state
eos storage monitor                    # Start monitoring daemon
eos storage cleanup [--level=compress|aggressive|emergency]
eos storage provision                  # Provision new storage
eos storage emergency                  # Emergency recovery mode

# Environment-aware commands
eos storage detect-env                 # Detect environment size/roles
eos storage apply-role [role]          # Apply specific role configuration
eos storage scale                      # Scale storage based on environment

# Backup operations
eos backup create [--type=full|incremental]
eos backup restore [snapshot-id]
eos backup list
eos backup verify

# Filesystem operations
eos storage fs recommend [workload]    # Recommend filesystem
eos storage fs optimize [path]         # Apply optimizations
eos storage fs convert [from] [to]     # Convert filesystem

# Container-specific
eos storage docker cleanup
eos storage docker limits set
eos storage nomad volumes list
eos storage nomad volumes create

# Salt integration
eos storage salt generate              # Generate Salt states
eos storage salt apply [--test]        # Apply configuration
eos storage salt verify                # Verify configuration
```


## EOS Storage Operations CLI Integration
```
eos/
├── cmd/
│   ├── eos/
│   │   └── main.go                    # Main CLI entry point
│   ├── storage/
│   │   ├── monitor.go                 # Storage monitoring orchestrator
│   │   ├── cleanup.go                 # Cleanup orchestrator
│   │   ├── provision.go               # Storage provisioning orchestrator
│   │   └── emergency.go               # Emergency response orchestrator
│   └── backup/
│       ├── backup.go                  # Backup orchestrator
│       └── restore.go                 # Restore orchestrator
├── pkg/
│   ├── storage/
│   │   ├── analyzer/
│   │   │   ├── analyzer.go            # Storage analysis logic
│   │   │   ├── growth.go              # Growth rate calculations
│   │   │   └── classifier.go          # Data classification
│   │   ├── filesystem/
│   │   │   ├── detector.go            # Filesystem type detection
│   │   │   ├── optimizer.go           # FS-specific optimizations
│   │   │   └── mount.go               # Mount management
│   │   ├── threshold/
│   │   │   ├── manager.go             # Threshold management
│   │   │   ├── actions.go             # Progressive actions
│   │   │   └── rules.go               # Rule definitions
│   │   ├── container/
│   │   │   ├── docker.go              # Docker storage management
│   │   │   ├── nomad.go               # Nomad volume management
│   │   │   └── logs.go                # Container log management
│   │   └── emergency/
│   │       ├── recovery.go            # Emergency recovery functions
│   │       └── diagnostics.go         # System diagnostics
│   ├── backup/
│   │   ├── restic/
│   │   │   ├── client.go              # Restic wrapper
│   │   │   ├── scheduler.go           # Backup scheduling
│   │   │   └── policy.go              # Retention policies
│   │   └── database/
│   │       ├── postgres.go            # PostgreSQL backup
│   │       └── mysql.go               # MySQL backup
│   ├── environment/
│   │   ├── detector.go                # Machine count/role detection
│   │   ├── roles.go                   # Role assignment logic
│   │   └── adaptation.go              # Environment adaptation
│   └── salt/
│       ├── state.go                   # Salt state generator
│       ├── pillar.go                  # Pillar data generator
│       └── executor.go                # Salt command executor
├── internal/
│   ├── config/
│   │   ├── storage.go                 # Storage configuration
│   │   └── thresholds.go              # Threshold configurations
│   └── metrics/
│       ├── collector.go               # Metrics collection
│       └── exporter.go                # Prometheus exporter
└── configs/
    ├── storage-ops.yaml               # Default configuration
    └── thresholds/
        ├── single.yaml                # Single machine thresholds
        ├── small.yaml                 # 2-3 machine thresholds
        └── distributed.yaml           # 4+ machine thresholds
```




## Table of Contents

1. [Overview](./01-overview.md) - Storage philosophy and critical incidents
2. [Filesystem Selection Guide](./02-filesystem-selection.md) - Which filesystem for which workload
3. [Progressive Threshold System](./03-threshold-management.md) - Automated storage management
4. [Container Storage Architecture](./04-container-storage.md) - Docker/Nomad storage patterns
5. [Backup and Recovery](./05-backup-recovery.md) - Restic, database backups, cold storage
6. [Machine Role Assignment](./06-machine-roles.md) - 1-10 machine scaling formula
7. [Performance Benchmarks](./07-performance.md) - Real-world filesystem comparisons
8. [SaltStack Implementation](./08-saltstack-implementation.md) - Automated deployment
9. [Emergency Procedures](./09-emergency-procedures.md) - When things go wrong
10. [Architecture Examples](./10-architecture-examples.md) - Reference implementations

## Quick Start

For immediate implementation on a crashed system:

```bash
# Emergency cleanup (recovers ~130GB)
sudo truncate -s 0 /var/lib/docker/containers/*-json.log
docker system prune -af --volumes
sudo journalctl --vacuum-time=3d
rm -rf ~/Downloads/
```

## Core Principles

1. **Never run production on >70% disk usage**
2. **Separate storage by workload type**
3. **Automate before you need it**
4. **Monitor both capacity and performance**
5. **Test your backups monthly**
```

## eos/docs/storage_ops/01-overview.md

```markdown
# Storage Operations Overview

## The Problem We're Solving

Recent production incidents have shown that disk-full conditions can cause complete system failures. This happened on vhost5 when Grafana logs consumed 55GB in a single file, pushing the system to 87% capacity and causing SSH sessions to hang.

## Core Storage Philosophy

### Data Classification
```
CRITICAL:    Customer data, databases, configs, SSL certs (never delete)
IMPORTANT:   Recent logs (<7 days), app state, backups (compress first)
STANDARD:    Older logs (7-30 days), caches, temp files (delete when needed)
EXPENDABLE:  Ancient logs (>30 days), build artifacts (delete aggressively)
```

### Progressive Response System
- **60%**: Start monitoring and alerting
- **70%**: Begin compression of non-essential data
- **80%**: Delete old compressed files, clean caches
- **85%**: Stop accepting non-critical data
- **90%**: Emergency mode - aggressive cleanup
- **95%**: Prepare for controlled shutdown

## What Is StorageOps?

StorageOps encompasses:
- **Storage Orchestration**: Automating provisioning and management
- **Capacity Planning**: Predicting and managing growth
- **Data Lifecycle Management**: Moving data between tiers
- **Storage Tiering**: Hot/warm/cold data strategies

## Critical Lessons Learned

1. **Container logs can kill systems** - Always set log rotation limits
2. **70% is the new 100%** - Order hardware at 60% usage
3. **Databases need local storage** - CephFS latency kills performance
4. **Compression buys time** - Can save 60%+ on backups
5. **Automation prevents 3am calls** - Set it and forget it
```

## eos/docs/storage_ops/02-filesystem-selection.md

```markdown
# Filesystem Selection Guide

## Quick Decision Matrix

| Workload | Filesystem | Why |
|----------|------------|-----|
| Boot/OS | ext4 | Boring is good for boot |
| Databases | XFS on LVM | Best random I/O performance |
| Container Runtime | ext4 | Simple and reliable |
| Backup Storage | BTRFS | Compression + deduplication |
| Distributed Storage | CephFS | Scalable and shareable |

## Detailed Filesystem Characteristics

### ext4
**Use for**: Boot partitions, general purpose, container runtime
- ✅ Extremely stable and well-understood
- ✅ Good all-around performance
- ✅ Simple recovery procedures
- ❌ No built-in compression/deduplication
- ❌ Limited to 16TB volumes

**Performance**: Baseline for all comparisons

### XFS
**Use for**: Databases, large files, high-performance workloads
- ✅ Excellent parallel I/O performance
- ✅ Handles large files efficiently
- ✅ Stable at high capacity (>80%)
- ❌ Cannot shrink filesystem
- ❌ No snapshots

**Performance**: 
- Sequential reads: 5% faster than ext4
- Random I/O: 8% faster than ext4
- Database workloads: 60% faster than BTRFS

### BTRFS
**Use for**: Backup storage, development environments, container registries
- ✅ Built-in compression (zstd saves 60%+)
- ✅ Instant snapshots
- ✅ Deduplication for similar files
- ❌ Performance degrades over time
- ❌ Complex maintenance requirements
- ❌ Poor database performance

**Performance**:
- Container creation: 5x faster than ext4
- Runtime I/O: 15-60% slower than ext4
- Compression ratio: 2.5-4x for backups

### CephFS
**Use for**: Shared storage, scalable applications, bulk data
- ✅ Distributed and highly available
- ✅ Scales to petabytes
- ✅ Multi-node access
- ❌ 2-3x slower than local storage
- ❌ Requires 60% threshold (rebalancing)
- ❌ Complex setup and maintenance

## Mount Options by Workload

```bash
# Database (XFS)
mount -o noatime,nodiratime,nobarrier /dev/vg/db /mnt/postgres

# Backup Storage (BTRFS)
mount -o compress=zstd:3,noatime,space_cache=v2 /dev/vg/backup /mnt/backup

# Container Runtime (ext4)
mount -o noatime,commit=60 /dev/vg/docker /var/lib/docker

# General Purpose (ext4)
mount -o defaults,noatime /dev/vg/root /
```

## When Facebook's BTRFS Approach Makes Sense

Facebook uses BTRFS because they have:
- Billions of similar files (photos)
- Custom kernel patches
- Dedicated BTRFS team
- Specific deduplication needs

For most organizations, the complexity isn't worth it except for backup storage.
```

## eos/docs/storage_ops/03-threshold-management.md

```markdown
# Progressive Threshold Management

## Threshold Configuration by Environment

### Single Machine (Survival Mode)
```yaml
thresholds:
  warning: 60%
  compression: 70%
  cleanup: 75%     # More aggressive
  degraded: 80%
  emergency: 85%
  critical: 90%
retention:
  logs: 7 days
  backups: 3 days
  cache: 1 day
```

### Two Machines (Basic HA)
```yaml
thresholds:
  warning: 65%
  compression: 75%
  cleanup: 80%
  degraded: 85%
  emergency: 90%
  critical: 95%
retention:
  logs: 14 days
  backups: 7 days
  cache: 3 days
```

### Three+ Machines (Distributed)
```yaml
thresholds:
  warning: 70%
  compression: 80%
  cleanup: 85%
  degraded: 90%
  emergency: 93%
  critical: 95%
retention:
  logs: 30 days
  backups: 30 days
  cache: 7 days
```

## Automated Actions by Threshold

### 60% - Monitoring Phase
```bash
#!/bin/bash
# Alert team, start tracking growth rate
echo "Storage at 60% on $(hostname)" | mail -s "Storage Warning" ops@company.com
# Calculate growth rate
GROWTH=$(df_growth_rate.sh)
echo "Current growth: ${GROWTH}GB/day"
```

### 70% - Compression Phase
```bash
# Compress old logs
find /var/log -name "*.log" -mtime +7 -exec gzip {} \;

# Compress old backups
find /backup -name "*.tar" -mtime +3 -exec xz {} \;

# Enable BTRFS compression if available
btrfs property set /backup compression zstd
```

### 80% - Cleanup Phase
```bash
# Remove compressed files older than retention
find /var/log -name "*.gz" -mtime +30 -delete

# Clean Docker artifacts
docker system prune -af --filter "until=72h"

# Clear package caches
apt-get clean
yum clean all
```

### 85% - Service Degradation
```bash
# Stop non-critical services
systemctl stop jenkins
systemctl stop gitlab-runner

# Reject new uploads
echo "return 507;" > /etc/nginx/conf.d/storage-full.conf
nginx -s reload
```

### 90% - Emergency Mode
```bash
# Aggressive cleanup
find /tmp -type f -atime +1 -delete
find /var/tmp -type f -atime +1 -delete
truncate -s 0 /var/lib/docker/containers/*-json.log

# Stop all non-essential containers
docker stop $(docker ps -q --filter "label=priority=low")
```

## Data Classification Rules

### Never Delete
- `/etc/` - Configuration files
- `/var/lib/mysql/` - Database files
- `/var/lib/postgresql/` - Database files
- `/home/*/Documents/` - User documents
- `*.key`, `*.crt`, `*.pem` - SSL certificates

### Compress First
- `/var/log/*.log` - After 7 days
- `/backup/*.tar` - After 3 days
- `/var/cache/` - If untouched for 30 days

### Delete When Needed
- `/var/log/*.gz` - After retention period
- `/tmp/` - After 24 hours
- `/var/tmp/` - After 7 days
- Docker images - Unused for 72 hours
- Build artifacts - After 30 days

## Monitoring Integration

```yaml
# Prometheus alerts
groups:
  - name: storage
    rules:
      - alert: StorageWarning
        expr: disk_usage_percent > 60
        annotations:
          summary: "Storage at {{ $value }}% on {{ $labels.instance }}"
      
      - alert: StorageCritical
        expr: disk_usage_percent > 80
        annotations:
          summary: "CRITICAL: Storage at {{ $value }}%"
```
```

## eos/docs/storage_ops/04-container-storage.md

```markdown
# Container Storage Architecture

## Three-Layer Storage Model

```
┌─────────────────────────────────────┐
│     Container (Ephemeral)           │
│     - Application code              │
│     - Runtime libraries             │
└─────────────┬───────────────────────┘
              │
┌─────────────▼───────────────────────┐
│     Volume Mount (Persistent)       │
│     - Application data              │
│     - Database files                │
│     - User uploads                  │
└─────────────┬───────────────────────┘
              │
┌─────────────▼───────────────────────┐
│     Storage Backend                 │
│     - Local disk (ext4/XFS)         │
│     - Distributed (CephFS)          │
│     - Object storage (S3)           │
└─────────────────────────────────────┘
```

## Container Storage Patterns

### Ephemeral Containers (Stateless)
```yaml
# Backup job - runs and exits
restic-backup:
  image: restic/restic:latest
  volumes:
    - /mnt/cephfs/data:/source:ro
    - /mnt/cephfs/repo:/repo
  restart: "no"  # Don't restart

# CI/CD runner
gitlab-runner:
  image: gitlab/runner:latest
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock
  restart: "no"
```

### Persistent Applications
```yaml
# Database with specific storage
postgres:
  image: postgres:15
  volumes:
    # Data on fast local storage
    - /mnt/nvme/postgres:/var/lib/postgresql/data
    # WAL on separate disk
    - /mnt/ssd/wal:/var/lib/postgresql/wal
    # Backups to bulk storage
    - /mnt/cephfs/backups:/backups
```

### Log Management (Critical!)
```yaml
# ALWAYS set log limits
services:
  app:
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "3"
        compress: "true"
```

## Storage Driver Selection

### overlay2 (Recommended)
```bash
# /etc/docker/daemon.json
{
  "storage-driver": "overlay2",
  "storage-opts": [
    "overlay2.override_kernel_check=true"
  ]
}
```
- Best balance of performance and stability
- Works on ext4/XFS
- Good for general workloads

### btrfs (Special Cases)
```bash
{
  "storage-driver": "btrfs"
}
```
- Use when you have many similar images
- Requires BTRFS filesystem
- 5x faster container creation
- 15-60% slower runtime performance

## Volume Types and Use Cases

### Named Volumes
```yaml
# Docker manages location
volumes:
  grafana-data:
  postgres-data:

services:
  grafana:
    volumes:
      - grafana-data:/var/lib/grafana
```

### Bind Mounts
```yaml
# You control location
services:
  nextcloud:
    volumes:
      - /mnt/bulk-storage/nextcloud:/var/www/html/data
      - /mnt/fast-ssd/nextcloud-db:/var/lib/mysql
```

### tmpfs Mounts
```yaml
# Memory-only, for sensitive data
services:
  app:
    volumes:
      - type: tmpfs
        target: /tmp
        tmpfs:
          size: 100m
```

## Nomad Volume Configuration

### Static Host Volumes
```hcl
# On Nomad client
client {
  host_volume "postgres-data" {
    path = "/mnt/nvme/postgres"
    read_only = false
  }
}

# In job file
volume "postgres-data" {
  type      = "host"
  source    = "postgres-data"
  read_only = false
}
```

### CSI Volumes (Dynamic)
```hcl
volume "nextcloud-data" {
  type      = "csi"
  plugin_id = "cephfs"
  source    = "nextcloud-vol"
  
  capability {
    access_mode     = "multi-node-multi-writer"
    attachment_mode = "file-system"
  }
}
```

## Best Practices

1. **Always set log rotation limits**
2. **Separate data by performance requirements**
3. **Use named volumes for portability**
4. **Bind mount for specific placement control**
5. **Monitor volume usage separately from host**
6. **Regular cleanup of unused volumes**
7. **Test backup/restore procedures monthly**
```

## eos/docs/storage_ops/05-backup-recovery.md

```markdown
# Backup and Recovery Strategy

## Three-Tier Backup Architecture

### Tier 1: Continuous (Hot Backups)
- **PostgreSQL WAL archiving**: Every transaction
- **CephFS snapshots**: Every 15 minutes
- **Redis AOF**: Continuous append

### Tier 2: Daily (Warm Backups)
- **Database dumps**: 2 AM daily
- **Application data**: Restic to local repository
- **Configuration files**: Git commits

### Tier 3: Weekly (Cold Storage)
- **Full system backups**: Restic to S3
- **Archived to Glacier**: After 90 days
- **Retained**: 2 years minimum

## Database Backup Strategies

### PostgreSQL Production Setup
```yaml
# docker-compose.yml
services:
  postgres:
    image: postgres:15
    volumes:
      - /mnt/nvme/postgres/data:/var/lib/postgresql/data
      - /mnt/ssd/postgres/wal:/var/lib/postgresql/wal
      - /mnt/cephfs/postgres/archive:/archive
    environment:
      POSTGRES_INITDB_WALDIR: /var/lib/postgresql/wal
    command: |
      postgres
      -c wal_level=replica
      -c archive_mode=on
      -c archive_command='test ! -f /archive/%f && cp %p /archive/%f'
      -c max_wal_size=1GB

  # WAL-G for continuous backup
  walg:
    image: walg/walg:latest
    volumes:
      - /mnt/cephfs/postgres/archive:/archive
      - /mnt/cephfs/walg-backups:/backups
    environment:
      WALG_FILE_PREFIX: /backups
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    command: wal-push /archive
```

### Backup Script
```bash
#!/bin/bash
# /usr/local/bin/backup-postgres.sh

set -euo pipefail

BACKUP_DIR="/mnt/cephfs/postgres-backups"
DATE=$(date +%Y%m%d-%H%M%S)
BACKUP_NAME="postgres-${DATE}"

# Create consistent backup point
docker exec postgres psql -c "SELECT pg_start_backup('${BACKUP_NAME}', true);"

# Create LVM snapshot
lvcreate -L 50G -s -n pg-snap-${DATE} /dev/postgres-vg/postgres-data

# Mount and backup
mount -o ro /dev/postgres-vg/pg-snap-${DATE} /mnt/snapshot

# Restic backup
restic backup \
  --tag postgres \
  --tag daily \
  --host $(hostname) \
  /mnt/snapshot

# Cleanup
docker exec postgres psql -c "SELECT pg_stop_backup();"
umount /mnt/snapshot
lvremove -f /dev/postgres-vg/pg-snap-${DATE}

# Also create logical backup
docker exec postgres pg_dumpall | \
  gzip > ${BACKUP_DIR}/logical-${DATE}.sql.gz

# Prune old backups
find ${BACKUP_DIR} -name "*.sql.gz" -mtime +30 -delete
```

## Restic Configuration

### Repository Setup
```bash
# Local repository (fast recovery)
restic init --repo /mnt/backup-btrfs/restic-repo

# S3 repository (disaster recovery)
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
restic init --repo s3:s3.amazonaws.com/backup-bucket
```

### Automated Backup Job
```yaml
# nomad-backup.hcl
job "restic-backup" {
  type = "batch"
  
  periodic {
    cron = "0 3 * * *"  # 3 AM daily
  }
  
  group "backup" {
    task "backup-all" {
      driver = "docker"
      
      config {
        image = "restic/restic:latest"
        volumes = [
          "/mnt/cephfs:/source:ro",
          "/mnt/backup-btrfs/restic-repo:/repo",
          "/mnt/fast-ssd/restic-cache:/cache"
        ]
      }
      
      env {
        RESTIC_REPOSITORY = "/repo"
        RESTIC_PASSWORD = "${RESTIC_PASSWORD}"
        RESTIC_CACHE_DIR = "/cache"
      }
      
      template {
        data = <<EOH
#!/bin/bash
# Backup with exclusions
restic backup \
  --verbose \
  --exclude="*.tmp" \
  --exclude="*/cache/*" \
  --exclude="*.part" \
  --tag="daily" \
  --tag="$(date +%Y-%m-%d)" \
  /source

# Prune old snapshots
restic forget \
  --keep-daily 7 \
  --keep-weekly 4 \
  --keep-monthly 12 \
  --keep-yearly 2 \
  --prune

# Verify integrity
restic check --read-data-subset=1%
EOH
        destination = "local/backup.sh"
        perms = "755"
      }
      
      resources {
        cpu    = 2000
        memory = 4096
      }
    }
  }
}
```

## Recovery Procedures

### Database Recovery
```bash
# Point-in-time recovery
docker run --rm \
  -v /mnt/restore:/var/lib/postgresql/data \
  -v /mnt/cephfs/postgres/archive:/archive \
  -e POSTGRES_PASSWORD=secret \
  postgres:15 \
  postgres -c restore_command='cp /archive/%f %p'

# Logical restore
gunzip < /backups/logical-20240115.sql.gz | \
  docker exec -i postgres psql
```

### File Recovery
```bash
# List snapshots
restic snapshots --repo /mnt/backup-btrfs/restic-repo

# Restore specific files
restic restore latest \
  --repo /mnt/backup-btrfs/restic-repo \
  --target /mnt/restore \
  --include "/source/nextcloud/user/important.doc"

# Full restore
restic restore latest \
  --repo s3:s3.amazonaws.com/backup-bucket \
  --target /mnt/restore
```

## Backup Storage on BTRFS

### Setup for Deduplication
```bash
# Create BTRFS volume optimized for backups
mkfs.btrfs -L backup-volume /dev/sdX
mount -o compress=zstd:3,noatime,space_cache=v2 /dev/sdX /mnt/backup-btrfs

# Create subvolumes
btrfs subvolume create /mnt/backup-btrfs/restic
btrfs subvolume create /mnt/backup-btrfs/postgres
btrfs subvolume create /mnt/backup-btrfs/minio
```

### Monitoring Compression Efficiency
```bash
#!/bin/bash
# /usr/local/bin/backup-stats.sh

echo "=== Backup Storage Efficiency ==="
btrfs filesystem df /mnt/backup-btrfs
echo ""
compsize /mnt/backup-btrfs
echo ""
echo "Top consumers:"
btrfs filesystem du -s /mnt/backup-btrfs/* | sort -h
```

## Testing and Validation

### Monthly Recovery Drill
```bash
#!/bin/bash
# /usr/local/bin/test-recovery.sh

# Test database recovery
TEST_DB="test_recovery_$(date +%Y%m%d)"
docker exec postgres createdb $TEST_DB
restic restore latest --include "*postgres*" --target /tmp/test-restore
# Verify data integrity

# Test file recovery
restic restore latest --tag nextcloud --target /tmp/test-files
# Compare checksums

# Report results
echo "Recovery test completed: $(date)" >> /var/log/recovery-tests.log
```
```

## eos/docs/storage_ops/06-machine-roles.md

```markdown
# Machine Role Assignment Formula

## Scaling Philosophy

- **Odd numbers** introduce new capabilities
- **Even numbers** add redundancy/failover
- **Data gravity** keeps related services together
- **Failure isolation** separates critical paths
- **Resource optimization** avoids competition

## Role Assignments by Machine Count

### 1 Machine - "Monolith Survivor"
```yaml
roles: [everything]
storage_threshold: 75%
services:
  - App + Database (containerized)
  - Nginx reverse proxy
  - Local backups (rotating)
  - Basic monitoring
constraints:
  - Maximum 100 concurrent users
  - No video/image processing
  - Aggressive resource limits
```

### 2 Machines - "Frontend/Backend Split"
```yaml
machine_1:
  role: edge
  services:
    - Nginx/Caddy reverse proxy
    - Static file serving
    - SSL termination
    - Rate limiting / WAF
    - Varnish cache
  storage: 
    - 20% for logs
    - 80% for cache

machine_2:
  role: core
  services:
    - Application servers
    - PostgreSQL/MySQL primary
    - Redis cache
    - Background workers
    - Monitoring stack
    - Backup storage
  storage:
    - 40% for database
    - 40% for backups
    - 20% for applications
```

### 3 Machines - "Data Protection"
```yaml
machine_1: edge (unchanged)
machine_2: 
  role: app
  services:
    - Application servers only
    - Background workers
    - Build runners
    - Stateless services

machine_3:
  role: data
  services:
    - Database primary
    - Redis/Memcached
    - Elasticsearch
    - Backup storage
    - Secrets vault
    - Time-series DB
  storage:
    - Dedicated to persistence
```

### 4 Machines - "Edge Redundancy"
```yaml
machine_1-2: edge cluster (HA pair)
machine_3: app
machine_4: data
benefit: No single point of failure for incoming traffic
```

### 5 Machines - "Message Queue"
```yaml
machine_1-2: edge
machine_3: app
machine_4: data
machine_5:
  role: message
  services:
    - RabbitMQ/Kafka
    - Redis pub/sub
    - Event store
    - Webhook processor
    - Log shipper
```

### 6 Machines - "Data Redundancy"
```yaml
machine_1-2: edge
machine_3: app
machine_4: data primary
machine_5: message
machine_6:
  role: data secondary
  services:
    - Database replica
    - Backup storage primary
    - Analytics DB
    - Reporting services
```

### 7 Machines - "Observability"
```yaml
machine_7:
  role: observe
  services:
    - Prometheus + Grafana
    - ELK/Loki stack
    - Jaeger tracing
    - Uptime monitoring
    - SIEM/Security monitoring
    - Runbook automation
```

### 8-10 Machines - "Full Scale"
```yaml
8_machines:
  add: app secondary (redundancy + batch processing)

9_machines:
  add: specialized compute (GPU/ML/video processing)

10_machines:
  add: message secondary (full HA for all services)
```

## Failure Impact by Scale

| Machines | Failed Component | Business Impact | Recovery Time |
|----------|------------------|-----------------|---------------|
| 1 | Any | Complete outage | Full rebuild |
| 2 | Edge | Service degraded | 5 minutes |
| 2 | Core | Data available only | 30 minutes |
| 3+ | Edge | Transparent failover | 0 minutes |
| 5+ | Message | Async processing delayed | 10 minutes |
| 6+ | Database | Read-only mode | 15 minutes |
| 10 | Any component | No impact | 0 minutes |

## Service Placement Rules

### Never Colocate
```yaml
incompatible:
  - [database_primary, database_replica]  # Split failure domain
  - [elasticsearch, database]             # Memory competition
  - [video_processing, database]          # CPU vs I/O
  - [monitoring, monitored_services]      # Circular dependency
```

### Prefer Together
```yaml
affinity:
  - [app_server, redis_cache]            # Latency sensitive
  - [database, database_backup]          # Bandwidth optimization
  - [log_collector, log_storage]         # Avoid network overhead
```

## Resource Allocation by Role

```python
def allocate_resources(machine_count, role):
    """Resource allocation formula"""
    
    base = {
        'edge': {'cpu': 4, 'ram': 8, 'disk': 100, 'network': '10G'},
        'app': {'cpu': 8, 'ram': 16, 'disk': 200, 'network': '1G'},
        'data': {'cpu': 8, 'ram': 32, 'disk': 1000, 'network': '1G'},
        'message': {'cpu': 4, 'ram': 16, 'disk': 500, 'network': '10G'},
        'observe': {'cpu': 4, 'ram': 16, 'disk': 1000, 'network': '1G'},
        'compute': {'cpu': 16, 'ram': 64, 'disk': 200, 'network': '1G'}
    }
    
    # Scale down for smaller deployments
    if machine_count <= 3:
        multiplier = 2.0  # Overprovisioned
    elif machine_count <= 6:
        multiplier = 1.5  # Comfortable
    else:
        multiplier = 1.0  # Optimal
    
    return scale_resources(base[role], multiplier)
```

## Implementation Example

```bash
#!/bin/bash
# /usr/local/bin/detect-role.sh

MACHINE_COUNT=$(salt '*' test.ping | wc -l)
MACHINE_ID=$(hostname | grep -o '[0-9]*')

case $MACHINE_COUNT in
  1) ROLE="monolith" ;;
  2) [[ $MACHINE_ID == 1 ]] && ROLE="edge" || ROLE="core" ;;
  3) 
    case $MACHINE_ID in
      1) ROLE="edge" ;;
      2) ROLE="app" ;;
      3) ROLE="data" ;;
    esac ;;
  *)
    # Use more complex logic for 4+ machines
    ROLE=$(salt-call pillar.get role)
    ;;
esac

# Apply role-specific configuration
salt-call state.apply storage-ops.roles.${ROLE}
```
```

## eos/docs/storage_ops/07-performance.md

```markdown
# Storage Performance Benchmarks

## Real-World Performance Data

### Container Operations
```
Operation: Creating 100 containers with same base image

ext4 (overlay2):
├── First container: 2.3 seconds
├── Subsequent: 1.8 seconds each
├── Delete: 0.4 seconds
└── Total: ~3 minutes

BTRFS (btrfs driver):
├── First container: 2.1 seconds
├── Subsequent: 0.3 seconds each (6x faster!)
├── Delete: 0.1 seconds
└── Total: ~35 seconds
```

### Database Performance (PostgreSQL pgbench)
```
Transactions Per Second (TPS):

Native (no container):     12,500 TPS
├── ext4 container:        12,200 TPS (2.4% slower)
├── XFS container:         12,400 TPS (0.8% slower)
├── BTRFS container:       10,800 TPS (13.6% slower)
└── BTRFS + nodatacow:     11,900 TPS (4.8% slower)
```

### Random I/O Performance (4K blocks)
```
IOPS Comparison:

XFS:         48,000 IOPS
ext4:        45,000 IOPS  
BTRFS:       38,000 IOPS (15% slower)
BTRFS+nocow: 43,000 IOPS (4% slower)
CephFS:      12,000 IOPS (73% slower - network overhead)
```

### Sequential Performance (1GB file)
```
Read Speed:

XFS:    3,350 MB/s
ext4:   3,200 MB/s
BTRFS:  3,100 MB/s (3% slower)
CephFS: 1,100 MB/s (65% slower - network limited)
```

## Application-Level Impact

### Web Application (NextCloud)
```yaml
page_load_times:
  ext4:
    first_load: 1.23s
    cached: 0.31s
    upload_100mb: 8.2s
  
  btrfs:
    first_load: 1.28s     # +40ms (unnoticeable)
    cached: 0.32s         # +10ms (unnoticeable)
    upload_100mb: 9.1s    # +0.9s (noticeable)
  
  cephfs:
    first_load: 1.45s     # +220ms (noticeable)
    cached: 0.38s         # +70ms (barely noticeable)
    upload_100mb: 11.3s   # +3.1s (very noticeable)
```

### Database Operations
```sql
-- 1 million row table

-- Sequential scan
ext4:  0.823 seconds
xfs:   0.798 seconds (3% faster)
btrfs: 0.841 seconds (2% slower)

-- Random index lookups (1000 queries)
ext4:  0.0012s per query
xfs:   0.0011s per query (8% faster)
btrfs: 0.0019s per query (58% slower!)

-- Bulk insert (100k rows)
ext4:  4.2 seconds
xfs:   3.9 seconds (7% faster)
btrfs: 6.8 seconds (62% slower)
```

## Storage Latency Distribution
```
4KB Random Read Latency (NVMe SSD):

ext4:
├── p50: 0.08ms (80 microseconds)
├── p95: 0.12ms
└── p99: 0.15ms

BTRFS:
├── p50: 0.11ms (110 microseconds)
├── p95: 0.23ms
└── p99: 0.31ms (2x slower at tail)

CephFS:
├── p50: 0.9ms (network RTT included)
├── p95: 2.1ms
└── p99: 5.3ms (35x slower than local)
```

## Compression Impact (BTRFS + zstd)
```
10GB Backup File:

No compression (ext4):
├── Write time: 8.2 seconds (1.22 GB/s)
├── Read time: 3.1 seconds (3.23 GB/s)
└── Space used: 10GB

BTRFS + zstd:3:
├── Write time: 12.4 seconds (0.81 GB/s)
├── Read time: 3.3 seconds (3.03 GB/s)  
└── Space used: 3.8GB (62% saved!)

Verdict: 4 seconds slower write for 6.2GB saved
```

## When Performance Differences Matter

### Critical (User-Facing Impact)
```yaml
database_random_io:
  ext4: 0.1ms latency
  btrfs: 0.2ms latency
  impact: "2x slower queries - unacceptable"
  
high_frequency_trading:
  ext4: 10 microseconds
  btrfs: 25 microseconds
  impact: "Lost competitive advantage"
  
api_response_time:
  local_ssd: 45ms total
  cephfs: 180ms total
  impact: "4x slower - users notice"
```

### Acceptable (Background Tasks)
```yaml
backup_jobs:
  ext4: 20 minutes at 3am
  btrfs: 25 minutes at 3am
  impact: "No one notices"
  
log_rotation:
  ext4: 5 seconds
  btrfs: 7 seconds
  impact: "Happens async anyway"
  
bulk_uploads:
  ext4: 60 seconds
  btrfs: 75 seconds
  impact: "Progress bar keeps user happy"
```

## Performance Tuning Commands

### XFS Optimization
```bash
# For databases
mkfs.xfs -f -d agcount=32 /dev/vg/database
mount -o noatime,nodiratime,nobarrier,logbufs=8 /dev/vg/database /mnt/db

# Check fragmentation
xfs_db -r /dev/vg/database -c frag
```

### ext4 Optimization
```bash
# General purpose
mkfs.ext4 -E lazy_itable_init=0,lazy_journal_init=0 /dev/vg/data
mount -o noatime,commit=60,data=writeback /dev/vg/data /mnt/data

# Large files
tune2fs -o journal_data_writeback /dev/vg/data
```

### BTRFS Optimization
```bash
# For backups
mkfs.btrfs -f -d single -m single /dev/vg/backup
mount -o compress=zstd:3,noatime,space_cache=v2,commit=120 /dev/vg/backup /mnt/backup

# Disable COW for databases
chattr +C /mnt/btrfs/postgres
```

## Decision Matrix

```python
def choose_filesystem_by_workload(workload, performance_critical=False):
    if workload == "database":
        return "XFS"  # Always fastest for random I/O
    
    elif workload == "container_host":
        if container_churn > 100/hour:
            return "BTRFS"  # Creation speed matters
        else:
            return "ext4"  # Runtime performance matters
    
    elif workload == "backup_storage":
        return "BTRFS"  # Compression worth the tradeoff
    
    elif workload == "general_purpose":
        return "ext4"  # Best all-around
    
    elif workload == "distributed":
        if performance_critical:
            avoid("CephFS")  # Too slow
        else:
            return "CephFS"  # Scalability wins
```
```

## eos/docs/storage_ops/08-saltstack-implementation.md

```markdown
# SaltStack Storage Operations Implementation

## Directory Structure
```
salt/
└── storage-ops/
    ├── init.sls              # Main orchestration
    ├── monitor.sls           # Monitoring and thresholds
    ├── classify.sls          # Data classification
    ├── cleanup.sls           # Progressive cleanup
    ├── adapt.sls             # Environment adaptation
    ├── safety.sls            # Safety checks
    ├── notify.sls            # Alerting
    ├── roles/
    │   ├── monolith.sls      # 1 machine config
    │   ├── edge.sls          # Edge role
    │   ├── core.sls          # Core services
    │   ├── data.sls          # Database role
    │   └── message.sls       # Queue role
    └── pillar/
        ├── defaults.sls      # Default thresholds
        ├── overrides.sls     # Environment specific
        └── secrets.sls       # Credentials
```

## Main Orchestration (init.sls)
```yaml
# storage-ops/init.sls

include:
  - .monitor
  - .classify
  - .adapt

# Determine machine count and role
{%- set machine_count = salt['mine.get']('*', 'network.ip_addrs')|length %}
{%- set hostname = grains['host'] %}
{%- set role = salt['pillar.get']('storage:role', 'auto') %}

# Auto-detect role if not specified
{%- if role == 'auto' %}
  {%- if machine_count == 1 %}
    {%- set role = 'monolith' %}
  {%- elif machine_count == 2 %}
    {%- set role = hostname.endswith('1') and 'edge' or 'core' %}
  {%- else %}
    {%- set role = salt['grains.get']('storage_role', 'general') %}
  {%- endif %}
{%- endif %}

# Apply role-specific configuration
storage_role_config:
  salt.state:
    - tgt: {{ grains['id'] }}
    - sls: storage-ops.roles.{{ role }}

# Set up monitoring
storage_monitoring:
  salt.state:
    - tgt: {{ grains['id'] }}
    - sls: storage-ops.monitor
    - require:
      - salt: storage_role_config
```

## Monitoring Module (monitor.sls)
```yaml
# storage-ops/monitor.sls

# Install monitoring tools
monitoring_packages:
  pkg.installed:
    - pkgs:
      - sysstat
      - iotop
      - ncdu
      - prometheus-node-exporter

# Deploy monitoring script
/usr/local/bin/storage-monitor.sh:
  file.managed:
    - source: salt://storage-ops/files/storage-monitor.sh
    - mode: 755
    - contents: |
        #!/bin/bash
        
        # Get current usage
        USAGE=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
        ROOT_FREE=$(df / | tail -1 | awk '{print $4}')
        
        # Get thresholds from pillar
        WARN={{ salt['pillar.get']('storage:thresholds:warning', 60) }}
        COMPRESS={{ salt['pillar.get']('storage:thresholds:compress', 70) }}
        CLEAN={{ salt['pillar.get']('storage:thresholds:cleanup', 80) }}
        CRITICAL={{ salt['pillar.get']('storage:thresholds:critical', 90) }}
        
        # Export metrics
        echo "storage_usage_percent ${USAGE}" > /var/lib/node_exporter/storage.prom
        echo "storage_free_bytes ${ROOT_FREE}000" >> /var/lib/node_exporter/storage.prom
        
        # Trigger actions based on thresholds
        if [ $USAGE -ge $CRITICAL ]; then
            salt-call state.apply storage-ops.cleanup.emergency
        elif [ $USAGE -ge $CLEAN ]; then
            salt-call state.apply storage-ops.cleanup.aggressive  
        elif [ $USAGE -ge $COMPRESS ]; then
            salt-call state.apply storage-ops.cleanup.compress
        elif [ $USAGE -ge $WARN ]; then
            salt-call state.apply storage-ops.notify
        fi

# Cron job for monitoring
storage_monitor_cron:
  cron.present:
    - name: /usr/local/bin/storage-monitor.sh
    - minute: '*/5'
    - identifier: storage-monitor
```

## Data Classification (classify.sls)
```yaml
# storage-ops/classify.sls

# Create classification marker files
{% for category, paths in salt['pillar.get']('storage:classification', {}).items() %}
{% for path in paths %}
{{ path }}/.storage_class:
  file.managed:
    - contents: {{ category }}
    - makedirs: True
{% endfor %}
{% endfor %}

# Default classification rules
/etc/storage-ops/classification.yaml:
  file.managed:
    - makedirs: True
    - contents: |
        critical:
          - /etc
          - /var/lib/mysql
          - /var/lib/postgresql
          - /home/*/Documents
          - "*.key"
          - "*.crt"
          - "*.pem"
        
        important:
          - /var/log/*.log
          - /var/backups
          - /opt/backups
          
        standard:
          - /var/cache
          - /tmp
          - /var/tmp
          
        expendable:
          - "*.tmp"
          - "*.cache"
          - "*.pyc"
          - "__pycache__"
```

## Progressive Cleanup (cleanup.sls)
```yaml
# storage-ops/cleanup/compress.sls

compress_old_logs:
  cmd.run:
    - name: |
        find /var/log -name "*.log" -mtime +7 -size +100M -exec gzip {} \;
        find /var/log -name "*.log.[0-9]" -exec gzip {} \;
    - unless: df / | tail -1 | awk '{print $5}' | sed 's/%//' | test $(cat) -lt 70

# storage-ops/cleanup/aggressive.sls

clean_docker:
  cmd.run:
    - name: |
        docker system prune -af --filter "until=72h"
        docker volume prune -f
        truncate -s 0 /var/lib/docker/containers/*-json.log

clean_package_cache:
  cmd.run:
    - name: |
        apt-get clean
        yum clean all 2>/dev/null || true
        rm -rf /var/cache/apt/archives/*
        
clean_tmp:
  cmd.run:
    - name: |
        find /tmp -type f -atime +1 -delete
        find /var/tmp -type f -atime +7 -delete

# storage-ops/cleanup/emergency.sls

emergency_stop_services:
  service.dead:
    - names:
{%- for service in salt['pillar.get']('storage:emergency:stop_services', []) %}
      - {{ service }}
{%- endfor %}

emergency_clean_all:
  cmd.run:
    - name: |
        # Stop all non-critical containers
        docker stop $(docker ps -q --filter "label=priority=low")
        
        # Aggressive log cleanup  
        find /var/log -name "*.gz" -delete
        journalctl --vacuum-size=100M
        
        # Clear all caches
        rm -rf /var/cache/*
        rm -rf /home/*/.cache
```

## Environment Adaptation (adapt.sls)
```yaml
# storage-ops/adapt.sls

{%- set machine_count = salt['mine.get']('*', 'network.ip_addrs')|length %}

# Set thresholds based on environment size
storage_thresholds:
  grains.present:
    - name: storage_thresholds
    - value:
{%- if machine_count == 1 %}
        warning: 60
        compress: 70  
        cleanup: 75
        degraded: 80
        critical: 85
{%- elif machine_count == 2 %}
        warning: 65
        compress: 75
        cleanup: 80
        degraded: 85
        critical: 90
{%- else %}
        warning: 70
        compress: 80
        cleanup: 85
        degraded: 90
        critical: 95
{%- endif %}

# Configure cross-machine backups for 2+ machines
{%- if machine_count >= 2 %}
setup_cross_backup:
  file.directory:
    - name: /mnt/cross-backup
    - makedirs: True
    
  mount.mounted:
    - name: /mnt/cross-backup
    - device: {{ salt['mine.get']('not ' + grains['id'], 'network.ip_addrs').values()[0][0] }}:/backup
    - fstype: nfs
    - opts: soft,bg,timeo=5
    - require:
      - file: /mnt/cross-backup
{%- endif %}
```

## Pillar Configuration
```yaml
# pillar/storage-ops/defaults.sls

storage:
  role: auto  # auto-detect based on hostname/count
  
  thresholds:
    warning: 60
    compress: 70
    cleanup: 80
    degraded: 85
    critical: 90
    
  retention:
    logs: 30
    backups: 90
    tmp: 7
    
  classification:
    critical:
      - /etc
      - /var/lib/mysql
      - /var/lib/postgresql
      
  emergency:
    stop_services:
      - jenkins
      - gitlab-runner
      - minecraft-server
      
  notify:
    email: ops@company.com
    slack_webhook: https://hooks.slack.com/...
```

## Test Suite
```yaml
# test/storage-ops.sls

test_threshold_detection:
  cmd.run:
    - name: |
        # Simulate high disk usage
        dd if=/dev/zero of=/tmp/test-file bs=1G count=10
        /usr/local/bin/storage-monitor.sh
        # Verify cleanup triggered
        test ! -f /tmp/test-file

test_classification:
  cmd.run:
    - name: |
        # Verify critical paths protected
        touch /etc/test-critical
        salt-call state.apply storage-ops.cleanup.aggressive
        test -f /etc/test-critical
        rm -f /etc/test-critical

test_role_detection:
  cmd.run:
    - name: |
        ROLE=$(salt-call grains.get storage_role --out=txt | cut -d' ' -f2)
        echo "Detected role: $ROLE"
        test -n "$ROLE"
```

## Deployment Commands
```bash
# Initial deployment
salt '*' state.apply storage-ops

# Test on single node
salt 'test-node' state.apply storage-ops test=True

# Force specific role
salt 'node1' state.apply storage-ops pillar='{"storage": {"role": "edge"}}'

# Emergency cleanup
salt '*' state.apply storage-ops.cleanup.emergency

# View current status
salt '*' cmd.run '/usr/local/bin/storage-monitor.sh'
```
```

## eos/docs/storage_ops/09-emergency-procedures.md

```markdown
# Emergency Storage Procedures

## Immediate Actions (System Unresponsive)

### 1. Can't SSH? Use Console
```bash
# From physical/IPMI console
Alt+F2  # Switch to TTY2

# Minimal cleanup to restore access
echo 3 > /proc/sys/vm/drop_caches
killall -9 rsync
rm -rf /tmp/*
```

### 2. Emergency 100GB Recovery
```bash
#!/bin/bash
# RUN THIS FIRST - Recovers ~100GB immediately

# 1. Truncate massive log files (50GB+)
find /var/lib/docker/containers -name "*-json.log" -size +1G -exec truncate -s 0 {} \;

# 2. Nuclear docker cleanup (30GB)
docker stop $(docker ps -aq)
docker system prune -af --volumes

# 3. Clear systemd journals (5GB)
journalctl --vacuum-size=100M

# 4. Remove package cache (5GB)
apt-get clean
yum clean all
rm -rf /var/cache/apt/archives/*

# 5. Clear user downloads (10GB+)
rm -rf /home/*/Downloads/*
rm -rf /home/*/.cache/*
```

### 3. Service-Specific Emergency Actions

#### PostgreSQL Full
```bash
# DO NOT delete database files!
# Instead, move WAL files
mv /var/lib/postgresql/data/pg_wal/*.done /backup/emergency/

# Vacuum database
docker exec postgres psql -c "VACUUM FULL;"

# Drop old tables
docker exec postgres psql -c "DROP TABLE IF EXISTS temp_*;"
```

#### Elasticsearch/ELK Full
```bash
# Delete old indices
curl -X DELETE "localhost:9200/*-$(date -d '30 days ago' +%Y.%m.%d)"

# Force merge
curl -X POST "localhost:9200/_forcemerge?only_expunge_deletes=true"

# Clear cache
curl -X POST "localhost:9200/_cache/clear"
```

#### Nextcloud Full
```bash
# Clear preview cache
rm -rf /var/lib/docker/volumes/nextcloud_data/_data/appdata_*/preview/*

# Empty trash for all users
docker exec -u www-data nextcloud php occ trashbin:cleanup --all-users

# Clear versions
docker exec -u www-data nextcloud php occ versions:cleanup
```

## Diagnostic Commands

### Find Space Hogs
```bash
# Top 20 largest files
find / -xdev -type f -size +100M -exec ls -lh {} \; | sort -k5 -rh | head -20

# Largest directories
du -h / 2>/dev/null | sort -rh | head -20

# Docker specific
docker ps -s  # Container sizes
docker system df  # Overall usage

# Hidden space users
lsof | grep deleted  # Deleted but open files
df -i  # Inode usage
```

### What's Growing?
```bash
#!/bin/bash
# growth-tracker.sh - Run twice, 1 hour apart

SNAPSHOT_FILE="/tmp/disk-snapshot-$(date +%s)"

# First run - create snapshot
if [ ! -f /tmp/disk-snapshot-* ]; then
    find / -xdev -type f -size +10M -printf "%s %p\n" > $SNAPSHOT_FILE
    echo "Snapshot created. Run again in 1 hour."
    exit 0
fi

# Second run - compare
OLD_SNAPSHOT=$(ls -t /tmp/disk-snapshot-* | head -1)
find / -xdev -type f -size +10M -printf "%s %p\n" | while read SIZE FILE; do
    OLD_SIZE=$(grep " $FILE$" $OLD_SNAPSHOT | awk '{print $1}')
    if [ -n "$OLD_SIZE" ]; then
        GROWTH=$((SIZE - OLD_SIZE))
        [ $GROWTH -gt 1048576 ] && echo "$GROWTH $FILE"
    fi
done | sort -rn | head -20
```

## Recovery Procedures

### Accidentally Deleted Important Data
```bash
# 1. STOP all writes immediately
mount -o remount,ro /

# 2. Check if still in container
docker exec container_name ls /path/to/file

# 3. Check Restic backups
restic snapshots --repo /mnt/backup-btrfs/restic-repo
restic restore latest --target /tmp/recovery --include "*important*"

# 4. Check BTRFS snapshots (if applicable)
ls /mnt/data/.snapshots/
cp -a /mnt/data/.snapshots/daily-*/important-file /tmp/

# 5. Last resort - attempt recovery
apt-get install extundelete
extundelete /dev/mapper/vg-lv --restore-file path/to/file
```

### System Won't Boot (Disk Full)
```bash
# Boot from USB/Recovery mode

# 1. Mount root filesystem
mkdir /mnt/recovery
mount /dev/mapper/ubuntu--vg-ubuntu--lv /mnt/recovery

# 2. Clean enough to boot
rm -rf /mnt/recovery/tmp/*
rm -rf /mnt/recovery/var/log/*.gz
truncate -s 0 /mnt/recovery/var/log/*.log

# 3. Prevent services starting
touch /mnt/recovery/etc/cloud/cloud-init.disabled
```

## Prevention Checklist

### Daily Automated Checks
```bash
#!/bin/bash
# /etc/cron.daily/storage-guardian

# Alert if approaching threshold
USAGE=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
if [ $USAGE -gt 70 ]; then
    echo "Disk usage at ${USAGE}% on $(hostname)" | \
    mail -s "URGENT: Disk Space Warning" ops@company.com
fi

# Preemptive cleanup
if [ $USAGE -gt 75 ]; then
    docker system prune -f
    find /var/log -name "*.gz" -mtime +7 -delete
    journalctl --vacuum-time=7d
fi
```

### Weekly Maintenance
```bash
# Sunday 2 AM - maintenance window
0 2 * * 0 root /usr/local/bin/weekly-maintenance.sh

#!/bin/bash
# weekly-maintenance.sh

# 1. Docker cleanup
docker system prune -af --filter "until=168h"  # 1 week

# 2. Compress old logs
find /var/log -name "*.log.[0-9]" -exec gzip {} \;

# 3. Database maintenance
docker exec postgres vacuumdb --all --analyze

# 4. Check backup integrity
restic check --repo /mnt/backup-btrfs/restic-repo
```

## Communication Templates

### Incident Start
```
Subject: URGENT: Storage Critical on [hostname]

Current Usage: XX%
Growth Rate: XX GB/hour
ETA to Full: XX hours

Immediate Actions Taken:
- [ ] Docker cleanup initiated
- [ ] Log rotation forced
- [ ] Non-critical services stopped

Next Steps:
- Investigating root cause
- May need emergency maintenance window
```

### Post-Incident Report
```
Subject: Storage Incident Post-Mortem

Root Cause: [e.g., Grafana container log grew to 55GB]

Timeline:
- HH:MM - Alert triggered at 85%
- HH:MM - Emergency cleanup started
- HH:MM - Service restored

Space Recovered:
- Docker logs: XXX GB
- Old containers: XXX GB  
- System logs: XXX GB
- Total: XXX GB

Prevention Measures:
1. Added log rotation to affected container
2. Implemented daily cleanup cron
3. Set up growth rate monitoring

Lessons Learned:
- Always set container log limits
- Monitor growth rate, not just usage
- Automate cleanup before it's critical
```

## The Nuclear Option

When all else fails and you need the system back NOW:

```bash
#!/bin/bash
# DANGER: This will break things but save the system

# Stop everything non-essential
systemctl stop docker
systemctl stop mysql
systemctl stop postgresql

# Clear everything clearable
rm -rf /var/log/*
rm -rf /tmp/*
rm -rf /var/tmp/*
rm -rf /var/cache/*
rm -rf /home/*/.cache
rm -rf /var/lib/docker/containers/*
rm -rf /var/lib/docker/overlay2/*

# Restart minimal services
systemctl start ssh
systemctl start networking

echo "System recovered. Restore from backups now."
```

Remember: **Data recovery is possible. System recovery from 100% full is not.**
```

## eos/docs/storage_ops/10-architecture-examples.md

```markdown
# Storage Architecture Examples

## Example 1: Single Machine Blog

### Hardware
- 1x VPS with 2 CPU, 4GB RAM, 100GB SSD

### Storage Layout
```
/dev/vda1  /boot  ext4     1GB   (Boot partition)
/dev/vda2  /      ext4    99GB   (Everything else)

Thresholds: 60% warn, 70% compress, 75% clean, 80% critical
```

### Docker Compose
```yaml
version: '3.8'

services:
  wordpress:
    image: wordpress:latest
    volumes:
      - wordpress_data:/var/www/html
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    
  mysql:
    image: mysql:5.7
    volumes:
      - mysql_data:/var/lib/mysql
    environment:
      MYSQL_ROOT_PASSWORD: changeme
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  backup:
    image: restic/restic:latest
    volumes:
      - wordpress_data:/source/wordpress:ro
      - mysql_data:/source/mysql:ro
      - ./backups:/repo
    command: backup /source
    profiles: ["backup"]  # Run with: docker-compose --profile backup up

volumes:
  wordpress_data:
  mysql_data:
```

## Example 2: Small Business Setup (3 Machines)

### Hardware
- Machine 1: Edge - 4 CPU, 8GB RAM, 256GB SSD
- Machine 2: App - 8 CPU, 16GB RAM, 512GB SSD  
- Machine 3: Data - 8 CPU, 32GB RAM, 256GB SSD + 2TB HDD

### Storage Architecture
```
Machine 1 (Edge):
├── /dev/sda1  /boot     ext4    1GB
├── /dev/sda2  /         ext4    50GB
├── /dev/sda3  /var/log  ext4    50GB
└── /dev/sda4  /cache    ext4    155GB

Machine 2 (App):
├── /dev/sda1  /boot     ext4    1GB
├── /dev/sda2  /         ext4    100GB
├── /dev/sda3  /var/lib/docker  ext4  200GB
└── /dev/sda4  /data     ext4    211GB

Machine 3 (Data):
├── /dev/sda1  /boot     ext4    1GB
├── /dev/sda2  /         ext4    50GB
├── /dev/sda3  /var/lib/postgresql  xfs  205GB
├── /dev/sdb1  /backup   btrfs   2TB (compressed)
```

### Nomad Job Example
```hcl
job "nextcloud" {
  datacenters = ["dc1"]
  
  group "app" {
    count = 1
    
    network {
      port "http" { to = 80 }
    }
    
    constraint {
      attribute = "${attr.unique.hostname}"
      value     = "app-server"
    }
    
    task "nextcloud" {
      driver = "docker"
      
      config {
        image = "nextcloud:latest"
        ports = ["http"]
        
        volumes = [
          "/data/nextcloud:/var/www/html/data"
        ]
        
        logging {
          type = "json-file"
          config {
            max-size = "50m"
            max-files = "5"
          }
        }
      }
      
      resources {
        cpu    = 2000
        memory = 2048
      }
    }
  }
}
```

## Example 3: Startup with Growth (5 Machines)

### CephFS Distributed Storage Setup
```bash
# Initialize Ceph cluster on data nodes
cephadm bootstrap --mon-ip 10.0.1.4
cephadm add-host 10.0.1.6 data2

# Create CephFS
ceph fs volume create company-data

# Mount on all app servers
mount -t ceph 10.0.1.4:6789:/ /mnt/cephfs \
  -o name=admin,secret=AQBSdFhm...
```

### Storage Distribution
```yaml
roles:
  edge_servers: [edge1, edge2]
  app_server: [app1]
  data_primary: [data1]
  message_queue: [queue1]
  data_replica: [data2]

storage_layout:
  edge:
    nginx_cache: 100GB SSD
    ssl_certs: 1GB
    logs: 50GB
    
  app:
    containers: 200GB SSD
    temp_processing: 100GB SSD
    
  data_primary:
    postgresql: 500GB NVMe
    redis: 64GB RAM
    
  queue:
    rabbitmq: 100GB SSD
    message_store: 200GB SSD
    
  data_replica:
    postgresql_replica: 500GB SSD
    backups: 2TB HDD (BTRFS)
    ceph_osd: 2TB HDD
```

## Example 4: Enterprise HA Setup (10 Machines)

### Complete Infrastructure
```yaml
infrastructure:
  edge_tier:
    servers: [edge1, edge2]
    storage: 256GB SSD each
    role: "Load balancing, SSL, static content"
    
  application_tier:
    servers: [app1, app2, app3]
    storage: 512GB SSD each
    role: "Stateless applications"
    
  data_tier:
    servers: [data1, data2]
    storage: 2TB NVMe + 8TB HDD each
    role: "PostgreSQL primary/replica"
    
  message_tier:
    servers: [queue1, queue2]
    storage: 1TB SSD each
    role: "RabbitMQ cluster"
    
  observability:
    servers: [monitor1]
    storage: 4TB HDD
    role: "Prometheus, Grafana, ELK"
    
  compute:
    servers: [compute1]
    storage: 256GB SSD + GPU
    role: "ML, video processing"
```

### Kubernetes Storage Classes
```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: fast-ssd
provisioner: ceph.csi.ceph.com
parameters:
  clusterID: ceph-cluster
  pool: ssd-pool
reclaimPolicy: Retain
allowVolumeExpansion: true

---
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: bulk-hdd
provisioner: ceph.csi.ceph.com
parameters:
  clusterID: ceph-cluster
  pool: hdd-pool
reclaimPolicy: Delete
allowVolumeExpansion: true

---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgres-data
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: fast-ssd
  resources:
    requests:
      storage: 500Gi
```

## Migration Example: Moving from Single to Multi-Machine

### Phase 1: Prepare Single Machine
```bash
# On original machine
# 1. Create full backup
restic backup / \
  --exclude /dev \
  --exclude /proc \
  --exclude /sys \
  --exclude /tmp

# 2. Dump databases
pg_dumpall > backup.sql
mysqldump --all-databases > mysql-backup.sql

# 3. Export Docker volumes
for volume in $(docker volume ls -q); do
  docker run --rm -v $volume:/data -v $(pwd):/backup \
    alpine tar czf /backup/$volume.tar.gz -C /data .
done
```

### Phase 2: Distribute Services
```bash
# On new edge machine
docker-compose up -d nginx certbot

# On new app machine  
docker-compose up -d app worker

# On new data machine
# Restore databases first
psql < backup.sql
mysql < mysql-backup.sql

# Then start services
docker-compose up -d postgres mysql redis
```

### Phase 3: Migrate Data
```bash
# Sync files with minimal downtime
rsync -avz --progress old-server:/data/ /mnt/cephfs/data/

# Final sync with services stopped
docker-compose down
rsync -avz --delete old-server:/data/ /mnt/cephfs/data/
docker-compose up -d
```

## Monitoring All Architectures

### Universal Prometheus Config
```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'node'
    static_configs:
      - targets: ['edge1:9100', 'app1:9100', 'data1:9100']
        
  - job_name: 'docker'
    static_configs:
      - targets: ['edge1:9323', 'app1:9323', 'data1:9323']

rule_files:
  - 'storage-alerts.yml'
```

### Universal Alert Rules
```yaml
# storage-alerts.yml
groups:
  - name: storage
    rules:
      - alert: DiskSpaceLow
        expr: disk_usage_percent > 70
        for: 5m
        labels:
          severity: warning
          
      - alert: DiskSpaceCritical
        expr: disk_usage_percent > 85
        for: 1m
        labels:
          severity: critical
          
      - alert: InodeUsageHigh
        expr: disk_inodes_used_percent > 80
        for: 5m
        labels:
          severity: warning
```

## Key Takeaways

1. **Start simple** - Single machine can handle more than you think
2. **Monitor early** - Add monitoring before you need it
3. **Separate concerns** - Edge/App/Data separation scales naturally
4. **Plan for growth** - But don't over-engineer early
5. **Test backups** - Monthly restore drills save careers
6. **Automate cleanup** - Before you hit thresholds
7. **Document decisions** - Future you will thank present you
```

This comprehensive guide merges all the information from your documentation into a structured format that can be used as a reference for your storage operations. Each document builds on the previous ones, creating a complete picture of how to manage storage across your infrastructure at any scale.