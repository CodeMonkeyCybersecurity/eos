#  Removal & Simplification Plan

## Overview
This document outlines the strategy to remove  from the Eos infrastructure and replace it with simpler, more maintainable solutions for on-premises Linux fleet disk management.

## Current State Analysis

###  Components to Remove
- `pkg/storage_monitor/` -  disk monitoring integration
-  minion configurations
-  master infrastructure
- Complex state files and  data
- Manual `vg`/`lv` LVM management scripts

### Dependencies to Maintain
- Existing storage interfaces in `pkg/storage/`
- Monitoring and alerting systems
- Current mount points and data

## Replacement Solutions

### Option 1: Terraform + Cloud-Init (Recommended)
**Best for:** New deployments and infrastructure-as-code approach

**Advantages:**
- Declarative configuration
- Version controlled
- No agents required
- Integrates with existing Terraform usage

**Implementation:**
- Use Terraform modules for VM provisioning with storage
- Cloud-init handles disk formatting and mounting
- systemd timers for monitoring and auto-resize

### Option 2: Direct Go Implementation (EOS Native)
**Best for:** Tight integration with existing Eos codebase

**Advantages:**
- No external dependencies
- Native Go error handling and logging
- Consistent with Eos patterns
- Real-time operations

**Implementation:**
- `pkg/storage/local/` package for direct disk management
- CLI commands: `eos create storage-local`
- No LVM - direct filesystem creation

### Option 3: Ansible (Transitional)
**Best for:** Teams familiar with Ansible, gradual migration

**Advantages:**
- Simpler than 
- Good documentation
- Idempotent operations
- Easy to understand playbooks

**Implementation:**
- Ansible playbooks for disk management
- systemd services for monitoring
- Gradual replacement of  states

## Migration Strategy

### Phase 1: Parallel Implementation (Month 1)
1. **Deploy new solutions alongside **
   - Implement local storage manager
   - Create Terraform modules
   - Test on non-production systems

2. **Validation**
   - Compare results between old and new systems
   - Verify data integrity
   - Test failure scenarios

### Phase 2: Gradual Migration (Months 2-3)
1. **New deployments use new system**
   - All new VMs use Terraform + cloud-init
   - New storage requests use Go implementation

2. **Migrate existing systems**
   - Start with development environments
   - Move to staging
   - Finally migrate production (with rollback plan)

### Phase 3: Complete Removal (Month 4)
1. **Remove  infrastructure**
   - Remove minion configurations
   - Clean up old code

2. **Documentation and training**
   - Update operational procedures
   - Train team on new tools
   - Create troubleshooting guides

## Implementation Details

### Terraform Module Usage
```hcl
module "storage_vm" {
  source = "./modules/linux-storage"
  
  vm_name = "app-server-01"
  vm_config = {
    memory_mb = 4096
    vcpus     = 2
    network   = "default"
  }
  
  storage_config = {
    data_disk_size_gb = 100
    filesystem_type   = "ext4"
    mount_point      = "/data"
    auto_resize      = true
  }
}
```

### Eos CLI Usage
```bash
# Create local storage volume
eos create storage-local data-vol /dev/sdb \
  --filesystem ext4 \
  --mount /data \
  --options noatime,defaults

# List storage volumes
eos list storage-local

# Resize volume (automatic)
eos resize storage-local data-vol
```

### Monitoring Integration
- systemd timers replace cron jobs
- Native logging to journald
- Prometheus metrics via node_exporter
- Consul health checks for storage services

## Risk Mitigation

### Data Safety
- Always backup before migration
- Test restore procedures
- Validate data integrity post-migration
- Keep rollback procedures ready

### Operational Continuity
- Parallel running during transition
- Gradual migration by environment
- 24/7 monitoring during migration
- Team training before cutover

### Performance Impact
- Benchmark before/after migration
- Monitor disk I/O during transition
- Validate application performance
- Have performance rollback triggers

## Success Criteria

### Technical
- [ ] All storage operations work without 
- [ ] No data loss during migration
- [ ] Performance maintained or improved
- [ ] Monitoring and alerting functional

### Operational
- [ ] Team trained on new tools
- [ ] Documentation updated
- [ ] Troubleshooting procedures tested
- [ ] On-call procedures updated

### Business
- [ ] Reduced operational complexity
- [ ] Faster deployment times
- [ ] Lower maintenance overhead
- [ ] Improved reliability

## Timeline

| Phase | Duration | Key Milestones |
|-------|----------|----------------|
| Phase 1 | Month 1 | New solutions implemented and tested |
| Phase 2 | Months 2-3 | 50% of systems migrated |
| Phase 3 | Month 4 |  completely removed |

## Resource Requirements

### Development
- 1 senior engineer (lead migration)
- 1 junior engineer (testing and validation)
- DevOps engineer (infrastructure changes)

### Infrastructure
- Test environment for validation
- Backup storage for safety
- Monitoring system updates

## Rollback Plan

### Triggers
- Data corruption detected
- Performance degradation > 20%
- Critical system failures
- Team unable to operate new system

### Procedure
1. Stop new system operations
2. Restore  services
3. Validate data integrity
4. Resume normal operations
5. Analyze failure and plan retry

## Post-Migration Benefits

### Simplified Architecture
- Fewer moving parts
- No  master/minion complexity
- Direct API calls instead of  states
- Native Go error handling

### Improved Operations
- Faster deployments
- Better error visibility
- Consistent logging
- Native monitoring integration

### Reduced Maintenance
- No  version upgrades
- Fewer security patches
- Simpler troubleshooting
- Better documentation
