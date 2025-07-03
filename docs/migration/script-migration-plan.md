# Shell Script Migration Plan

**Last Updated**: March 7, 2025  
**Status**: Phase 1 Complete, Phases 2-4 Planning

## Overview

This document outlines the comprehensive migration plan for converting legacy shell scripts in the `scripts/` directory to native Go implementations within the Eos framework. The migration follows established architectural patterns and prioritizes functionality by importance and complexity.

## Migration Status

### ✅ Completed Migrations (Phase 1 - Critical Infrastructure)

As of March 7, 2025, the following high-priority scripts have been successfully migrated:

#### SSH Security & Diagnostics
- **Source Scripts**: `checkSshCredentials.sh`, `troubleshootSsh.sh`, `disableSSHIntoRoot.py`, `copySshIds.sh`, `distributeSshKeys.sh`
- **New Package**: `pkg/ssh/diagnostics.go`
- **Commands Added**:
  - `eos secure ssh` - Comprehensive SSH troubleshooting
  - `eos secure ssh check-credentials` - Quick credential validation
  - `eos secure ssh disable-root` - Disable SSH root login for security hardening
  - `eos secure ssh copy-keys` - Copy SSH keys to multiple remote hosts
  - `eos secure ssh distribute-keys` - Distribute SSH keys to Tailscale network peers
- **Features**: SSH key validation, network connectivity testing, service status checking, permission fixing, root login hardening, SSH key distribution, Tailscale integration

#### Storage Management
- **Source Scripts**: `manageFstab.sh`, `resizeFilesystems.sh`
- **New Packages**: `pkg/storage/filesystem.go`, `pkg/storage/lvm.go`
- **Commands Enhanced**:
  - `eos update storage --resize` - Auto-resize Ubuntu LVM
  - `eos update storage fstab` - Interactive fstab management
  - `eos read storage` - Comprehensive storage information
- **Features**: LVM operations, filesystem resizing, fstab management, interactive disk mounting

#### System Information Collection
- **Source Scripts**: `collectUbuntuInfo.sh`
- **New Package**: `pkg/system/info.go`
- **Commands Added**: `eos read system` - Comprehensive system diagnostics
- **Features**: Process info, package lists, disk usage, network config, system logs, crontab entries

#### Network Configuration
- **Source Scripts**: `setupHeadscale.sh`, `createTailscaleHostsConf.sh`
- **New Packages**: `pkg/infrastructure/network/headscale.go`, `pkg/infrastructure/network/hosts.go`
- **Commands Added**:
  - `eos create headscale` - Complete Headscale server setup
  - `eos create tailscale-hosts` - Generate hosts configs from Tailscale
  - `eos read tailscale` - Display network status
- **Features**: Headscale installation, Tailscale peer management, multiple output formats (YAML, JSON, Ansible)

#### Container Orchestration
- **Source Scripts**: `installKubeadm.sh`, `installMicroK8s.sh`
- **New Packages**: `pkg/container/kubernetes.go`, enhanced `cmd/create/k3s.go`
- **Commands Added**:
  - `eos create kubeadm` - Complete Kubernetes installation using kubeadm
  - `eos create microk8s` - MicroK8s installation and configuration
- **Features**: Kubernetes prerequisite installation, firewall configuration, swap management, cluster initialization, addon management, status monitoring

#### User Management
- **Source Scripts**: `addUser.sh`, `changeUserPassword.sh`, `usersWithRemoteSsh.sh`, `userHostnameStamp.sh`
- **New Package**: `pkg/users/management.go`
- **Commands Added**:
  - `eos create user-simple` - Interactive user creation with sudo and SSH options
  - `eos update users password` - Change user passwords securely
  - `eos update users ssh-access` - Grant SSH access to users
  - `eos read users` - List system users, SSH users, and user-hostname stamps
- **Features**: User account creation, password management, SSH access control, interactive prompts, username validation, sudo group management

### 🔄 Remaining Scripts (Phases 2-4)

## Detailed Migration Plan

### Phase 2: Core Services (Planned Q2 2025)

#### Security Package Enhancement (`pkg/security`)
**Timeline**: 8 weeks  
**Complexity**: High  
**Scripts to Migrate**:
- `setupTerminal2FA.sh` - Terminal 2FA setup

**Proposed Commands**:
```bash
eos secure 2fa --setup --user <username>
eos secure ssh --disable-root --distribute-keys
eos create user --name john --ssh-access --2fa-required
eos secure audit --ssh-users --remote-access
```

#### Container Orchestration Enhancement (`pkg/container`)
**Timeline**: 4 weeks  
**Complexity**: High  
**Scripts to Migrate**:
- `installOpenStack.sh`, `installMicroCloud.sh` - Cloud platforms
- `docker/` directory (12 scripts) - Docker management utilities

**Proposed Commands**:
```bash
eos create k8s --type kubeadm --nodes 3
eos create microcloud --storage zfs --network ovn
eos create kubernetes --type microk8s --addons dns,storage
```

#### Virtualization Package (`pkg/virtualization`)
**Timeline**: 4 weeks  
**Complexity**: High  
**Scripts to Migrate**:
- `createLxdContainer.sh`, `installLxd.sh`, `initialiseLxd.sh` - LXD management
- `deployVirtualBox-7.1.x.sh`, `manageVbox.py` - VirtualBox management
- `installQemuGuestAgent.sh` - QEMU guest agent

**Proposed Commands**:
```bash
eos create lxd --init --storage zfs --network bridge
eos create vbox --vm ubuntu-server --memory 4GB --disk 20GB
eos create container --name web --image ubuntu:22.04 --port 80:8080
```

### Phase 3: Extended Services (Planned Q3 2025)

#### Monitoring & Security (`pkg/monitoring`)
**Timeline**: 4 weeks  
**Complexity**: Medium  
**Scripts to Migrate**:
- `deployClamAV.py` - Antivirus deployment
- `installGrafana.py`, `installLokiDocker.sh` - Monitoring stack
- `delphi/` scripts (4 files) - Enhanced Wazuh/Delphi operations

**Proposed Commands**:
```bash
eos create antivirus --type clamav --auto-update
eos create monitoring --stack prometheus-grafana-loki
eos delphi enhanced --cluster-mode --backup-enabled
```

#### Network Services Extension (`pkg/network`)
**Timeline**: 4 weeks  
**Complexity**: Medium  
**Scripts to Migrate**:
- `installCaddy.sh`, `installTraefik.sh` - Reverse proxies
- `installApacheGuacServer.sh` - Remote access gateway
- `createHostsConf.sh` - Network configuration management

**Proposed Commands**:
```bash
eos create proxy --type caddy --domain example.com --tls auto
eos create guacamole --database mysql --auth ldap
eos create network --hosts-from tailscale --dns-integration
```

#### Backup Systems (`pkg/backup`)
**Timeline**: 4 weeks  
**Complexity**: Medium  
**Scripts to Migrate**:
- `installBorg.sh`, `installRestic.sh` - Modern backup solutions
- `createTarBackup.sh`, `backupAFile.sh` - Traditional backup methods

**Proposed Commands**:
```bash
eos create backup --type borg --repository /backup --encryption
eos create backup --type restic --backend s3 --schedule daily
eos backup restore --from borg --date yesterday --path /home
```

### Phase 4: System Operations (Planned Q4 2025)

#### Database Management (`pkg/database`)
**Timeline**: 3 weeks  
**Complexity**: Medium  
**Scripts to Migrate**:
- `PostgreSQL/` directory (7 scripts) - Complete PostgreSQL management suite

**Proposed Commands**:
```bash
eos create postgresql --version 15 --cluster-name main
eos database backup --type postgresql --compress --encrypt
eos database migrate --from 14 --to 15 --validate
```

#### System Maintenance Enhancement (`pkg/system`)
**Timeline**: 4 weeks  
**Complexity**: Medium  
**Scripts to Migrate**:
- `removeUnusedPackages.sh`, `purgeAndReinstallSnapd.sh` - Package management
- `manageCron.py`, `manageServices.py` - Service automation
- `installPowershell.sh`, `installZx.sh` - Development tool installation

**Proposed Commands**:
```bash
eos update system --cleanup-packages --repair-snap
eos create cron --job "backup" --schedule "0 2 * * *" --user backup
eos create service --name myapp --user myapp --restart always
```

#### Storage Enhancement (`pkg/storage`)
**Timeline**: 3 weeks  
**Complexity**: Medium  
**Scripts to Migrate**:
- `manageZfs.mjs` - ZFS pool management
- `resizeDiskVolume.mjs`, `diskManager.mjs` - Advanced disk operations

**Proposed Commands**:
```bash
eos create zfs --pool mypool --raid raidz1 --compression lz4
eos update storage --resize-volume --filesystem zfs --auto
eos read storage --zfs-status --performance-metrics
```

### Phase 5: Development & Utilities (Planned Q1 2026)

#### Development Tools (`pkg/development`)
**Timeline**: 2 weeks  
**Complexity**: Low  
**Scripts to Migrate**:
- `setupGit.sh`, `initGitRepo.sh`, `gitWrap.sh` - Git management
- `setup-github-labels.sh`, `setupLaunchpad.sh` - Repository setup
- `changeGitRemote.sh` - Git configuration

#### Utility Cleanup (`pkg/utilities`)
**Timeline**: 2 weeks  
**Complexity**: Low  
**Scripts to Migrate**:
- `utilities/` directory (12 helper scripts)
- `cleanupPATH.py`, `debuggingPATH.sh` - Path management
- `parseTemplate.sh`, `enableAutocomplete.sh` - System utilities

## Implementation Guidelines

### Architectural Patterns

All migrated functionality must follow established Eos patterns:

1. **Structured Logging**: Use `otelzap.Ctx(rc.Ctx)` for all logging operations
2. **Error Handling**: Implement `eos_err.NewExpectedError()` for user-facing errors
3. **Telemetry**: Include OpenTelemetry spans using `telemetry.Start()`
4. **Command Structure**: Follow `eos.Wrap()` pattern for command functions
5. **Configuration**: Use runtime context (`*eos_io.RuntimeContext`) throughout

### Code Quality Requirements

- **Test Coverage**: Minimum 90% for all new packages
- **Linting**: Pass `golangci-lint run` without warnings
- **Security**: No hardcoded secrets, proper input validation
- **Documentation**: Comprehensive command help and package documentation
- **Performance**: Go implementations must be ≥2x faster than shell equivalents

### Migration Checklist

For each script migration:

- [ ] **Analysis**: Document script functionality and dependencies
- [ ] **Design**: Plan Go package structure and command interface
- [ ] **Implementation**: Write Go code following Eos patterns
- [ ] **Testing**: Unit tests and integration tests
- [ ] **Documentation**: Update command help and documentation
- [ ] **Validation**: Verify functionality matches original script
- [ ] **Cleanup**: Remove original shell script
- [ ] **Integration**: Update any dependent scripts or documentation

## Success Metrics

### Quantitative Goals
- **Coverage**: 100% of shell scripts migrated to Go
- **Performance**: ≥2x speed improvement over shell equivalents
- **Reliability**: Zero regression issues in migrated functionality
- **Maintainability**: 90% test coverage across all new packages
- **Security**: All security-related functions reviewed and validated

### Qualitative Goals
- **Consistency**: Unified command interface across all operations
- **Usability**: Improved error messages and user experience
- **Maintainability**: Easier debugging and feature enhancement
- **Documentation**: Comprehensive usage and troubleshooting guides

## Timeline Summary

| Phase | Duration | Scripts | Packages | Completion Target |
|-------|----------|---------|----------|-------------------|
| Phase 1 | 16 weeks | 17 scripts | 6 packages | ✅ **Complete** (March 2025) |
| Phase 2 | 16 weeks | ~40 scripts | 3 packages | Q2 2025 |
| Phase 3 | 12 weeks | ~50 scripts | 3 packages | Q3 2025 |
| Phase 4 | 10 weeks | ~35 scripts | 3 packages | Q4 2025 |
| Phase 5 | 6 weeks | ~25 scripts | 2 packages | Q1 2026 |
| **Total** | **60 weeks** | **~158 scripts** | **15 packages** | **Q1 2026** |

## Resource Requirements

### Development Team
- **2 Senior Go Developers** - Core package development
- **1 DevOps Engineer** - Testing and validation
- **1 Security Engineer** - Security review (part-time)
- **1 Technical Writer** - Documentation (part-time)

### Infrastructure
- **CI/CD Pipeline** - Automated testing and validation
- **Test Environment** - Ubuntu server instances for integration testing
- **Security Scanning** - Automated security analysis tools

## Risk Mitigation

### Technical Risks
- **Complexity Underestimation**: Add 20% buffer to all timeline estimates
- **Dependency Issues**: Identify and resolve package dependencies early
- **Performance Regression**: Benchmark all implementations against originals
- **Security Vulnerabilities**: Mandatory security review for all security packages

### Operational Risks
- **User Adoption**: Maintain backward compatibility where possible
- **Documentation Gap**: Comprehensive migration guides for existing users
- **Support Burden**: Clear troubleshooting documentation and error messages

## Contact & Support

- **Project Lead**: Development Team
- **Security Review**: Security Team
- **Documentation**: Technical Writing Team
- **Questions**: Create issue in Eos repository with `migration` label

---

*This document is updated monthly. For the latest status, check the Eos repository migration project board.*