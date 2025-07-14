# Eos Scripts Migration Analysis

## Executive Summary

Analysis of the scripts directory reveals 100+ shell scripts and Python utilities that provide various system administration, security, and infrastructure management capabilities. Many core functionalities have been migrated to Go commands within the Eos framework, but significant opportunities remain for further migration.

## Already Migrated Scripts

### User Management
- **addUser.sh** → `eos create user` / `eos create user-account`
  - Full user creation with SSH keys and secure passwords
  - SaltStack integration for remote management
  - Vault integration for password storage

- **changeUserPassword.sh** → `eos update users`
  - Password management integrated with system

- **deleteUsers.sh** → `eos delete users`
  - User removal functionality

### SSH Management
- **createSshKey.sh** → `eos create ssh`
  - FIPS-compliant SSH key generation
  - Remote host connection setup
  - SSH config management

- **copySshIds.sh** → Partially covered by `eos create ssh`
  - SSH key distribution functionality

### Docker Operations
- **deployDocker.py** → `eos create docker`
  - Docker installation and setup

- **backupDockerContainers.mjs** → `eos backup docker`
- **backupDockerImages.mjs** → `eos backup docker`
- **backupDockerVolumesWithCp.mjs** → `eos backup docker`
- **backupDockerNetworks.mjs** → `eos backup docker`
  - Comprehensive Docker backup with all components

### Service Management
- **manageServices.py** → `eos create service`
  - Service deployment via SaltStack/Nomad
  - Systemd service management
  - Docker Compose integration

### Backup Operations
- **backupAFile.sh** → `eos backup create`
  - General backup functionality
  - Timestamp-based backups

### Cron Management
- **manageCron.py** → `eos update crontab`
  - Crontab management functionality

### Package Management
- **removeUnusedPackages.sh** → `eos update packages`
  - System package updates and cleanup

### Security Tools
- **disableSSHIntoRoot.py** → `eos secure system`
  - SSH hardening as part of security management
  - Comprehensive security configurations

- **setupTerminal2FA.sh** → Partially in `eos secure system`
  - Two-factor authentication setup

### Infrastructure Tools
- **installTailscale.sh** → Various `eos create` commands
- **deployVault.sh** → `eos create vault`
- **installKubeadm.sh** → `eos create k3s`
- **installMattermost.py** → `eos create mattermost`
- **installTraefik.py** → `eos create hecate` (reverse proxy)

### Delphi Integration
- **delphi/deleteAgent.py** → `eos delphi delete agent`
- **custom-delphi-webhook** → `eos create delphi-webhook`
- **validate-delphi-config.py** → `eos delphi services validate`

## High-Priority Scripts for Migration

### 1. System Security & Hardening (Critical)
- **deployClamAV.py** - Antivirus deployment
- **deployWhois.py** - WHOIS service setup
- **setupDropbear.sh** - Lightweight SSH server
- **checkSshCredentials.sh** - SSH credential validation
- **troubleshootSsh.sh** - SSH diagnostics
- **checkSudo.py** - Sudo configuration validation

### 2. Storage & Filesystem Management (High)
- **manageZfs.mjs** - ZFS pool management
- **resizeDiskVolume.mjs** - Disk volume resizing
- **resizeFilesystems.sh** - Filesystem expansion
- **changePartitionFormat.sh** - Partition formatting
- **checkPartitionFormat.sh** - Partition verification
- **manageFstab.sh** - Mount point management

### 3. Monitoring & Diagnostics (High)
- **collectUbuntuInfo.sh** - System information gathering
- **setupDmesgsCollections.sh** - Kernel message logging
- **writeOutDmesg.sh** - Dmesg export
- **debuggingPATH.sh** - PATH troubleshooting
- **diskManager.mjs** - Disk usage monitoring

### 4. Network & VPN (Medium-High)
- **installOpenStack.sh** - OpenStack deployment
- **setupHeadscale.sh** - Headscale VPN setup
- **createTailscaleHostsConf.sh** - Tailscale configuration
- **generateULA.py** - IPv6 ULA generation

### 5. Container & Virtualization (Medium)
- **createLxdContainer.sh** - LXD container creation
- **initialiseLxd.sh** - LXD initialization
- **installMicroCloud.sh** - MicroCloud setup
- **manageVbox.py** - VirtualBox management
- **deployVirtualBox-7.1.x.sh** - VirtualBox installation
- **deployVBoxGuestAdditions.sh** - Guest additions

### 6. Backup & Recovery (Medium)
- **createTarBackup.sh** - TAR archive creation
- **installBorg.sh** - Borg backup setup
- **installRestic.sh** - Restic backup setup
- **backupWazuhDocker.mjs** - Wazuh backup

### 7. Development & CI/CD (Lower)
- **initGitRepo.sh** - Git repository initialization
- **changeGitRemote.sh** - Git remote management
- **gitAutoCommit.mjs** - Automated commits
- **setup-github-labels.sh** - GitHub label configuration

## Grouped by Functionality

### System Management
- System information collection
- Service management extensions
- Package management extensions
- User and permission management
- Cron job automation

### Security & Compliance
- Antivirus deployment
- SSH hardening and diagnostics
- Two-factor authentication
- Firewall configuration
- Security scanning tools

### Storage & Backup
- Filesystem management
- Volume management
- Backup tool integration
- Disaster recovery

### Networking
- VPN deployment
- Network configuration
- DNS management
- Load balancer setup

### Monitoring & Observability
- Log collection
- System monitoring
- Performance metrics
- Alert configuration

### Container & Virtualization
- Container orchestration
- VM management
- Cloud-init configuration
- Virtualization tools

## Migration Strategy Recommendations

1. **Immediate Priority**: Security-related scripts (ClamAV, SSH hardening, 2FA)
2. **High Priority**: Storage management (ZFS, filesystem operations)
3. **Medium Priority**: Monitoring and diagnostics tools
4. **Lower Priority**: Development tools and utilities

## Implementation Notes

- Many scripts contain interactive prompts that should be converted to flags/options
- Error handling should follow Eos patterns with proper context
- Logging should use structured logging with OpenTelemetry
- Commands should integrate with existing Eos subsystems (Vault, SaltStack, etc.)
- Consider grouping related scripts into subcommands (e.g., `eos storage zfs`, `eos storage resize`)