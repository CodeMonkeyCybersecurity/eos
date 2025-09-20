# Essential Eight Compliance Guide

*Last Updated: 2025-01-20*

## Overview

This document outlines how Eos helps organizations implement and maintain compliance with the Australian Cyber Security Centre's (ACSC) Essential Eight mitigation strategies.

## Essential Eight Controls

### 1. Application Control

**Eos Implementation:**
- **AppArmor Integration**: `eos create apparmor` configures mandatory access controls
- **Container Security**: Docker containers run with restricted capabilities by default
- **Nomad Job Policies**: Application execution controlled through Nomad job specifications

**Commands:**
```bash
# Configure application control
eos create apparmor --profile-mode enforce
eos update container security --cap-drop ALL
```

### 2. Patch Applications

**Eos Implementation:**
- **Automated Updates**:  states for regular application patching
- **Version Management**: `pkg/platform/version_resolver.go` ensures latest versions
- **Monitoring**: Delphi tracks unpatched applications

**Commands:**
```bash
# Check application patch status
eos read system patches
eos update applications --auto-patch
```

### 3. Configure Microsoft Office Macro Settings

**Eos Implementation:**
- Not directly applicable to Linux servers
- For Windows workstations managed via : custom states available

### 4. User Application Hardening

**Eos Implementation:**
- **Browser Hardening**: Automated Firefox/Chrome hardening via 
- **PDF Reader Security**: Restricted PDF handling in containers
- **Email Security**: Integration with mail servers for attachment filtering

**Commands:**
```bash
# Harden user applications
eos create hardening user-apps
```

### 5. Restrict Administrative Privileges

**Eos Implementation:**
- **LDAP Integration**: Centralized user management with role-based access
- **Sudo Policies**: Granular sudo rules via  states
- **Vault Integration**: Time-bound credential leasing
- **Audit Logging**: All privileged actions logged to Delphi

**Commands:**
```bash
# Configure privilege restrictions
eos create ldap --enforce-rbac
eos update sudo-policy --max-session 15m
eos create vault-auth --lease-ttl 1h
```

### 6. Patch Operating Systems

**Eos Implementation:**
- **Automated OS Updates**: Unattended upgrades configured by default
- **Reboot Management**: Controlled reboot windows for kernel updates
- **Rollback Capability**: ZFS snapshots before major updates

**Commands:**
```bash
# Configure OS patching
eos create update-manager --auto-security
eos update system --kernel-live-patch
```

### 7. Multi-Factor Authentication (MFA)

**Eos Implementation:**
- **Authentik Integration**: Built-in MFA support for all web services
- **SSH MFA**: Google Authenticator or YubiKey for SSH access
- **API Security**: All Eos APIs require MFA tokens

**Commands:**
```bash
# Enable MFA
eos create authentik --require-mfa
eos update ssh --mfa-required
eos create api-gateway --enforce-mfa
```

### 8. Regular Backups

**Eos Implementation:**
- **Automated Backups**: Scheduled via `eos backup` commands
- **Immutable Storage**: Backup versioning with retention policies
- **Encryption**: All backups encrypted at rest and in transit
- **Testing**: Automated restore testing via  states

**Commands:**
```bash
# Configure backups
eos backup schedule --frequency daily --retention 30d
eos backup test-restore --random-sample
eos create backup-encryption --algorithm aes-256
```

## Implementation Maturity Levels

### Maturity Level 1 (Basic)
1. **Application Control**: Basic whitelisting
2. **Patch Applications**: Monthly patching
3. **Admin Privileges**: Basic RBAC
4. **Patch OS**: Quarterly updates

### Maturity Level 2 (Standard)
1. **MFA**: All remote access
2. **Backups**: Daily with encryption
3. **Application Hardening**: Browser and PDF security
4. **Enhanced Monitoring**: Delphi integration

### Maturity Level 3 (Advanced)
1. **Zero Trust**: Network segmentation via Hecate
2. **Automated Response**: Delphi-triggered remediation
3. **Continuous Compliance**: Real-time monitoring
4. **Advanced Threat Detection**: ML-based analysis

## Compliance Reporting

### Generate Compliance Report
```bash
# Generate Essential Eight compliance report
eos read compliance essential-eight --format pdf

# Check specific control status
eos read compliance --control application-control
```

### Continuous Monitoring
```bash
# Enable compliance monitoring
eos create delphi-compliance --framework essential-eight

# Set up alerts
eos create alert --compliance-drift --severity high
```

## Integration with Existing Tools

###  States for Compliance
```yaml
# /srv//essential-eight/init.sls
essential_eight_compliance:
  eos.compliance:
    - framework: essential-eight
    - maturity_level: 2
    - controls:
        - application_control
        - patch_management
        - privilege_restriction
        - mfa_enforcement
```

### Delphi Rules
```yaml
# Monitor compliance drift
- rule: Essential Eight Compliance Drift
  condition: compliance.score < 80
  action: 
    - alert: security-team
    - remediate: auto
```

## Quick Start Guide

### 1. Initial Assessment
```bash
# Run compliance assessment
eos read compliance assess --framework essential-eight

# Generate gap analysis
eos read compliance gaps --export gaps.json
```

### 2. Implementation Plan
```bash
# Generate implementation plan
eos create compliance-plan --target-maturity 2

# Deploy controls
eos create essential-eight --maturity-level 1
```

### 3. Ongoing Compliance
```bash
# Schedule regular assessments
eos backup schedule compliance-check --frequency weekly

# Enable drift detection
eos create monitor compliance-drift
```

## Best Practices

1. **Gradual Implementation**: Start with Maturity Level 1
2. **Test First**: Use staging environments
3. **Document Changes**: Maintain compliance changelog
4. **Regular Training**: Security awareness for all users
5. **Incident Response**: Integrate with IR procedures

## Troubleshooting

### Common Issues

**Application Control Blocking Legitimate Apps**
```bash
# Review blocked applications
eos read apparmor blocks --last 24h

# Add exception
eos update apparmor whitelist --app /usr/bin/legitimate-app
```

**Patch Conflicts**
```bash
# Check patch status
eos read patches conflicts

# Defer specific patch
eos update patch defer --package problematic-pkg --days 7
```

**MFA Issues**
```bash
# Check MFA status
eos read authentik mfa-status

# Reset user MFA
eos update user reset-mfa --username john.doe
```

## References

- [ACSC Essential Eight](https://www.cyber.gov.au/acsc/view-all-content/essential-eight)
- [Essential Eight Maturity Model](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/essential-eight-maturity-model)
- Code Monkey Cybersecurity Compliance Framework

## Support

For Essential Eight compliance assistance:
- GitHub Issues: https://github.com/CodeMonkeyCybersecurity/eos/issues
- Documentation: https://wiki.cybermonkey.net.au/essential-eight
- Email: compliance@cybermonkey.net.au