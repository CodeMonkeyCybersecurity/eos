# Vault Salt States Documentation

*Last Updated: 2025-01-17*

## Overview

This directory contains comprehensive Salt states for managing the complete HashiCorp Vault lifecycle. These states provide idempotent, repeatable deployment and configuration of Vault following Eos security best practices.

## Architecture

The Salt-based Vault deployment follows the three-phase lifecycle model:

1. **Create Phase**: Installation, environment setup, TLS, configuration, service start, and initialization
2. **Enable Phase**: Unsealing, authentication setup, policies, audit logging, MFA, and agent configuration
3. **Harden Phase**: System hardening, Vault-specific security, network restrictions, and backup setup

## Available States

### Core Lifecycle States

- **`hashicorp.vault.complete_lifecycle`** - Runs all three phases in sequence (recommended)
- **`hashicorp.vault.eos_complete`** - Phase 1: Complete creation and initialization
- **`hashicorp.vault.enable`** - Phase 2: Enable features and authentication
- **`hashicorp.vault.harden`** - Phase 3: Apply comprehensive hardening

### Component States

- **`hashicorp.vault.install`** - Install Vault binary and create user/directories
- **`hashicorp.vault.tls`** - Generate self-signed TLS certificates
- **`hashicorp.vault.config_eos`** - Write Eos-specific Vault configuration
- **`hashicorp.vault.service_eos`** - Manage Vault systemd service
- **`hashicorp.vault.initialize`** - Initialize Vault with 5 keys (3 threshold)
- **`hashicorp.vault.unseal`** - Unseal Vault using stored keys

### Management States

- **`hashicorp.vault.remove`** - Clean removal of Vault (preserves data by default)

## Usage Examples

### Complete Deployment

Deploy Vault with all features enabled:

```bash
salt-call --local state.apply hashicorp.vault.complete_lifecycle pillar='{
  "vault": {
    "enable_userpass": true,
    "enable_approle": true,
    "enable_mfa": true,
    "enable_agent": true,
    "allowed_subnets": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  }
}'
```

### Phase-by-Phase Deployment

```bash
# Phase 1: Create and Initialize
salt-call --local state.apply hashicorp.vault.eos_complete

# Phase 2: Enable Features (after unsealing)
ROOT_TOKEN=$(jq -r .root_token /var/lib/eos/secret/vault_init.json)
salt-call --local state.apply hashicorp.vault.enable pillar="{\"vault\":{\"root_token\":\"$ROOT_TOKEN\"}}"

# Phase 3: Apply Hardening
salt-call --local state.apply hashicorp.vault.harden pillar="{\"vault\":{\"root_token\":\"$ROOT_TOKEN\"}}"
```

### Unseal Vault

```bash
# Automatic unseal using stored keys
salt-call --local state.apply hashicorp.vault.unseal
```

## Pillar Configuration

### Available Pillar Options

```yaml
vault:
  # Installation options
  version: latest              # Vault version to install
  user: vault                  # System user for Vault
  group: vault                 # System group for Vault
  port: 8179                   # Eos-specific Vault port
  
  # Directory paths
  install_dir: /opt/vault
  config_path: /etc/vault.d
  data_path: /opt/vault/data
  log_path: /opt/vault/logs
  tls_path: /opt/vault/tls
  
  # Configuration options
  log_level: info
  log_format: json
  tls_enabled: true
  ui_enabled: true
  
  # Enablement options
  enable_userpass: true        # Enable userpass auth
  enable_approle: true         # Enable AppRole auth
  enable_mfa: true             # Enable MFA
  enable_agent: true           # Deploy Vault Agent
  eos_password: <random>       # Password for eos user
  
  # Hardening options
  allowed_subnets:             # Networks allowed to access Vault
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
  
  # Runtime options (set automatically)
  root_token: <from_init_file> # Root token for configuration
```

## File Locations

After deployment, important files are located at:

- **Configuration**: `/etc/vault.d/vault.hcl`
- **TLS Certificates**: `/opt/vault/tls/`
- **Initialization Data**: `/var/lib/eos/secret/vault_init.json` (SENSITIVE!)
- **Audit Logs**: `/var/log/vault/vault-audit.log`
- **Service File**: `/etc/systemd/system/vault.service`
- **Agent Config**: `/etc/vault.d/agent/agent.hcl`
- **Management Scripts**: `/usr/local/bin/eos-vault*`

## Security Features

### System Hardening
- Swap disabled for memory security
- Core dumps disabled
- Security-focused ulimits
- Firewall rules (UFW/iptables)
- SSH hardening
- AppArmor profile (Debian/Ubuntu)

### Vault-Specific Security
- TLS encryption enforced
- Comprehensive audit logging (file + syslog)
- Rate limiting quotas
- Automated backup configuration
- Service security overrides
- Log rotation

### Authentication & Authorization
- Multiple auth methods (userpass, AppRole)
- Entity and alias management
- Core security policies
- MFA support (TOTP)
- Vault Agent for automated auth

## Integration with Eos

The Salt states integrate seamlessly with Eos commands:

```go
// Vault package automatically uses Salt when available
vault.OrchestrateVaultCreate(rc)      // Uses Salt if available
vault.EnableVault(rc, client, log)     // Uses Salt if available
vault.ComprehensiveHardening(rc, ...)  // Uses Salt if available
```

## Troubleshooting

### Check Vault Status
```bash
# Service status
systemctl status vault

# API status
export VAULT_ADDR="https://127.0.0.1:8179"
export VAULT_SKIP_VERIFY="true"
vault status

# Check logs
journalctl -u vault -f
tail -f /var/log/vault/vault-audit.log
```

### Common Issues

1. **Vault won't start**: Check `/opt/vault/logs/` and `journalctl -u vault`
2. **Can't unseal**: Ensure `/var/lib/eos/secret/vault_init.json` exists
3. **Auth failures**: Verify root token is correct in pillar data
4. **Network issues**: Check firewall rules and TLS configuration

### Manual Operations

```bash
# Manually unseal with stored keys
/usr/local/bin/eos-vault-unseal

# Check complete status
/usr/local/bin/eos-vault-status

# Manual backup
/usr/local/bin/vault-backup.sh
```

## Best Practices

1. **Always backup** the initialization file (`/var/lib/eos/secret/vault_init.json`)
2. **Distribute unseal keys** among multiple administrators
3. **Revoke root token** after setting up alternative authentication
4. **Monitor audit logs** regularly for security events
5. **Test backups** by performing restore drills
6. **Use Salt pillar encryption** for sensitive configuration

## Development Notes

### Adding New Features

1. Create new state files following the pattern
2. Include proper requisites for ordering
3. Add verification steps
4. Update documentation

### Testing States

```bash
# Test state parsing
salt-call --local state.show_sls hashicorp.vault.enable

# Dry run (test mode)
salt-call --local state.apply hashicorp.vault.enable test=True
```

## Related Documentation

- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)
- [Eos Vault Package Documentation](/opt/eos/pkg/vault/README.md)
- [Salt State Documentation](https://docs.saltproject.io/en/latest/topics/tutorials/starting_states.html)