# Vault Package Documentation

This package provides comprehensive HashiCorp Vault integration for Eos with enterprise-grade security features.

## Core Modules

### Security & Hardening
- **`hardening.go`** - Comprehensive security hardening with system, Vault, and network configurations
- **`mfa.go`** - Multi-factor authentication implementation (TOTP, Duo, PingID, Okta)
- **`secure_init_reader.go`** - Secure access to Vault initialization data with audit logging
- **`hcl_validator.go`** - HCL policy validation and automatic error correction (see `validation_README.md`)

### Lifecycle Management
- **`lifecycle1_create.go`** - Vault installation and initial setup
- **`lifecycle2_enable.go`** - Interactive Vault configuration with MFA and auth setup
- **`phase11_write_policies.go`** - Role-based access control policies
- **`phase15_harden.go`** - Final hardening and security confirmation

### Vault Operations
- **`util_read.go`** - Vault data reading utilities with fallback mechanisms
- **`vault_client.go`** - Client creation and connection management
- **`vault_auth.go`** - Authentication method configuration

## Security Features

### Multi-Factor Authentication
The MFA module supports multiple providers:
- **TOTP**: Time-based one-time passwords with QR code generation
- **Duo**: Duo Security integration with push notifications
- **PingID**: PingID authentication services
- **Okta**: Okta MFA integration

### Comprehensive Hardening
System-level hardening includes:
- Swap and core dump disabling
- Security-focused ulimits and firewall configuration
- SSH hardening with secure defaults
- Audit logging and log rotation
- Automated backup procedures
- Network access restrictions

### Role-Based Access Control
Four policy levels provide principle of least privilege:
- **Default Policy**: Basic user access with time-bound leases
- **Admin Policy**: Infrastructure management capabilities
- **Emergency Policy**: Controlled emergency access with approval workflows
- **Read-Only Policy**: Monitoring and audit access

### Secure Init Data Access
The `eos read vault-init` command provides:
- Automatic sensitive data redaction
- Access control with user verification
- Comprehensive audit logging
- File integrity verification
- Multiple export formats (console, JSON, secure file)

## Usage Examples

### Complete Vault Deployment
```bash
eos create vault    # Install Vault
eos enable vault    # Interactive setup with MFA
eos secure vault    # Apply comprehensive hardening
```

### Secure Data Access
```bash
# Secure access with redaction (recommended)
sudo eos read vault-init

# Status overview without sensitive data
sudo eos read vault-init --status-only

# Emergency access with audit trail
sudo eos read vault-init --no-redact --reason "Emergency recovery"
```

### Hardening Options
```bash
# Comprehensive security hardening (recommended)
sudo eos secure vault --comprehensive

# Basic hardening (legacy compatibility)
sudo eos secure vault --disable-swap --disable-coredump
```

## Configuration Files

### Vault Configuration
Vault configuration is generated using Go templates in `pkg/shared/vault_server.go` with secure defaults:
- TLS encryption with strong cipher suites
- File storage backend with secure permissions
- Comprehensive logging and monitoring
- UI enabled for administration

### Security Policies
Policy templates are defined in `pkg/shared/vault_policies.go` using HCL syntax with:
- Identity-based path templating
- Time-bound access controls
- Control group requirements for sensitive operations
- Explicit denials for dangerous operations

### Vault Agent Configuration
Vault Agent provides automatic token renewal and authentication. Configuration is managed through:
- **Agent Config Generation**: Templates in `pkg/shared/vault_agent.go` create secure agent configurations
- **AppRole Authentication**: Uses consistent `shared.AppRoleName` for AppRole credential paths (without trailing newlines)
- **Systemd Integration**: Runtime directories managed via tmpfiles.d configuration at `/etc/tmpfiles.d/eos.conf`
- **TLS Security**: Automatic CA certificate validation before agent startup
- **Enhanced Error Handling**: Comprehensive logging and troubleshooting capabilities

#### Systemd Integration
The agent service includes robust systemd integration with proper EOS paths:
```bash
# Runtime directory creation via tmpfiles.d
/etc/tmpfiles.d/eos.conf:
d /run/eos 0755 eos eos -

# Service unit configuration
[Unit]
Description=Vault Agent (Eos)
After=network.target

[Service]
User=eos
Group=eos
RuntimeDirectory=eos
RuntimeDirectoryMode=0700
Environment=VAULT_SKIP_HCP=true
Environment=VAULT_SKIP_TLS_VERIFY=false
ExecStart=vault agent -config=/etc/vault-agent-eos.hcl
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

#### AppRole Configuration
Agent authentication uses AppRole with secure credential handling:
- **Role ID Path**: `/var/lib/eos/secret/role_id` (no trailing newlines)
- **Secret ID Path**: `/var/lib/eos/secret/secret_id` (no trailing newlines)
- **Token Output**: `/run/eos/vault_agent_eos.token`
- **Agent Config**: `/etc/vault-agent-eos.hcl`
- **CA Certificate**: `/home/eos/.config/vault/ca.crt`
- **Credential Persistence**: `remove_secret_id_file_after_reading = false` prevents consumption issues

#### Agent Configuration Template
The agent uses a secure HCL configuration without unnecessary listeners:
```hcl
vault {
  address = "https://hostname:8179"
  tls_ca_file = "/home/eos/.config/vault/ca.crt"
}

auto_auth {
  method "approle" {
    config = {
      role_id_file_path   = "/var/lib/eos/secret/role_id"
      secret_id_file_path = "/var/lib/eos/secret/secret_id"
      remove_secret_id_file_after_reading = false
    }
  }
  sink "file" { 
    config = { 
      path = "/run/eos/vault_agent_eos.token" 
    } 
  }
}
```

#### Troubleshooting Agent Issues
The system includes enhanced troubleshooting with automatic systemd log collection:

**Service Fails to Start**:
- Check CA certificate: `ls -la /home/eos/.config/vault/ca.crt`
- Verify runtime directory: `ls -ld /run/eos`
- Check service status: `systemctl status vault-agent-eos`
- Review agent config: `cat /etc/vault-agent-eos.hcl`

**Authentication Failures**:
- Verify AppRole credentials exist: `ls -la /var/lib/eos/secret/role_id /var/lib/eos/secret/secret_id`
- Check for trailing newlines: `hexdump -C /var/lib/eos/secret/role_id` (should not end with 0a)
- Test AppRole auth: `vault auth -method=approle role_id=$(cat /var/lib/eos/secret/role_id) secret_id=$(cat /var/lib/eos/secret/secret_id)`
- Review detailed logs: `journalctl -u vault-agent-eos --no-pager -n 50`

**Token Issues**:
- Check token file exists: `ls -la /run/eos/vault_agent_eos.token`
- Verify token validity: `curl -k -H "X-Vault-Token: $(cat /run/eos/vault_agent_eos.token)" https://hostname:8179/v1/auth/token/lookup-self`
- Monitor token renewal: `journalctl -u vault-agent-eos -f`

**Permission Errors**:
- Ensure vault user ownership: `chown -R vault:vault /etc/vault/`
- Verify tmpfiles.d configuration: `systemd-tmpfiles --create`
- Check selinux contexts if enabled: `restorecon -R /etc/vault/`

## Directory Structure

```
pkg/vault/
├── README.md                    # This documentation
├── hardening.go                 # System and Vault hardening
├── mfa.go                      # Multi-factor authentication
├── secure_init_reader.go       # Secure init data access
├── lifecycle1_create.go        # Vault installation
├── lifecycle2_enable.go        # Interactive setup
├── phase11_write_policies.go   # Policy management
├── phase13_write_agent_config.go # Vault Agent configuration
├── phase14_start_agent_and_validate.go # Agent lifecycle management
├── phase15_harden.go          # Final hardening
├── agent.go                   # Agent operations and validation
├── agent_lifecycle.go         # Agent service lifecycle management
├── util_read.go               # Data reading utilities
├── vault_client.go            # Client management
└── vault_auth.go              # Authentication setup
```

## Integration Points

### System Integration
- **Directory Structure**: Uses `/var/lib/eos/secrets` as fallback storage
- **Service Management**: Integrates with systemd for Vault service
- **Logging**: Structured logging to `/var/log/eos` with audit trails
- **Permissions**: Secure file permissions and ownership management

### CLI Integration
- **Commands**: Integrated with `eos create`, `eos enable`, `eos secure`, and `eos read`
- **Flags**: Comprehensive flag support for security and operational control
- **Error Handling**: Consistent error patterns with user-friendly messages
- **Progress Indication**: Clear progress reporting during operations

## Development Notes

### Error Handling
Use `eos_err.IsExpectedUserError()` to distinguish between user errors and system errors. All functions should return wrapped errors with context.

### Logging
Use structured logging with `otelzap.Ctx(rc.Ctx)` for all operations. Include relevant context fields for debugging and audit purposes.

### Security Considerations
- All sensitive data should be redacted in logs using `crypto.Redact()`
- File operations should use secure permissions (0600 for secrets, 0640 for configs)
- User confirmation is required for operations that expose sensitive data
- Access to initialization data requires audit logging with reason codes