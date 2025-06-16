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
├── phase15_harden.go          # Final hardening
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