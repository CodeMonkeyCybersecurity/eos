# Vault Package Documentation

> ** Documentation has been moved inline with the code for better maintainability.**
> 
> The comprehensive documentation for the Vault package is now embedded directly in the Go source files where the functionality is implemented. This ensures the documentation stays current with code changes and is immediately available to developers.

## Quick Reference

For detailed documentation, see the inline comments in these files:

- **Core Client**: `pkg/vault/client.go` - Main Vault client with comprehensive security features
- **Security & Hardening**: `pkg/vault/hardening.go` - System and Vault hardening
- **MFA**: `pkg/vault/mfa.go` - Multi-factor authentication (TOTP, Duo, PingID, Okta)
- **Lifecycle Management**: `pkg/vault/lifecycle1_create.go`, `pkg/vault/lifecycle2_enable.go`
- **Policy Management**: `pkg/vault/phase11_write_policies.go` - Role-based access control
- **Agent Configuration**: `pkg/vault/agent.go` - Vault Agent with systemd integration

## Quick Start

```bash
# Complete Vault deployment
eos create vault    # Install Vault
eos enable vault    # Interactive setup with MFA
eos secure vault    # Apply comprehensive hardening

# Secure data access
sudo eos read vault-init                    # With redaction (recommended)
sudo eos read vault-init --status-only     # Status overview only
```

## Key Features

- **Multi-Factor Authentication**: TOTP, Duo, PingID, Okta support
- **Comprehensive Hardening**: System-level security with swap/coredump disabling
- **Role-Based Access Control**: Four policy levels with principle of least privilege
- **Secure Agent Integration**: AppRole authentication with systemd integration
- **Audit Logging**: Comprehensive logging with sensitive data redaction

---

> ** For comprehensive documentation, configuration examples, troubleshooting guides, and security considerations, see the inline documentation in the source files listed above.**