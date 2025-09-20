# EOS Infrastructure Compiler

> **📝 Documentation has been moved inline with the code for better maintainability.**
> 
> The comprehensive documentation for the EOS Infrastructure Compiler is now embedded directly in the Go source files where the functionality is implemented. This ensures the documentation stays current with code changes and is immediately available to developers.

## Quick Reference

For detailed documentation, see the inline comments in these files:

- **Bootstrap System**: `pkg/bootstrap/check.go` - Machine preparation and validation
- **Storage Management**: `pkg/storage/interfaces.go` - Unified storage interface and architecture
- **Security Hardening**: `pkg/security/hardening.go` - Comprehensive security measures
- **User Management**: `pkg/users/management.go` - User lifecycle and SSH management
- **Vault Integration**: `pkg/vault/client.go` - Secure credential management

## Core Philosophy

EOS is a thin wrapper around powerful infrastructure tools that acts as a human-friendly infrastructure compiler. It translates imperative human commands into declarative infrastructure state.

### Core Architecture Flow
```
Human Intent (Imperative) → Eos CLI →  (Declarative) → Terraform (Resource Provisioning) → Nomad (Container Runtime)
```

### Key Principles
- **Human-First Interface**: Users think in actions ("create", "resize", "deploy"), not states
- **Declarative Under the Hood**: All imperative commands compile to declarative configurations
- **Multi-System Orchestration**: Single commands orchestrate across multiple systems seamlessly

## Quick Examples

```bash
# Bootstrap system preparation
eos bootstrap

# Deploy services with full orchestration
eos create mattermost --domain chat.company.com
eos create nomad --server --bootstrap-expect 3

# Secure infrastructure management
eos create vault && eos enable vault && eos secure vault
```

---

> **💡 For comprehensive architecture documentation, design patterns, and implementation details, see the inline documentation in the source files listed above.**