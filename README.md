# Eos - Ubuntu Server Administration Made Simple

*Last Updated: 2025-01-23*

**Eos** is a powerful Go-based CLI tool that simplifies Ubuntu server administration through automation, orchestration, and security hardening. Built by Code Monkey Cybersecurity, Eos transforms complex server management tasks into simple, reliable commands.

## Philosophy

Eos embodies **"Solve problems once, encode in Eos, never solve again"**:

- **Human-Centric**: Technology serves humans with actionable output, informed consent, and barriers-to-entry reduction
- **Evidence-Based**: Decisions grounded in security research and best practices with adversarial collaboration
- **Sustainable Innovation**: Maintainable code, comprehensive documentation, iterative improvement
- **Iterative Evolution**: Build on what exists, enhance rather than replace, encode solutions permanently

## Overview

Eos provides a comprehensive suite of tools for:
- **Infrastructure Automation**: Deploy and manage HashiCorp stack (Vault, Consul, Nomad), Kubernetes (K3s), Ceph storage, and virtualization (KVM)
- **Security Hardening**: Implement fail2ban, LDAP/Authentik authentication, Vault secrets management, Wazuh SIEM, and Boundary access control
- **AI/ML Services**: Deploy BionicGPT, OpenWebUI, Ollama, n8n automation, and LiteLLM gateway
- **Service Orchestration**: Manage web services (Mattermost, Penpot, Umami), databases, reverse proxies (Hecate), and monitoring (Grafana, Temporal)
- **System Administration**: Handle backups, user management, configuration drift correction, and system maintenance
- **Storage Management**: Ceph, ZFS, LVM, Btrfs with automatic drift detection and correction

## Key Features

- **Verb-First Architecture**: Intuitive command structure (`eos create`, `eos read`, `eos update`, `eos delete`, `eos list`)
- **Built-in Safety**: Assess → Intervene → Evaluate pattern ensures reliable, idempotent operations
- **Configuration Drift Correction**: Automated detection and correction with `eos update <service> --fix`
- **Secrets Management**: Integrated HashiCorp Vault with automatic secret generation and rotation
- **Service Discovery**: Consul-based service registry with health checking and KV configuration
- **Interactive Prompts**: Informed consent model - explain dependencies, show install commands, ask permission
- **Comprehensive Diagnostics**: 13+ debug commands with automatic evidence capture and root cause analysis
- **Structured Logging**: OpenTelemetry integration with context-aware logging (`otelzap`)
- **Error Recovery**: Intelligent error detection - retry transient failures, fail fast on configuration errors
- **SDK-First Approach**: Use official SDKs (go-ceph, Docker SDK, HashiCorp APIs) over shell commands

## Quick Start

### Prerequisites
- Ubuntu 24.04+ (primary target, also tested on Ubuntu 22.04/24.04)
- Go 1.25 or higher
- Root/sudo access for system operations
- Git for cloning the repository

### Installation

```bash
# Elevate to root
sudo -i

# Clone the repository
cd /opt
git clone https://github.com/CodeMonkeyCybersecurity/eos.git
cd eos

# Run the installation script
./install.sh

# Verify installation
eos --help
```

The install script will:
1. Build the Eos binary
2. Install to `/usr/local/bin/eos`
3. Create necessary directories (`/etc/eos`, `/var/log/eos`)
4. Set up runtime context


## Usage Examples

```bash
# Get the latest version
eos self update
```

```bash
# List available commands
eos --help
```

### Create Infrastructure

```bash
# HashiCorp Stack
eos create vault              # Secrets management with auto-unsealing
eos create consul             # Service discovery and configuration
eos create nomad              # Container and kvm orchestration

# Storage
eos create ceph               # Distributed storage cluster
eos create kvm --name=myvm    # Virtual machine

# Security
eos create fail2ban           # Intrusion prevention
eos create authentik          # Identity provider
eos create wazuh              # SIEM and threat detection

# AI/ML Services
eos create bionicgpt          # Private AI assistant with RAG
eos create ollama             # Local LLM runtime

# Web Services
eos create mattermost         # Team collaboration
eos create hecate             # Reverse proxy (Caddy-based)
eos create umami              # Privacy-focused analytics
```

### Debug and Diagnostics

```bash
# Run diagnostics (auto-captures to ~/.eos/debug/)
eos debug vault               # Vault health, auth, policies
eos debug consul              # Consul cluster health
eos debug ceph                # Ceph cluster status with root cause analysis
eos debug bionicgpt           # AI service diagnostics

# Check specific components
eos debug vault --mode=agent  # Vault agent-specific checks
eos debug vault --mode=auth   # Authentication diagnostics
```

### Configuration Drift Correction

```bash
# Detect and fix configuration drift
eos update vault --fix         # Fix Vault permissions, config, duplicates
eos update consul --fix        # Fix Consul permissions and config
eos update ceph --fix          # Fix Ceph permissions and ownership

# Dry-run mode (check without fixing)
eos update vault --fix --dry-run
eos update ceph --fix --dry-run

# DEPRECATED (use update --fix instead):
# eos fix vault   → eos update vault --fix
# eos fix consul  → eos update consul --fix
```

### List Resources

```bash
# List environments and services
eos list env                  # Show all environments
eos list services             # Show managed services
eos list containers           # Docker containers

# Storage
eos list ceph pools           # Ceph storage pools
eos list kvm                  # Virtual machines
```

### Secrets Management

```bash
# Secrets are managed automatically via Vault
# When creating services, Eos:
# 1. Generates strong passwords/tokens
# 2. Stores in Vault at secret/<service>/<key>
# 3. Delivers via Vault Agent or Consul Template
# 4. Auto-rotates on template changes

# Manual secret operations
eos create credentials --service=myapp
eos update vault rotate-secrets --service=myapp
```


## Architecture

Eos follows a strict **separation of concerns** between orchestration and business logic:

```
cmd/                    # Command definitions (ORCHESTRATION ONLY)
├── create/            # Service creation commands (94 services)
├── read/              # Read/inspection commands
├── update/            # Modification commands (50+ including --fix)
├── delete/            # Deletion commands
├── list/              # Listing commands
├── debug/             # Diagnostic commands (13 services)
├── backup/            # Backup operations
├── restore/           # Restore operations
├── promote/           # Environment promotion
├── self/              # Eos self-management
└── sync/              # State synchronization

pkg/                    # Business logic (ALL actual work happens here)
├── eos_io/            # RuntimeContext, I/O utilities
├── eos_err/           # Error handling (UserError, SystemError)
├── secrets/           # Secret management abstraction
├── environment/       # Environment discovery
├── verify/            # Validation and safety checks
├── crypto/            # Cryptographic utilities
├── docker/            # Docker SDK integration
├── vault/             # HashiCorp Vault operations
├── consul/            # Consul operations
├── nomad/             # Nomad operations
├── ceph/              # Ceph storage management
├── cephfs/            # CephFS operations via go-ceph
├── bionicgpt/         # BionicGPT AI service
├── authentik/         # Authentik identity provider
├── wazuh/             # Wazuh SIEM
└── [100+ packages]    # Feature-specific business logic
```

### Design Principles

**1. Assess → Intervene → Evaluate Pattern**
```go
// All pkg/ functions follow this pattern
func RunOperation(rc *eos_io.RuntimeContext, config *Config) error {
    // ASSESS: Check current state
    currentState := assessSystem(rc)

    // INTERVENE: Apply changes if needed
    if !config.DryRun {
        results := applyChanges(rc, currentState)
    }

    // EVALUATE: Verify and report
    displayResults(rc, results)
    return nil
}
```

**2. Architecture Enforcement**
- `cmd/` files: <100 lines, flags + delegation only
- `pkg/` files: All business logic, file operations, loops
- Violation = refactor to pkg/

**3. Single Source of Truth**
- Constants in `pkg/[service]/constants.go` only
- Zero hardcoded values (paths, ports, IPs, permissions)
- Shared constants in `pkg/shared/`

## Development

### Building from Source

```bash
# Clone the repository
git clone https://github.com/CodeMonkeyCybersecurity/eos.git
cd eos

# Build
sudo ./install.sh
```

### Testing Requirements (P0 - CRITICAL)

Before marking any task complete:

```bash
# 1. Build must succeed
sudo ./install.sh

# 2. Code formatting must be clean
gofmt -l pkg/ cmd/
# (Should return nothing)

# 3. Vet must pass
go vet ./pkg/...
go vet ./cmd/...

# 4. Tests must pass
go test -v ./pkg/...

# 5. Linting (if available)
golangci-lint run
```

### Contributing

**Critical Rules (P0 - Breaking)**:
1. **Logging**: ONLY use `otelzap.Ctx(rc.Ctx)` - NEVER `fmt.Print*/Println`
2. **Architecture**: Business logic in `pkg/`, orchestration ONLY in `cmd/`
3. **Pattern**: ALWAYS follow Assess → Intervene → Evaluate
4. **Context**: Always use `*eos_io.RuntimeContext` for all operations
5. **Secrets**: Use `secrets.SecretManager` - NEVER hardcode credentials
6. **Constants**: Zero hardcoded values - use constants from `pkg/[service]/constants.go`
7. **Pre-commit**: Run `go build -o /tmp/eos-build ./cmd/` - zero tolerance for compile errors

See [CLAUDE.md](./CLAUDE.md) for comprehensive development guidelines and patterns.

### Code Review Checklist

Before submitting:
- [ ] Business logic is in `pkg/`, not `cmd/`
- [ ] All logging uses `otelzap.Ctx(rc.Ctx)`
- [ ] No hardcoded values (paths, ports, IPs, permissions)
- [ ] Secrets managed via SecretManager
- [ ] Follows Assess → Intervene → Evaluate pattern
- [ ] `go build -o /tmp/eos-build ./cmd/` succeeds
- [ ] `gofmt -l` returns nothing
- [ ] `go vet ./...` passes

## Key Technologies

- **Language**: Go 1.25+ (type safety, concurrency, single binary deployment)
- **Secrets Management**: HashiCorp Vault (KV v2, AppRole auth, auto-unsealing)
- **Service Discovery**: HashiCorp Consul (service registry, KV store, health checks)
- **Container Orchestration**: HashiCorp Nomad, Docker Compose, Kubernetes (K3s)
- **Storage**: Ceph (RBD, CephFS, RGW), ZFS, LVM, Btrfs
- **Observability**: OpenTelemetry, Grafana, Wazuh, structured logging (otelzap)
- **Identity**: Authentik, LDAP, HashiCorp Boundary
- **SDKs**: go-ceph, Docker SDK, HashiCorp APIs, Kubernetes client-go

## Documentation

- **Knowledge Base**: [Athena Wiki](https://wiki.cybermonkey.net.au) - Comprehensive guides and tutorials
- **Development Guide**: [CLAUDE.md](./CLAUDE.md) - Coding standards, patterns, critical rules
- **Pattern Library**: [PATTERNS.md](./docs/PATTERNS.md) - Code examples and best practices
- **Architecture**: [STACK.md](./STACK.md) - Design principles and technology stack

## Support

- **Email**: main@cybermonkey.net.au
- **Website**: [cybermonkey.net.au](https://cybermonkey.net.au)
- **GitHub Issues**: [Report bugs or request features](https://github.com/CodeMonkeyCybersecurity/eos/issues)
- **Community**: Join us on [Facebook](https://www.facebook.com/codemonkeycyber), [X/Twitter](https://x.com/codemonkeycyber), [LinkedIn](https://www.linkedin.com/company/codemonkeycyber)

## License

Eos is dual-licensed:
- **GNU Affero General Public License v3.0 (AGPL-3.0-or-later)**
- **Do No Harm License**

Both licenses apply. This ensures:
- Source code modifications must be shared (AGPL)
- Technology serves ethical purposes and human benefit (Do No Harm)
- Defensive security only - no offensive or malicious use

See [LICENSE](./LICENSE) for full details.

## Project Status

**Active Development** - Eos is under continuous improvement with:
- ✅ 94+ service integrations
- ✅ 13+ diagnostic commands
- ✅ Automated drift correction
- ✅ SDK-first architecture migration (ongoing)
- 🚧 Evidence collection infrastructure (planned integration)
- 🚧 Centralized constants audit (monthly)

Recent additions (January 2025):
- CephFS volume management via go-ceph SDK
- Configuration drift correction with `eos update --fix`
- Automatic debug output capture to `~/.eos/debug/`
- Enhanced Vault diagnostics with agent/auth modes
- Root cause analysis for Ceph diagnostics

## Why Eos?

**The Problem**: Modern infrastructure is complex. Setting up a production-grade server with Vault, Consul, monitoring, backups, and security hardening requires deep expertise across multiple domains.

**The Eos Solution**:
```bash
# Traditional approach: Days of research, configuration, debugging
# Eos approach:
eos create vault    # Production-ready Vault in minutes
eos create consul   # Service discovery configured
eos create wazuh    # SIEM monitoring enabled
eos debug vault     # Instant diagnostics with root cause analysis
```

**Result**: Infrastructure complexity becomes simple, reliable commands. Problems solved once, encoded in Eos, never solved again.

---

```bash
#       ___     _              __  __          _
#      / __|  _| |__  ___ _ _ |  \/  |___ _ _ | |_____ _  _  
#     | (_| || | '_ \/ -_) '_|| |\/| / _ \ ' \| / / -_) || |
#      \___\__,|_.__/\___|_|  |_|_ |_\___/_||_|_\_\___|\_, |
#          |__/                                        |__/
```

**Cybersecurity. With humans.**

© 2025 [Code Monkey Cybersecurity](https://cybermonkey.net.au/). ABN: 77 177 673 061. All rights reserved.