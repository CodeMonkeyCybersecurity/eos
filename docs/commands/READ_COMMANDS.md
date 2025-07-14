# Read Commands

*Last Updated: 2025-01-14*

This directory contains commands for reading, inspecting, and retrieving information from various system resources, services, and infrastructure components. These commands provide comprehensive visibility into system state, configurations, and operational data.

## Overview

The `read` command serves as the parent command for all inspection and data retrieval operations in Eos. It provides a unified interface for accessing information across different domains including system resources, cloud infrastructure, authentication services, and security tools.

**Usage:** `eos read <subcommand> [flags]`

**Aliases:** `inspect`, `get`, `query`, `verify`

## Commands

### System and Infrastructure

#### `infra`
Performs comprehensive infrastructure auditing across multiple domains.

**Usage:** `eos read infra [flags]`

**Features:**
- System information (CPU, memory, disk, network)
- Docker containers and configurations
- KVM/Libvirt virtual machines
- Hetzner Cloud resources
- Service configurations (nginx, databases, etc.)

**Flags:**
- `--terraform`: Output in Terraform format (.tf) instead of YAML
- `--output <path>`: Custom output path (default: `/etc/eos/<date>_<hostname>_infra_status.<ext>`)

**Examples:**
```bash
# Generate YAML infrastructure report
eos read infra

# Generate Terraform configuration
eos read infra --terraform

# Custom output location
eos read infra --output /tmp/infra-audit.yml
```

#### `process`
Retrieve detailed information about running processes.

**Usage:** `eos read process`

**Description:** Reads `/proc` directory and outputs detailed process information in table format including PID, PPID, command, CPU usage, and memory statistics.

#### `users`
Retrieve information about system users.

**Usage:** `eos read users`

**Description:** Reads `/etc/passwd` file and displays all system users with their associated information.

#### `logs`
Inspect Eos application logs (requires root or eos privileges).

**Usage:** `eos read logs`

**Description:** Displays the last 100 lines of recent Eos logs. Searches known log file locations first, falls back to journalctl if no log files found.

**Security:** Requires root or 'eos' user privileges for log access.

#### `storage`
Inspect storage configurations and usage.

**Usage:** `eos read storage`

**Description:** Provides detailed information about disk usage, mount points, and storage configurations.

#### `smartctl`
Read SMART disk health information.

**Usage:** `eos read smartctl`

**Description:** Retrieves disk health information using SMART monitoring tools.

### Authentication and Identity Services

#### `authentik`
Export Authentik blueprints to YAML format.

**Usage:** `eos read authentik [flags]`

**Flags:**
- `--ak-url <url>`: Base URL (required, can use AK_URL env var)
- `--ak-token <token>`: API token (required, can use AK_TOKEN env var)
- `--out <path>`: Override output path

**Examples:**
```bash
# Export with environment variables
AK_URL=https://id.dev.local AK_TOKEN=$(cat /run/secrets/ak_pat) eos read authentik

# Export with flags
eos read authentik --ak-url https://id.dev.local --ak-token $AK_TOKEN

# Custom output location
eos read authentik --ak-url https://id.dev.local --ak-token $AK_TOKEN --out /tmp/authentik.yaml
```

#### `keycloak`
Export Keycloak realm configuration to JSON format.

**Usage:** `eos read keycloak [flags]`

**Flags:**
- `--realm <name>`: Realm name (required)
- `--kc-admin-url <url>`: Admin base URL (can use KC_ADMIN_URL env var)
- `--kc-token <token>`: Bearer token (can use KC_ADMIN_TOKEN env var)
- `--clients`: Include clients (default: true)
- `--groups-roles`: Include groups & roles (default: true)
- `--out <path>`: Override output path

**Examples:**
```bash
# Export realm with environment variables
KC_ADMIN_URL=https://sso.dev.local KC_ADMIN_TOKEN=$(cat /run/secrets/kc_token) eos read keycloak --realm demo

# Export with custom settings
eos read keycloak --realm production --kc-admin-url https://keycloak.prod.local --kc-token $KC_TOKEN --out /backup/keycloak-realm.json
```

#### `ldap`
Inspect LDAP directory information.

**Usage:** `eos read ldap`

**Description:** Retrieves and displays LDAP directory structure, users, groups, and configuration information.

### HashiCorp Vault Integration

#### `vault`
Inspect Vault paths and secrets using enhanced architecture.

**Usage:** `eos read vault`

**Description:** Lists secrets stored in Vault using clean architecture patterns with enhanced dependency injection and graceful fallback when Vault is unavailable.

#### `vault-init`
Securely inspect Vault initialization data with comprehensive status.

**Usage:** `eos read vault-init [flags]`

**Flags:**
- `--no-redact`: Show sensitive data in plaintext (requires confirmation)
- `--export <format>`: Export format: console, json, secure
- `--status-only`: Show only Vault status information (no sensitive data)
- `--output <path>`: Output file path for export formats
- `--reason <text>`: Access reason for audit logging
- `--no-confirm`: Skip confirmation prompts (use with caution)

**Security Features:**
- Access control and user verification
- Optional sensitive data redaction
- Comprehensive audit logging
- File integrity verification
- Current Vault status integration

**Examples:**
```bash
# Secure read with redaction
sudo eos read vault-init

# Show plaintext (requires confirmation)
sudo eos read vault-init --no-redact

# Export to JSON
sudo eos read vault-init --export json --output /secure/vault-init.json

# Status only (no sensitive data)
eos read vault-init --status-only
```

#### `vault agent`
Check Vault Agent comprehensive status and functionality.

**Usage:** `eos read vault agent [flags]`

**Flags:**
- `--json`: Output status in JSON format for automation

**Features:**
- Service status and health
- Token availability and validity
- Configuration validation
- Monitoring status

**Examples:**
```bash
# Full status check
eos read vault agent

# JSON output for automation
eos read vault agent --json
```

#### `vault ldap`
View LDAP configuration stored in Vault.

**Usage:** `eos read vault ldap`

**Description:** Retrieves and displays LDAP configuration stored in Vault with sensitive fields properly redacted.

### Cloud Providers

#### `kvm`
Inspect KVM/libvirt virtual machines and configurations.

**Usage:** `eos read kvm`

**Description:** Provides comprehensive information about KVM virtual machines, networks, storage pools, and libvirt configurations.

### Specialized Tools

#### `ollama`
Inspect Ollama AI model configurations and status.

**Usage:** `eos read ollama`

**Description:** Retrieves information about installed Ollama models, configurations, and service status.

## Architecture and Design

### Command Structure
All read commands follow consistent patterns:

- **Cobra CLI Framework**: Structured command hierarchy with proper flag handling
- **Runtime Context**: All commands use `*eos_io.RuntimeContext` for cancellation, timeouts, and structured logging
- **Error Handling**: Comprehensive error handling using `eos.Wrap()` and structured logging
- **Security Controls**: Privilege checking for sensitive operations using `eos_unix.IsPrivilegedUser()`

### Logging Standards
Commands implement comprehensive structured logging:

- **OpenTelemetry Integration**: Full tracing and observability
- **Progress Updates**: Detailed logging of discovery phases and timing
- **Error Context**: Actionable troubleshooting information
- **Resource Metrics**: Counts, sizes, and status information

### Security Features

#### Access Control
- **Privilege Verification**: Commands accessing sensitive data require appropriate privileges
- **Secret Redaction**: Sensitive information is masked by default using `crypto.Redact()`
- **Audit Logging**: All access to sensitive resources is logged with context

#### Data Protection
- **Secure Defaults**: Sensitive fields masked unless explicitly requested
- **Confirmation Prompts**: Interactive confirmation for dangerous operations
- **Access Reasons**: Optional audit trail for sensitive access

### Output Formats
Commands support multiple output formats:

- **Console**: Human-readable formatted output with structured logging
- **YAML**: Machine-readable YAML format for infrastructure data
- **JSON**: Structured JSON output for automation and integration
- **Terraform**: Infrastructure as Code format for Terraform integration

### Error Handling
Comprehensive error handling includes:

- **Configuration Errors**: Clear messages for missing or invalid configurations
- **Permission Errors**: Detailed permission and privilege error reporting
- **Network Issues**: Connection timeout and network error handling with troubleshooting tips
- **Service Availability**: Graceful handling of unavailable services with fallback options

### Dependencies

#### Core Eos Packages
- `pkg/eos_cli`: Command wrapping and runtime context
- `pkg/eos_io`: I/O operations and structured logging
- `pkg/eos_unix`: Unix system operations and privilege checking
- `pkg/inspect`: Infrastructure discovery and reporting

#### External Services
- `pkg/vault`: HashiCorp Vault integration
- `pkg/ldap`: LDAP directory services
- `pkg/delphi`: Wazuh security monitoring integration
- `pkg/exportutil`: Export utilities for various formats

#### System Tools
- Docker API for container information
- libvirt for KVM virtualization
- systemd for service management
- Hetzner Cloud API for cloud resources

### Development Guidelines

#### Adding New Read Commands
1. **Create Command File**: Add new `.go` file in `cmd/read/`
2. **Follow Patterns**: Use existing commands as templates for consistency
3. **Implement Security**: Add appropriate privilege checking for sensitive operations
4. **Structured Logging**: Use comprehensive structured logging throughout
5. **Error Handling**: Implement proper error handling with actionable messages
6. **Documentation**: Update this README.md with new command information

#### Testing
- **Unit Tests**: Test core functionality with mocked dependencies
- **Integration Tests**: Test end-to-end functionality with real services
- **Security Tests**: Verify privilege checking and access controls
- **Error Scenarios**: Test error handling and edge cases

### Examples and Use Cases

#### Infrastructure Auditing
```bash
# Complete infrastructure audit
eos read infra --output /audit/$(date +%Y%m%d)-infra.yml

# Terraform generation for IaC
eos read infra --terraform --output /terraform/current-state.tf
```

#### Security Monitoring
```bash
# Vault status check
eos read vault-init --status-only

# Check agent health
eos read vault agent --json | jq '.health_status'
```

#### Identity Management
```bash
# Export Authentik configuration
eos read authentik --out /backup/authentik-$(date +%Y%m%d).yaml

# Export Keycloak realm
eos read keycloak --realm production --out /backup/keycloak-prod.json
```

#### System Administration
```bash
# Process monitoring
eos read process | grep high-cpu-service

# User audit
eos read users | grep -E "(admin|root)"

# Log analysis
sudo eos read logs | tail -50
```