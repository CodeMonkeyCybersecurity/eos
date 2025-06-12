# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Eos** is a Go-based CLI application for Ubuntu server administration developed by Code Monkey Cybersecurity. It provides automation, orchestration, and hardening capabilities for users who need simplified server management.

## Development Commands

### Building and Installation
```bash
# Build the application
go build -o eos .

# Install dependencies
go mod tidy

# Install using the provided script
./install.sh

# Manual installation after build
sudo cp eos /usr/local/bin/
```

### Testing
```bash
# Run all tests
go test ./...

# Specific test files exist in:
# - pkg/crypto/fuzz_test.go
# - pkg/parse/fuzz_test.go 
# - pkg/delphi/provision_test.go
# - pkg/interaction/fuzz_test.go
```

## Architecture

### CLI Structure (Cobra Framework)
The application uses Cobra CLI with the following command hierarchy:
- **CRUD Operations**: create, read, update, delete, list
- **Infrastructure Management**: vault, k3s, docker, ldap, jenkins
- **Security Tools**: delphi (monitoring), hecate (reverse proxy)
- **System Operations**: backup, sync, refresh, secure, config

### Core Packages (`pkg/`)
- **eos_cli/**: CLI wrapper utilities and command execution
- **eos_io/**: I/O operations and runtime context management
- **eos_err/**: Centralized error handling
- **eos_unix/**: Unix system operations
- **vault/**: HashiCorp Vault integration
- **container/**: Docker container management
- **delphi/**: Security monitoring platform
- **hecate/**: Reverse proxy management
- **hetzner/**: Hetzner cloud provider integration
- **kvm/**: KVM virtualization management
- **ldap/**: LDAP directory operations

### Entry Points
- **main.go**: Creates runtime context and executes root command
- **cmd/root.go**: Cobra CLI setup with command registration and global watchdog

### Key Dependencies
- Cobra CLI framework for commands
- HashiCorp Vault API for secrets management
- Docker client for container operations
- LDAP client for directory services
- Hetzner Cloud API for infrastructure
- PostgreSQL driver with GORM ORM
- OpenTelemetry for observability
- Zap for structured logging

### Supporting Infrastructure
- **ansible/** - Ansible playbooks for automation
- **assets/** - Python workers, services, and configurations  
- **scripts/** - Shell scripts for various operations
- **policies/** - Policy definitions (OPA Rego, CUE, YAML)
- **sql/** - Database schemas and SQL dumps
- **templates/** - Email and service templates

## Important Notes

### Runtime Context
All commands use `*eos_io.RuntimeContext` which provides:
- Context for cancellation and timeouts
- Structured logging with OpenTelemetry integration
- Global watchdog timer (3-minute default timeout)

### Error Handling
Use `eos_err.IsExpectedUserError()` to distinguish between user errors and system errors. User errors exit with code 0, system errors with code 1.

### Command Wrapping
All command implementations should use `eos.Wrap()` to properly handle the runtime context and error patterns.

### External References
- Knowledge base: [Athena](https://wiki.cybermonkey.net.au)
- Company website: [cybermonkey.net.au](https://cybermonkey.net.au/)
- Contact: main@cybermonkey.net.au

### Code Conventions
- Use structured logging with `otelzap.Ctx(rc.Ctx)`
- Follow Go module structure with clear package separation
- Implement proper context handling for cancellation
- Use the established error handling patterns