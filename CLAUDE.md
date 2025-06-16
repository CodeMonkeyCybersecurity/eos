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
# Run all unit tests with coverage
go test -v -coverprofile=coverage.out -covermode=atomic ./pkg/...

# Run integration tests
go test -v -timeout=5m ./integration_test.go ./integration_scenarios_test.go

# Generate coverage report
go tool cover -html=coverage.out -o coverage.html

# Run security-focused tests
go test -v -run "Security|Validation|Auth" ./pkg/...

# Run specific test files:
# - pkg/crypto/fuzz_test.go - Cryptographic fuzzing tests
# - pkg/parse/fuzz_test.go - Input parsing fuzzing tests
# - pkg/delphi/provision_test.go - Delphi provisioning tests
# - pkg/interaction/fuzz_test.go - User interaction fuzzing tests
# - pkg/eos_io/context_test.go - Runtime context tests
# - pkg/eos_cli/wrap_test.go - CLI wrapper tests
# - integration_test.go - End-to-end integration tests
# - integration_scenarios_test.go - Scenario-based integration tests
```

## Architecture

### CLI Structure (Cobra Framework)
The application uses Cobra CLI with the following command hierarchy:
- **CRUD Operations**: create, read, update, delete, list
- **Infrastructure Management**: vault, k3s, docker, ldap, jenkins
- **Security Tools**: delphi (monitoring), hecate (reverse proxy)
- **System Operations**: backup, sync, refresh, secure, config

#### HashiCorp Tools (HCL Command)
Install HashiCorp tools with official repository integration:
```bash
eos create hcl [terraform|vault|consul|nomad|packer|all]
```
See [docs/commands/hcl.md](docs/commands/hcl.md) for detailed documentation.

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

### Documentation Maintenance
When making changes to Eos functionality:
1. **Update CLAUDE.md** - Always update this file when adding new commands, packages, or workflows
2. **Create command documentation** - For new commands, create simple documentation explaining usage and examples
3. **Update CLI help text** - Ensure command descriptions and examples in code match actual functionality
4. **Document new dependencies** - Add any new external tools or libraries to the relevant sections
5. **Keep examples current** - Update code examples when command syntax or behavior changes

## CI/CD Pipeline

The project includes comprehensive GitHub Actions workflows for automated testing and quality assurance:

### Workflows
- **`.github/workflows/test.yml`** - Main testing pipeline with coverage reporting
- **`.github/workflows/lint.yml`** - Code linting and formatting checks
- **`.github/workflows/security.yml`** - Security testing and vulnerability scanning
- **`.github/workflows/quality-gates.yml`** - Quality gates for pull requests

### Testing Infrastructure
- **Unit Tests**: Comprehensive coverage for all core packages (pkg/eos_io, pkg/eos_cli, pkg/crypto, etc.)
- **Integration Tests**: End-to-end scenario testing with realistic workflows
- **Security Tests**: Validation of security improvements and input sanitization
- **Fuzz Tests**: Robust testing of input handling and cryptographic functions

### Quality Standards
- Minimum 70% test coverage required
- All tests must pass before merge
- Code must pass golangci-lint checks
- Security scans must complete without critical issues
- Integration tests validate real-world usage scenarios

### Test Framework
The project uses a custom integration testing framework in `pkg/testutil/` providing:
- Test environment orchestration
- Mock service management
- Scenario-based testing patterns
- Comprehensive error handling validation