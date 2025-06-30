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

# Run fuzz tests for security validation
./scripts/run-fuzz-tests.sh          # Run all fuzz tests (10s each)
./scripts/run-fuzz-tests.sh 30s      # Run with custom duration

# Run specific fuzz tests manually
go test -run=^FuzzValidateStrongPassword$ -fuzz=^FuzzValidateStrongPassword$ -fuzztime=10s ./pkg/crypto
go test -run=^FuzzNormalizeYesNoInput$ -fuzz=^FuzzNormalizeYesNoInput$ -fuzztime=10s ./pkg/interaction

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

### Development Principles
- Code needs to be modular and universal and as dont-repeat-yourself (DRY) as possible.
- **Modular Architecture**: All helper functions need to go in the `pkg/` directory, with files and functions in the `cmd/` directory only really to call up / orchestrate the individual helper functions. This is an effort to make the code as unified, modular and DRY as possible.

### Runtime Context
All commands use `*eos_io.RuntimeContext` which provides:
- Context for cancellation and timeouts
- Structured logging with OpenTelemetry integration
- Global watchdog timer (3-minute default timeout)

### Error Handling
Use `eos_err.IsExpectedUserError()` to distinguish between user errors and system errors. User errors exit with code 0, system errors with code 1.

### Command Wrapping
All command implementations should use `eos.Wrap()` to properly handle the runtime context and error patterns.

### Code Quality Requirements
**CRITICAL**: Before any task can be considered completed by Claude, the following requirements MUST be met:

1. **Zero Compilation Errors**: The code must compile successfully without any errors throughout the entire codebase
2. **Linting Standards**: Run `golangci-lint run` and the code MUST pass all linting checks without warnings or errors
3. **Test Compliance**: The code MUST pass all existing test modules relevant to the changes made
4. **Fix Code, Not Tests**: When tests fail, the production code must be corrected unless the test is clearly invalid or unreliable
5. **Verification Commands**: Before marking a task complete, run:
   ```bash
   # Verify compilation
   go build -o /tmp/eos-build ./cmd/
   
   # Verify linting
   golangci-lint run
   
   # Verify tests
   go test -v ./pkg/...
   ```

**No task should be marked as complete until ALL of these verification steps pass successfully.**

### External References
- Knowledge base: [Athena](https://wiki.cybermonkey.net.au)
- Company website: [cybermonkey.net.au](https://cybermonkey.net.au/)
- Contact: main@cybermonkey.net.au

### Code Conventions
- **CRITICAL**: Use ONLY structured logging with `otelzap.Ctx(rc.Ctx)` - NEVER use fmt.Printf, fmt.Println, fmt.Fprintf, fmt.Print, or any fmt package output functions
- **CRITICAL**: ALL user-facing output MUST go through structured logging - no exceptions
- **CRITICAL**: This is a developer tool - prioritize debugging information over pretty output formatting
- **CRITICAL**: Use zap.Error(), zap.String(), zap.Any(), zap.Int(), zap.Bool() etc. for all log fields - structured logging is mandatory
- **CRITICAL**: Interactive prompts and user input should use appropriate logging levels (Info for prompts, Warn for important notices)
- **CRITICAL**: Status updates, progress information, and results MUST use structured logging with appropriate fields
- Follow Go module structure with clear package separation
- Implement proper context handling for cancellation
- Use the established error handling patterns
- Verbose logging is preferred for debugging - add extensive structured logging to help troubleshoot issues

### Port Management Convention
[... rest of the existing content remains unchanged ...]