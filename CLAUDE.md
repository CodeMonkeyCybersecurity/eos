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

### Enhanced Developer Logging Requirements
**CRITICAL**: Eos is a developer tool requiring comprehensive visibility into all operations. Every function MUST provide detailed logging:

#### Mandatory Logging Elements
1. **User Context**: Who is running the command, where, and how
2. **Command Execution**: What commands are run, with arguments and timing
3. **File Operations**: Paths, permissions, sizes, and validation status
4. **Progress Indicators**: Detailed metrics, counts, and durations
5. **Resource Discovery**: What was found, skipped, or failed
6. **Error Context**: Actionable troubleshooting information

#### Required Logging Patterns
Every function MUST log at appropriate levels with structured fields:

```go
// Function entry with context
logger.Info("🔍 Starting [operation]", 
    zap.String("user", os.Getenv("USER")),
    zap.String("pwd", pwd),
    zap.String("command_line", strings.Join(os.Args, " ")),
    zap.String("function", "functionName"))

// File operations (ALWAYS log file paths immediately when determined)
logger.Info("📁 Output file determined",
    zap.String("file_path", outputPath),
    zap.String("format", format),
    zap.String("directory", outputDir),
    zap.Bool("exists", fileExists),
    zap.Bool("writable", isWritable))

// Command execution (MUST be INFO level, not DEBUG)
logger.Info("🔧 Executing command",
    zap.String("command", cmdName),
    zap.Strings("args", args),
    zap.Duration("timeout", timeout))

// Command completion with metrics
logger.Info("✅ Command completed",
    zap.String("command", cmdName),
    zap.Duration("duration", elapsed),
    zap.Int("output_lines", lineCount),
    zap.Int64("output_bytes", byteCount),
    zap.Int("exit_code", exitCode))

// Discovery results with detailed metrics
logger.Info("✅ [Resource] discovery completed",
    zap.Int("containers", containerCount),
    zap.Int("running", runningCount),
    zap.Int("networks", networkCount),
    zap.Int("volumes", volumeCount),
    zap.Duration("duration", elapsed))

// File creation with full details
logger.Info("📝 Writing [format] file",
    zap.String("file_path", outputPath),
    zap.Int("resources", resourceCount),
    zap.Int("providers", providerCount))

// File completion with validation
logger.Info("✅ File written successfully",
    zap.String("file_path", outputPath),
    zap.String("size", humanReadableSize),
    zap.String("permissions", permissions),
    zap.String("validation", "passed"))

// Operation completion with summary
logger.Info("✨ [Operation] complete",
    zap.Duration("total_duration", totalElapsed),
    zap.String("output_file", outputPath),
    zap.Int("resources_found", totalResources),
    zap.Int("phases_completed", phaseCount))
```

#### Error Logging Requirements
All errors MUST include actionable context:

```go
logger.Error("❌ [Operation] failed",
    zap.Error(err),
    zap.String("command", failedCommand),
    zap.Strings("args", args),
    zap.String("working_dir", pwd),
    zap.String("user", user),
    zap.String("troubleshooting", "Check permissions and ensure Docker is running"),
    zap.String("phase", currentPhase))
```

#### Debug vs Info Level Guidelines
- **INFO**: All user-facing operations, file paths, command execution, progress, results
- **DEBUG**: Internal state, variable values, detailed parsing
- **WARN**: Non-fatal issues, fallbacks, missing optional components
- **ERROR**: Failures requiring user attention

#### Timing Requirements
Every operation MUST include timing information:
- Command execution duration
- Phase completion time
- Total operation time
- File I/O timing

#### Structured Logging Examples
```go
// ✅ CORRECT - Use structured logging for all output
logger := otelzap.Ctx(rc.Ctx)
logger.Info("🔄 Starting certificate renewal process")
logger.Info("✅ Certificate renewal completed", zap.String("method", "k3s"), zap.Duration("duration", time.Since(start)))
logger.Warn("⚠️ Configuration file not found", zap.String("path", configPath), zap.Error(err))
logger.Error("❌ Operation failed", zap.String("operation", "deploy"), zap.Error(err))

// ❌ WRONG - Never use fmt package for output
fmt.Println("Starting process...")
fmt.Printf("Error: %v\n", err)
fmt.Fprintf(os.Stderr, "Warning: %s\n", message)
```

### System Directory Structure
Eos creates and manages the following system directories during installation:

#### Core System Directories
- **`/var/lib/eos/secrets`** - Local secrets storage (fallback when Vault is unavailable)
- **`/etc/eos`** - Configuration files and system settings
- **`/var/log/eos`** - Application logs and audit trails
- **`/usr/local/bin/eos`** - Main executable binary location
- **`/run/eos`** - Runtime directory for Vault Agent tokens and temporary files (managed by `/etc/tmpfiles.d/eos.conf`)

#### Directory Usage Patterns
- **Secrets Management**: Primary secrets are stored in HashiCorp Vault when available. The `/var/lib/eos/secrets` directory serves as a secure fallback for local secrets storage when Vault is inaccessible or not yet configured.
- **Configuration**: System-wide configuration files are stored in `/etc/eos` with appropriate permissions
- **Logging**: All Eos operations log to `/var/log/eos` with structured logging format
- **Permissions**: System directories are created with secure permissions (750/640) and appropriate ownership

#### Vault Integration
Eos provides comprehensive HashiCorp Vault integration with enhanced security:
```bash
# Complete Vault deployment with security hardening
eos create vault    # Install Vault
eos enable vault    # Interactive setup with MFA
eos secure vault    # Apply comprehensive security hardening
```

**Vault Security Features**:
- Multi-Factor Authentication (TOTP, Duo, PingID, Okta)
- Role-based access control with principle of least privilege
- Comprehensive system hardening (swap disable, firewall, SSH hardening)
- Automated audit logging and backup procedures
- Safe root token revocation with alternative auth verification
- Network security and rate limiting configurations

**Vault Agent Integration**:
- Automatic token renewal and authentication (no caching by default for security)
- AppRole authentication with secure credential handling (no trailing newlines in credential files)
- Systemd integration with tmpfiles.d runtime directory management (`/etc/tmpfiles.d/eos.conf`)
- Secure agent configuration generation without unnecessary TCP listeners
- Enhanced error handling with automatic systemd log collection for troubleshooting
- Persistent credential configuration (`remove_secret_id_file_after_reading = false`)

For detailed Vault functionality including Vault Agent configuration, secure init data access, policy validation, and security features, see `pkg/vault/README.md`.

### Documentation Maintenance
When making changes to Eos functionality:
1. **Update CLAUDE.md** - Always update this file when adding new commands, packages, or workflows that affect the entire project
2. **Create modular documentation** - For specific functionality, create README.md files in the relevant directories:
   - File/function-specific documentation goes in local README.md files
   - User guides and specific design notes belong in their respective directories
   - Only project-wide architectural changes belong in CLAUDE.md
3. **Update CLI help text** - Ensure command descriptions and examples in code match actual functionality
4. **Document new dependencies** - Add any new external tools or libraries to the relevant sections
5. **Keep examples current** - Update code examples when command syntax or behavior changes

#### Documentation Structure Guidelines
- **CLAUDE.md**: Project-wide architecture, development commands, and global patterns
- **Directory README.md**: Specific to functionality within that directory
- **Function documentation**: In-code comments and local README files
- **User guides**: In the most relevant directory (e.g., `cmd/` for command usage)

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