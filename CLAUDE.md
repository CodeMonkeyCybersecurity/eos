# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Eos** is a Go-based CLI application for Ubuntu server administration developed by Code Monkey Cybersecurity. It provides automation, orchestration, and hardening capabilities for users who need simplified server management.

## Quick Reference

### Critical Patterns
- **Command Structure**: `cmd/create_[feature].go` → orchestrates → `pkg/[feature]/*.go` helpers
- **Logging**: **ONLY** use `otelzap.Ctx(rc.Ctx)` - **NEVER** use `fmt.Printf/Println/Print`
- **Error Handling**: User errors exit with code 0, system errors exit with code 1
- **Context**: Always pass `*eos_io.RuntimeContext` (3-minute default timeout)
- **Pattern**: Every helper follows **Assess → Intervene → Evaluate**

### Testing Checklist
Before marking any task complete:
```bash
go build -o /tmp/eos-build ./cmd/        # Must compile without errors
golangci-lint run                        # Must pass all linting checks
go test -v ./pkg/...                     # Must pass all tests
```

### Command Development Flow
1. Create command file: `cmd/create_[feature].go`
2. Create package directory: `pkg/[feature]/`
3. Implement helpers: `types.go`, `install.go`, `configure.go`, `verify.go`
4. Use `eos.Wrap()` for command execution
5. Test thoroughly before completion

## Architecture

### Architecture Patterns

#### Command Flow
The complete flow from user input to execution follows these steps:

1. **User Input**: `eos create saltstack --log-level=debug`
2. **Cobra Parsing**: Routes to `cmd/create_saltstack.go`
3. **Runtime Context**: Created with timeout and logging
4. **Orchestration**: Command calls helpers from `pkg/saltstack/`
5. **Helper Execution**: Each helper follows Assess → Intervene → Evaluate
6. **Error Handling**: Proper exit codes based on error type
7. **Cleanup**: Context cancellation and resource cleanup

#### Package Responsibility Boundaries
```
cmd/
├── create_*.go         # Command definitions ONLY - no business logic
├── root.go            # Root command setup and registration
└── [operation]_*.go   # Other operation commands

pkg/
├── eos_cli/           # CLI wrapper utilities
├── eos_io/            # RuntimeContext and I/O operations
├── eos_err/           # Error handling and classification
├── [feature]/         # Feature-specific business logic
│   ├── types.go       # Types, constants, configurations
│   ├── install.go     # Installation logic
│   ├── configure.go   # Configuration logic
│   └── verify.go      # Verification logic
└── shared/            # Shared utilities (ports, common functions)
```

#### The Assess → Intervene → Evaluate Pattern
Every helper function must follow this pattern:

```go
func PerformOperation(rc *eos_io.RuntimeContext, config *Config) error {
    logger := otelzap.Ctx(rc.Ctx)
    
    // ASSESS - Check if operation is possible
    logger.Info("Assessing prerequisites")
    if !canPerformOperation(rc) {
        return eos_err.NewUserError("prerequisites not met")
    }
    
    // INTERVENE - Perform the actual operation
    logger.Info("Executing operation")
    if err := doOperation(rc, config); err != nil {
        return fmt.Errorf("operation failed: %w", err)
    }
    
    // EVALUATE - Verify operation succeeded
    logger.Info("Verifying operation results")
    if err := verifyOperation(rc); err != nil {
        return fmt.Errorf("verification failed: %w", err)
    }
    
    logger.Info("Operation completed successfully")
    return nil
}
```

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

## Development

### Development Principles
- Code must be modular, universal, and follow DRY principles
- **Modular Architecture**: All business logic goes in `pkg/`, command files in `cmd/` only orchestrate
- **Runtime Context**: All operations use `*eos_io.RuntimeContext` for logging and cancellation
- **Error Handling**: Distinguish user errors (exit 0) from system errors (exit 1)
- **Verbose Logging**: Add extensive structured logging for debugging

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

### Code Convention Examples

#### Correct Logging Pattern
```go
// CORRECT - Using structured logging
func InstallPackage(rc *eos_io.RuntimeContext, pkgName string) error {
    logger := otelzap.Ctx(rc.Ctx)
    
    logger.Info("Installing package",
        zap.String("package", pkgName),
        zap.String("action", "install"),
        zap.String("phase", "start"))
    
    // ... installation logic ...
    
    logger.Info("Package installed successfully",
        zap.String("package", pkgName),
        zap.Duration("duration", time.Since(start)))
    
    return nil
}

// INCORRECT - Never do this!
func BadExample(pkgName string) error {
    fmt.Printf("Installing %s\n", pkgName)  // NEVER use fmt for output!
    return nil
}
```

#### Interactive Prompt Pattern
```go
func GetUserInput(rc *eos_io.RuntimeContext, config *Config) error {
    logger := otelzap.Ctx(rc.Ctx)
    
    if config.Username == "" {
        logger.Info("Username not provided via flag, prompting user")
        logger.Info("terminal prompt: Please enter username")
        
        username, err := eos_io.ReadInput(rc)
        if err != nil {
            return fmt.Errorf("failed to read username: %w", err)
        }
        config.Username = username
    }
    
    return nil
}
```

#### Command Implementation Pattern
```go
// cmd/create_saltstack.go
package cmd

import (
    "github.com/spf13/cobra"
    "your-repo/pkg/eos_cli"
    "your-repo/pkg/saltstack"
)

var createSaltstackCmd = &cobra.Command{
    Use:   "saltstack",
    Short: "Install and configure SaltStack",
    RunE: eos_cli.Wrap(runCreateSaltstack),
}

func init() {
    createCmd.AddCommand(createSaltstackCmd)
    
    createSaltstackCmd.Flags().Bool("master-mode", false, "Install as master-minion instead of masterless")
    createSaltstackCmd.Flags().String("log-level", "warning", "Salt log level")
}

func runCreateSaltstack(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    // Parse flags
    config := &saltstack.Config{
        MasterMode: cmd.Flag("master-mode").Value.String() == "true",
        LogLevel:   cmd.Flag("log-level").Value.String(),
    }
    
    // Orchestrate helpers from pkg/saltstack/
    if err := saltstack.Install(rc, config); err != nil {
        return err
    }
    
    if err := saltstack.Configure(rc, config); err != nil {
        return err
    }
    
    if err := saltstack.Verify(rc); err != nil {
        return err
    }
    
    return nil
}
```

### Port Management Convention
See `pkg/shared/ports.go` for ports for internal service allocation and discovery. Always use the centralized port definitions to avoid conflicts.

## Testing

### Testing Requirements

#### Unit Tests Required For:
- All public functions in `pkg/` directories
- Error handling paths and edge cases
- Input validation and sanitization
- Business logic transformations

#### Integration Tests Required When:
- Interacting with external systems (databases, APIs, file systems)
- Multi-step workflows that span multiple packages
- Command-level functionality testing
- Network operations or service deployments

#### Test Structure
```go
// pkg/saltstack/install_test.go
func TestInstallSaltstack(t *testing.T) {
    tests := []struct {
        name    string
        config  *Config
        setup   func()
        wantErr bool
    }{
        {
            name: "successful installation",
            config: &Config{MasterMode: false},
            setup: func() {
                // Mock successful conditions
            },
            wantErr: false,
        },
        {
            name: "fails when already installed",
            config: &Config{MasterMode: false},
            setup: func() {
                // Mock already installed condition
            },
            wantErr: true,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            tt.setup()
            rc := eos_io.NewTestContext(t)
            err := Install(rc, tt.config)
            if (err != nil) != tt.wantErr {
                t.Errorf("Install() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

#### Coverage Requirements
- Aim for minimum 80% coverage on new code
- Critical paths must have 100% coverage
- Use `go test -coverprofile=coverage.out` to verify

### Testing Commands
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
```

## Code Quality

### Code Quality Requirements

**CRITICAL** - Any task can be considered completed ONLY when the following requirements are met:

1. **Zero Compilation Errors**: The code must compile successfully without any errors
   ```bash
   go build -o /tmp/eos-build ./cmd/
   ```

2. **Linting Standards**: Must pass all linting checks without warnings or errors
   ```bash
   golangci-lint run
   ```

3. **Test Compliance**: Must pass all existing tests relevant to changes
   ```bash
   go test -v ./pkg/...
   ```

4. **Fix Code, Not Tests**: When tests fail, fix the production code unless the test is clearly invalid

5. **Documentation**: All public functions must have proper GoDoc comments

**No task should be marked as complete until ALL verification steps pass successfully.**

### Code Conventions

**CRITICAL** - These conventions are mandatory:

1. **Structured Logging Only**
   - Use ONLY `otelzap.Ctx(rc.Ctx)` for all logging
   - NEVER use `fmt.Printf`, `fmt.Println`, or any `fmt` output functions
   - Use appropriate log levels: Debug, Info, Warn, Error

2. **Assess → Intervene → Evaluate Pattern**
   - Every helper function must follow this three-step pattern
   - Check prerequisites before acting
   - Verify success after acting

3. **Package Structure**
   - Business logic in `pkg/[feature]/`
   - Command orchestration in `cmd/`
   - No business logic in command files

4. **Error Handling**
   - Return wrapped errors with context: `fmt.Errorf("failed to X: %w", err)`
   - Use `eos_err.NewUserError()` for user-correctable issues
   - Use `eos_err.NewSystemError()` for system failures

5. **User Interaction**
   - Use flags for configuration when possible
   - Prompt interactively when flags not provided
   - Always log prompts as: `logger.Info("terminal prompt: [question]")`

## Common Pitfalls

### Things You Must NEVER Do:

1. **NEVER use fmt package for output**
   ```go
   // NEVER DO THIS
   fmt.Printf("Installing package\n")
   fmt.Println("Done!")
   
   // ALWAYS DO THIS
   logger := otelzap.Ctx(rc.Ctx)
   logger.Info("Installing package")
   logger.Info("Done!")
   ```

2. **NEVER put business logic in cmd/**
   ```go
   // WRONG - Business logic in command file
   // cmd/create_tool.go
   func runCreateTool(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
       // Don't implement installation logic here!
       exec.Command("apt-get", "install", "tool").Run()  // WRONG!
   }
   
   // CORRECT - Orchestrate helpers
   func runCreateTool(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
       return tool.Install(rc, config)  // Delegate to pkg/tool/
   }
   ```

3. **NEVER ignore RuntimeContext**
   - Always pass `rc` to all functions that might need logging or cancellation
   - Always check `rc.Ctx.Done()` in long-running operations

4. **NEVER skip verification steps**
   - Always verify operations succeeded
   - Don't assume external commands worked

5. **NEVER hardcode values**
   - Use configuration flags or prompts
   - Store defaults in constants

6. **NEVER assume external commands exist**
   ```go
   // WRONG
   exec.Command("terraform", "init").Run()
   
   // CORRECT
   if _, err := exec.LookPath("terraform"); err != nil {
       return eos_err.NewUserError("terraform not found in PATH")
   }
   ```

## Integration Guidelines

### Adding New Tool Integrations

When adding support for a new tool (like SaltStack, Terraform, etc.), follow this structure:

#### 1. Package Structure
```
pkg/[toolname]/
├── types.go       # Common types, constants, configurations
├── install.go     # Installation logic
├── configure.go   # Configuration logic
├── verify.go      # Verification logic
├── client.go      # API client (if needed)
└── *_test.go      # Corresponding test files
```

#### 2. Command Structure
```go
// cmd/create_[toolname].go
var create[Toolname]Cmd = &cobra.Command{
    Use:   "[toolname]",
    Short: "Install and configure [tool description]",
    Long: `Detailed description of what this command does...`,
    RunE: eos_cli.Wrap(runCreate[Toolname]),
}
```

#### 3. Flag Patterns
```go
func init() {
    createCmd.AddCommand(create[Toolname]Cmd)
    
    // Provide sensible defaults
    create[Toolname]Cmd.Flags().String("version", "latest", "Tool version to install")
    create[Toolname]Cmd.Flags().String("config-path", "/etc/[tool]", "Configuration directory")
    create[Toolname]Cmd.Flags().Bool("skip-verify", false, "Skip verification step")
}
```

#### 4. Error Messages
Be specific and actionable:
```go
// Bad error
return errors.New("installation failed")

// Good error
return fmt.Errorf("failed to install %s: apt-get returned exit code %d. Try running 'sudo apt-get update' first", pkgName, exitCode)
```

## Debugging Guidelines

### Troubleshooting Common Issues

1. **Missing Executables**
   ```go
   // Always check for required executables
   logger.Debug("Checking for required executables")
   for _, cmd := range []string{"salt", "terraform", "docker"} {
       if _, err := exec.LookPath(cmd); err != nil {
           logger.Warn("Required executable not found",
               zap.String("command", cmd),
               zap.Error(err))
       }
   }
   ```

2. **Permission Errors**
   ```go
   // Check permissions before operations
   if os.Geteuid() != 0 {
       return eos_err.NewUserError("this command requires root privileges, please run with sudo")
   }
   ```

3. **Network Timeouts**
   - Default timeout is 3 minutes via RuntimeContext
   - For longer operations, create a new context with extended timeout

4. **Debug Logging**
   ```go
   // Add detailed debug information
   logger.Debug("Operation state",
       zap.Any("config", config),
       zap.String("phase", "pre-install"),
       zap.Strings("environment", os.Environ()))
   ```

### Verification Patterns
```go
// Always verify prerequisites
func checkPrerequisites(rc *eos_io.RuntimeContext) error {
    logger := otelzap.Ctx(rc.Ctx)
    
    // Check OS version
    if !isUbuntu() {
        return eos_err.NewUserError("this tool requires Ubuntu")
    }
    
    // Check disk space
    if !hasEnoughDiskSpace() {
        return eos_err.NewUserError("insufficient disk space")
    }
    
    // Check network connectivity
    if !canReachRepository() {
        return eos_err.NewUserError("cannot reach package repository")
    }
    
    logger.Debug("All prerequisites satisfied")
    return nil
}
```

## External References

- Knowledge base: [Athena](https://wiki.cybermonkey.net.au)
- Company website: [cybermonkey.net.au](https://cybermonkey.net.au/)
- Contact: main@cybermonkey.net.au
- Architecture reference: See STACK.md for the architectural principles of the Eos framework

## Memories

- No use of emojis in code or documentation