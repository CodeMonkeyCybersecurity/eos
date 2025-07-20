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

### SaltStack + Nomad Dual-Layer Architecture

*Last Updated: 2025-01-20*

**CRITICAL**: Eos uses a dual-layer architecture that separates infrastructure management from application orchestration. This architecture decision drives all implementation choices.

#### Layer 1: Infrastructure Foundation (SaltStack)
**Responsibility**: System-level configuration, base packages, and infrastructure services

**SaltStack manages:**
- System packages (fail2ban, trivy, osquery, essential tools)
- Infrastructure services (Consul, Nomad, Vault, SaltStack itself)
- Host security configuration
- Docker runtime installation (for Nomad)

**Implementation Pattern for Infrastructure Services:**
```go
// Example: cmd/create/consul.go
func runCreateConsul(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    // ASSESS - Check SaltStack availability
    if _, err := exec.LookPath("salt-call"); err != nil {
        return fmt.Errorf("saltstack is required")
    }
    
    // INTERVENE - Apply SaltStack state
    pillarData := map[string]interface{}{
        "consul": map[string]interface{}{
            "datacenter": datacenterName,
            "ui_enabled": true,
        },
    }
    
    args := []string{"--local", "state.apply", "hashicorp.consul", 
                     fmt.Sprintf("pillar='%s'", pillarJSON)}
    exec.Command("salt-call", args...).Run()
    
    // EVALUATE - Verify service running
    return verifyService("consul")
}
```

#### Layer 2: Application Orchestration (Nomad)
**Responsibility**: Container-based applications, service mesh, and workload scheduling

**Nomad manages:**
- Application containers (Jenkins, Grafana, Mattermost, Nextcloud)
- Service discovery via Consul integration
- Container lifecycle, health checks, and recovery
- Resource allocation and scheduling

**Implementation Pattern for Application Services:**
```go
// Example: cmd/create/grafana.go  
func runCreateGrafana(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    // ASSESS - Check Nomad availability
    if err := checkNomadRunning(rc); err != nil {
        return fmt.Errorf("nomad is required for application services")
    }
    
    // INTERVENE - Deploy Nomad job
    jobTemplate := loadJobTemplate("grafana.nomad")
    jobConfig := buildJobConfig(cmd) // From flags
    nomadJob := renderJobTemplate(jobTemplate, jobConfig)
    
    if err := deployNomadJob(rc, nomadJob); err != nil {
        return fmt.Errorf("failed to deploy grafana: %w", err)
    }
    
    // EVALUATE - Verify job running and healthy
    return verifyNomadJob(rc, "grafana")
}
```

#### User Experience Abstraction
**CRITICAL**: Users don't need to know about the underlying architecture. The same `eos create X` pattern works for both layers:

```bash
# Infrastructure (SaltStack) - Users don't need to know
eos create consul        # Deploys via SaltStack state
eos create vault         # Deploys via SaltStack state
eos create fail2ban      # Deploys via SaltStack state

# Applications (Nomad) - Users don't need to know  
eos create grafana       # Deploys via Nomad job
eos create jenkins       # Deploys via Nomad job
eos create nextcloud     # Deploys via Nomad job
```

#### Service Classification Rules
**Infrastructure Services (SaltStack)**: System packages, security tools, orchestration platforms
**Application Services (Nomad)**: Containerized applications, web services, databases

#### Anti-Patterns to Avoid
- **NEVER** run Docker Compose alongside Nomad on same host
- **NEVER** mix SaltStack and Nomad for same service type
- **NEVER** expose architecture complexity to users
- **NEVER** bypass Consul for service discovery

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

### CLI Structure (Cobra Framework) - VERB-FIRST ARCHITECTURE

**CRITICAL**: Eos follows a strict **VERB-FIRST** command structure to prevent architectural drift and maintain consistency.

#### Core Command Structure
The `cmd/` directory MUST contain only these verb-based commands:
- **create** - All creation operations (`eos create saltstack`, `eos create database`, `eos create vault`)
- **read** - All read/inspection operations (`eos read config`, `eos read status`)
- **list** - All listing operations (`eos list services`, `eos list users`)
- **update** - All modification operations (`eos update config`, `eos update secrets`)
- **delete** - All deletion operations (`eos delete user`, `eos delete service`)

#### Special Case Commands
Only these exceptions are allowed for organizational clarity:
- **self** - Managing the Eos tool itself (`eos self update`, `eos self git commit`)
- **backup** - Backup operations (special case due to complex nomenclature)

#### Verb Synonyms and Aliases
To handle natural language variations, use command aliases:
- **read**: aliases = `inspect`, `show`, `get`, `status`
- **update**: aliases = `modify`, `manage`, `clean`, `enable`, `disable`, `sync`, `migrate`, `set`
- **create**: aliases = `deploy`, `install`, `setup`, `add`
- **delete**: aliases = `remove`, `destroy`, `uninstall`
- **list**: aliases = `ls`, `show-all`

#### PROHIBITED: Noun-First Commands
**NEVER** create noun-first commands like:
- ❌ `cmd/database/` 
- ❌ `cmd/delphi/`
- ❌ `cmd/container/`
- ❌ `cmd/vault/`

Instead, use verb-first structure:
- `eos create database`
- `eos update delphi`  
- `eos list containers`
- `eos read vault status`

#### Directory Structure
```
cmd/
├── create/           # All creation operations
│   ├── create.go    # Root create command
│   ├── saltstack.go # eos create saltstack
│   ├── database.go  # eos create database
│   └── vault.go     # eos create vault
├── read/            # All read/inspection operations
├── list/            # All listing operations  
├── update/          # All modification operations
├── delete/          # All deletion operations
├── self/            # Eos self-management (EXCEPTION)
│   ├── self.go
│   └── git/         # Git operations for Eos itself
└── backup/          # Backup operations (EXCEPTION)
```

#### Special Commands
The following commands have special status and remain under their current structure:
- **self**: Self-management commands for Eos (test, ai, git operations)
- **backup**: Backup operations remain as a special case due to complex nomenclature

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
- **Architecture Compliance**: **CRITICAL** - All new services MUST follow the SaltStack + Nomad dual-layer architecture
  - Infrastructure services → SaltStack states
  - Application services → Nomad jobs  
  - Users see consistent `eos create X` experience regardless of underlying implementation

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

5. **User Interaction and Interactive Prompting**
   - **CRITICAL RULE**: If required flags are not provided and would cause the command to fail, prompt the user for them interactively
   - Use flags for configuration when possible
   - Prompt interactively when flags not provided for required values
   - Always log prompts as: `logger.Info("terminal prompt: [question]")`
   - Use `eos_io.PromptInput()` for general input prompting
   - Use `eos_io.PromptSecurePassword()` for password prompting
   - Remove `MarkFlagRequired()` for flags that are handled with interactive prompts
   - Update flag descriptions to indicate "(prompted if not provided)" for required flags

6. **Deployment of new resources**
   - use version resolver in pkg/platform/version_resolver.go when deciding what version of something to download (eg. saltstack, nomad, etc.) to programatically make sure the most recent version of something is downloaded and installed when using `eos create ...` 


7. **Strategic documentation in docs/**
    - **ONLY** create documentation files in docs/ for high-level strategic changes
    - Examples: new standards (Essential Eight compliance), software stack decisions, architectural changes
    - Examples: migration guides for major framework changes, security policy updates
    - **DO NOT** create documentation for tactical implementation details, pre-commit checklists, or temporary work notes

8. **Tactical documentation as inline comments**
    - Use `// TODO:` comments for specific code improvements needed
    - Use `// Comment` for implementation explanations and context
    - Use structured logging for operational notes and debugging information
    - Examples: `// TODO: Add validation for edge case`, `// Using exponential backoff due to API rate limits`
    - **NEVER** create separate .md files for tactical notes, implementation reminders, or temporary checklists  

9. **Documentation Dating Requirements**
    - **MANDATORY**: Every time a documentation file (.md) is created or modified, add or update the date in the format: `*Last Updated: YYYY-MM-DD*`
    - Place the date immediately after the main heading (`# Title`) and before the first content section
    - This eliminates the need to dig through git history to understand when documentation was last current
    - Example format:
      ```markdown
      # Documentation Title
      
      *Last Updated: 2025-01-14*
      
      ## First Content Section
      ```
    - Apply this to ALL documentation files: README.md, component docs, guides, architecture docs, etc.


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

7. **NEVER create documentation files unless strategically necessary**
   ```go
   // WRONG - Creating files for tactical notes
   // docs/PRECOMMIT_CHECKLIST.md
   // docs/IMPLEMENTATION_NOTES.md
   // docs/TODO_LIST.md
   
   // CORRECT - Use inline comments for tactical documentation
   // TODO: Add input validation for edge cases
   // This uses exponential backoff to handle rate limits
   logger.Debug("Retrying after backoff", zap.Duration("wait", delay))
   ```

## Integration Guidelines

### Service Classification Decision Tree

**CRITICAL**: Before implementing any new service, determine the correct architectural layer:

#### Infrastructure Services (SaltStack Implementation)
**Criteria**: System packages, security tools, orchestration platforms, host-level services
**Examples**: consul, vault, nomad, fail2ban, trivy, osquery, saltstack itself

**Implementation Requirements**:
- Create SaltStack state file: `/salt/states/[category]/[service].sls`
- Use pillar data for configuration
- Apply via `salt-call state.apply`
- Service registers with system (systemd)

#### Application Services (Nomad Implementation)  
**Criteria**: Containerized applications, web services, databases, user-facing applications
**Examples**: grafana, jenkins, nextcloud, mattermost, gitlab

**Implementation Requirements**:
- Create Nomad job template: `/nomad/jobs/[service].nomad` 
- Use job variables for configuration
- Deploy via `nomad job run`
- Service registers with Consul for service discovery

#### Classification Examples
```bash
# Infrastructure (SaltStack)
eos create saltstack    # Orchestration platform
eos create consul       # Service discovery infrastructure  
eos create vault        # Secrets management infrastructure
eos create fail2ban     # Host security
eos create docker       # Container runtime

# Applications (Nomad)  
eos create grafana      # Monitoring dashboard
eos create jenkins      # CI/CD platform
eos create nextcloud    # File sharing platform
eos create postgres     # Database service
eos create redis        # Cache service
```

### Adding New Tool Integrations

When adding support for a new tool, follow this structure:

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

# important-instruction-reminders
Do what has been asked; nothing more, nothing less.
NEVER create documentation files unless they're absolutely necessary for strategic changes.
ALWAYS prefer inline comments (//TODO:, //Comment) for tactical documentation.
NEVER create .md files for implementation notes, checklists, or temporary work notes.
ALWAYS prefer editing an existing file to creating a new one.
NEVER proactively create documentation files (*.md) or README files. Only create documentation files if explicitly requested by the User.
MANDATORY: When creating or modifying any .md file, always add "*Last Updated: YYYY-MM-DD*" after the main heading.

CRITICAL IMPLEMENTATION PATTERN: Helper Function Self-Checks

  Every helper function MUST internally implement the Assess → 
  Intervene → Evaluate pattern:

  1. ASSESS (Can I Execute?)

  - Check permissions (e.g., "do I need sudo?")
  - Check dependencies exist (e.g., "is the required command
  available?")
  - Check preconditions (e.g., "is the service I need to interact
  with running?")
  - Check resources (e.g., "is there enough disk space?")
  - FAIL FAST with clear error messages if unable to proceed

  2. INTERVENE (Execute)

  - Only execute after all checks pass
  - Log what is being attempted
  - Handle errors gracefully
  - Use appropriate error wrapping

  3. EVALUATE (Did it work?)

  - Verify the action completed successfully
  - Check expected outputs/side effects
  - Validate state changes occurred
  - Return meaningful errors if verification fails

  Example Pattern:

  func InstallPackage(rc *eos_io.RuntimeContext, pkgName string) 
  error {
      logger := otelzap.Ctx(rc.Ctx)

      // ASSESS - Can I execute?
      logger.Info("Checking if we can install package",
  zap.String("package", pkgName))

      // Check if running as root
      if os.Geteuid() != 0 {
          return eos_err.NewUserError("package installation requires 
  root privileges, please run with sudo")
      }

      // Check if apt-get exists
      if _, err := exec.LookPath("apt-get"); err != nil {
          return eos_err.NewUserError("apt-get not found - this 
  command requires Ubuntu")
      }

      // Check if package manager is not locked
      if _, err := os.Stat("/var/lib/dpkg/lock"); err == nil {
          return eos_err.NewUserError("package manager is locked by 
  another process")
      }

      // INTERVENE - Execute
      logger.Info("Installing package", zap.String("package",
  pkgName))

      output, err := execute.Run(rc.Ctx, execute.Options{
          Command: "apt-get",
          Args:    []string{"install", "-y", pkgName},
          Capture: true,
      })
      if err != nil {
          return fmt.Errorf("package installation failed: %w", err)
      }

      // EVALUATE - Verify it worked
      logger.Info("Verifying package installation")

      // Check if package is now installed
      output, err = execute.Run(rc.Ctx, execute.Options{
          Command: "dpkg",
          Args:    []string{"-l", pkgName},
          Capture: true,
      })
      if err != nil || !strings.Contains(output, "ii") {
          return fmt.Errorf("package verification failed - package 
  may not be installed correctly")
      }

      logger.Info("Package installed successfully",
  zap.String("package", pkgName))
      return nil
  }

  Key Checks to Include:

  - Permission checks: os.Geteuid(), file permissions
  - Command availability: exec.LookPath()
  - Service status: systemctl is-active
  - File/directory existence: os.Stat()
  - Resource availability: disk space, memory
  - Lock files: dpkg lock, apt lock, etc.
  - Network connectivity: for downloads
  - Configuration validity: before applying

  REMEMBER:

  - Each function is self-contained and defensive
  - Don't assume anything about the environment
  - Provide clear, actionable error messages
  - Log at each phase for debugging
  - The main command orchestrates, but each helper validates itself
