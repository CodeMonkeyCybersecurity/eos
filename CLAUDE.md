# CLAUDE.md

*Last Updated: 2025-10-03*

AI assistant guidance for the Eos project - a Go-based CLI for Ubuntu server administration by Code Monkey Cybersecurity. The Motto is 'Cybersecurity. With humans.'  We focus on making sure cybersecurity is human centric, evidence based, and we focus on sustainable innovation. 

The building of eos is an iterative process, we need to as much as we can build on what already exists. We want to solve complex problems once, encode in Eos, never solve again.

Eos needs to be human-centric, 

## 🚨 CRITICAL RULES (P0 - Breaking)

These violations cause immediate failure:

1. **Logging**: ONLY use `otelzap.Ctx(rc.Ctx)` - NEVER `fmt.Print*/Println`
2. **Pattern**: ALWAYS follow Assess → Intervene → Evaluate in helpers
3. **Architecture**: Infrastructure → , Applications → Nomad
4. **Completion**: Must pass `go build`, `golangci-lint run`, `go test -v ./pkg/...`
5. **Context**: Always use `*eos_io.RuntimeContext` for all operations

## Quick Decision Trees

```
New Service?
├─ System/Security/Orchestration →  (//states/)
└─ Container/Web/Database → Nomad (/nomad/jobs/)

Need User Input?
├─ Flag provided → Use it
└─ Flag missing → Prompt interactively (eos_io.PromptInput)

Error Type?
├─ User fixable → eos_err.NewUserError() → exit(0)
├─ Config/validation → Fail fast, don't retry
└─ System failure → eos_err.NewSystemError() → exit(1)

Retry Decision?
├─ Transient (network, timeout, lock) → Retry with backoff
└─ Deterministic (config, validation, missing file) → Fail fast

Command Structure?
└─ VERB-FIRST only: create, read, list, update, delete (+ self, backup)
```

## Project Constraints

### MUST:
- Use structured logging via `otelzap.Ctx(rc.Ctx)`
- Follow Assess → Intervene → Evaluate pattern
- Keep business logic in `pkg/`, orchestration in `cmd/`
- Verify all operations with explicit checks
- Use version resolver for new deployments (`pkg/platform/version_resolver.go`)
- Add `*Last Updated: YYYY-MM-DD*` to all .md files
- Capture command output in errors for context
- Detect error type before retrying (fail fast on config errors)
- Include remediation steps in error messages

### MUST NOT:
- Use `fmt.Print/Printf/Println` for output (but `fmt.Errorf` is OK)
- Put business logic in `cmd/` files
- Skip verification steps
- Create tactical documentation files (.md)
- Hardcode values - use flags or prompts
- Mix  and Nomad for same service
- Retry deterministic errors (config validation, missing files)
- Return generic errors without context (e.g., "command failed")
- Execute operations without logging diagnostics

## Quick Command Reference

| Pattern | Example | Location |
|---------|---------|----------|
| Command file | `cmd/create/consul.go` | Orchestration only |
| Package helper | `pkg/consul/install.go` | Business logic |
| Error wrapping | `fmt.Errorf("failed to X: %w", err)` | All errors |
| User prompt | `logger.Info("terminal prompt: X")` | Before input |
| Testing | See `PATTERNS.md#testing` | All packages |

## Architecture Overview

### Dual-Layer System
- **Layer 1 ()**: Infrastructure, security tools, system packages
- **Layer 2 (Nomad)**: Containerized apps, web services, databases
- **User sees**: Unified `eos create X` regardless of layer

### Package Structure
```
cmd/[verb]/          # Orchestration only
pkg/[feature]/       # Business logic
  ├── types.go       # Types, constants
  ├── install.go     # Installation
  ├── configure.go   # Configuration  
  └── verify.go      # Verification
```

### Command Flow
1. User input → 2. Cobra routing → 3. RuntimeContext → 4. Orchestration (`cmd/`) 
→ 5. Business logic (`pkg/`) → 6. Assess/Intervene/Evaluate → 7. Error handling

## Testing Requirements

Before marking complete:
```bash
go build -o /tmp/eos-build ./cmd/    # Must compile
golangci-lint run                    # Must pass linting
go test -v ./pkg/...                 # Must pass tests
```

## AI Assistant Guidelines

### Efficiency Tips
- Batch related file reads in single response
- Use Task tool for open-ended searches
- Use TodoWrite for multi-step operations
- Search before asking for clarification
- Check existing patterns in codebase first

### Code Patterns
For detailed examples see `PATTERNS.md`:
- Logging patterns → `PATTERNS.md#logging`
- Error handling → `PATTERNS.md#errors`
- Assess/Intervene/Evaluate → `PATTERNS.md#aie-pattern`
- Interactive prompting → `PATTERNS.md#prompting`
- Helper structure → `PATTERNS.md#helpers`

## Common Anti-Patterns

| Never Do This | Always Do This |
|--------------|----------------|
| `fmt.Println("text")` | `logger.Info("text")` |
| Business logic in `cmd/` | Delegate to `pkg/` |
| `exec.Command().Run()` | Check with `exec.LookPath()` first |
| Skip verification | Explicit verification checks |
| Create tactical .md files | Use inline `// TODO:` comments |
| Retry all errors blindly | Detect error type, fail fast on config errors |
| `return fmt.Errorf("failed")` | Include output, context, remediation |
| Silent operations | Log before/during/after with context |

## Service Classification

### Infrastructure ()
consul, vault, nomad, fail2ban, trivy, osquery, , docker

### Applications (Nomad)
grafana, jenkins, nextcloud, mattermost, gitlab, postgres, redis

## Priority Levels

- **P0 (BREAKING)**: Violations cause immediate failure
- **P1 (CRITICAL)**: Must fix before marking complete
- **P2 (IMPORTANT)**: Should follow unless justified
- **P3 (RECOMMENDED)**: Best practices

## Idempotency Principles

1. Check before acting - Don't assume state
2. Handle "already done" gracefully - Not an error
3. Focus on end result, not the action
4. Use conditional operations

## Retry Logic (P1 - CRITICAL)

**RULE**: Only retry TRANSIENT failures. Never retry DETERMINISTIC failures.

### Transient Failures (RETRY)
- Network timeouts
- Temporary resource locks
- Race conditions
- Service not ready yet (starting up)
- Temporary disk full

### Deterministic Failures (FAIL FAST)
- Configuration validation errors
- Missing required files
- Invalid credentials
- Multiple network interfaces (needs user decision)
- Permission denied
- Command not found

### Implementation Pattern
```go
// GOOD: Detect error type before retrying
if err := operation(); err != nil {
    if isConfigError(err) || isValidationError(err) {
        // Don't retry - config won't fix itself
        return fmt.Errorf("configuration invalid: %w", err)
    }
    // Only retry transient errors
    return WithRetry(rc, config, operation)
}

// BAD: Blindly retry all errors
return WithRetry(rc, config, operation) // Will retry config errors 5x
```

### Logging Requirements
```go
// When retrying
logger.Warn("Operation failed, will retry",
    zap.Error(err),
    zap.String("reason", "network timeout"),  // WHY retrying
    zap.Int("attempt", attempt))

// When failing fast
logger.Error("Operation failed, not retrying",
    zap.Error(err),
    zap.String("reason", "configuration error"), // WHY not retrying
    zap.String("remediation", "fix config and retry")) // What user should do
```

## Error Context (P1 - CRITICAL)

**RULE**: Errors must be actionable. Always include context and remediation.

### Required Error Information
1. **What failed**: Specific operation, not just "command failed"
2. **Why it failed**: Root cause from stdout/stderr
3. **How to fix**: Actionable remediation steps
4. **System state**: Relevant context (interfaces, ports, services)

### Implementation Pattern
```go
// GOOD: Rich error context
output, err := execute.Run(ctx, opts)
if err != nil {
    return fmt.Errorf("consul config validation failed: %s\n"+
        "Detected interfaces: %v\n"+
        "Fix: Run 'ip addr' and configure bind_addr in consul.hcl",
        output, interfaces)
}

// BAD: Generic error
if err != nil {
    return fmt.Errorf("command failed: %w", err)
}
```

### Capture Command Output
```go
// Always capture output for error context
output, err := execute.Run(rc.Ctx, execute.Options{
    Command: "consul",
    Args:    []string{"validate", configPath},
    Capture: true,  // REQUIRED for error context
})

if err != nil {
    // Include output in error - this is the actual error message
    return fmt.Errorf("validation failed: %s", output)
}
```

### User vs System Errors
```go
// User can fix → exit 0, friendly message
if multipleInterfaces {
    return eos_err.NewUserError(
        "Multiple network interfaces detected: %v\n"+
        "Please select one:\n"+
        "  1. Run: eos bootstrap --interface=eth0\n"+
        "  2. Or configure manually in /etc/consul.d/consul.hcl",
        interfaces)
}

// System failure → exit 1, technical details
if err := os.WriteFile(path, data, 0640); err != nil {
    return eos_err.NewSystemError("failed to write %s: %w", path, err)
}
```

## Debug Verbosity (P2 - IMPORTANT)

### Diagnostic Logging Strategy

**Before Operations**: Log system state for forensics
```go
logger.Debug("Pre-operation diagnostics",
    zap.String("hostname", hostname),
    zap.Strings("interfaces", getInterfaces()),
    zap.Ints("listening_ports", getPorts()),
    zap.Strings("running_services", getServices()))
```

**During Operations**: Trace command execution
```go
// For critical system commands
if command == "systemctl" || command == "consul" {
    logger.Debug("COMMAND TRACE",
        zap.String("command", command),
        zap.Strings("args", args),
        zap.String("full_command", buildCommandString(command, args...)))
}
```

**After Operations**: Verify results
```go
logger.Debug("Post-operation verification",
    zap.Bool("service_active", isActive),
    zap.String("service_status", status),
    zap.Int("pid", pid))
```

### Debug Flag Pattern
```go
// In command definition
cmd.Flags().Bool("debug", false, "Enable debug logging")

// In execution
if debug {
    logger.Debug("Detailed state dump",
        zap.Any("full_config", config),
        zap.Strings("all_env_vars", os.Environ()))
}
```

## External References

- Detailed patterns: `PATTERNS.md`
- Architecture: `STACK.md`
- Knowledge base: [Athena](https://wiki.cybermonkey.net.au)
- Company: [cybermonkey.net.au](https://cybermonkey.net.au/)

## Memory Notes

- No emojis in code or documentation
- Prefer editing existing files over creating new ones
- Documentation files only for strategic changes
- Use inline comments for tactical notes