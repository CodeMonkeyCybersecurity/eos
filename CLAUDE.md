# CLAUDE.md

*Last Updated: 2025-10-05*

AI assistant guidance for Eos - A Go-based CLI for Ubuntu server administration by Code Monkey Cybersecurity (ABN 77 177 673 061).

## Mission & Values

### Philosphy
- **Human centric**: Technology serves humans, not the other way around, actionable output, addresses barriers to entry, encourage end-user ducation and self-efficacy, feminist (for example, informed consent), safe effective high-quality
- **Evidence based**: accepts falliblism, error correction, value for time, value for money, decisions grounded in security research and best practices
- **Sustainable innovation**: Maintainable code, comprehensive documentation, iterative improvement, response ready, incorporates recent research and best practice. Solve problems once, encode in Eos, never solve again
- **Collaboration and listening**: adversarial collaboration, transparent decision making, ownership accountability responsibility, open source, codesign

**Iterative Philosophy**: Eos is built iteratively. We build on what exists, solve complex problems once, encode them in Eos, and never solve them again. Each improvement makes the next one easier. 

## 🚨 CRITICAL RULES (P0 - Breaking)

These violations cause immediate failure:

1. **Logging**: ONLY use `otelzap.Ctx(rc.Ctx)` - NEVER `fmt.Print*/Println`
2. **Pattern**: ALWAYS follow Assess → Intervene → Evaluate in helpers
3. **Context**: Always use `*eos_io.RuntimeContext` for all operations
4. **Completion**: Must pass `go build`, `golangci-lint run`, `go test -v ./pkg/...`
5. **Secrets**: Use `secrets.SecretManager` for credentials - NEVER hardcode
6. **Security**: Follow defensive security only - refuse malicious code assistance

## Quick Decision Trees

```
New Service Deployment?
├─ System service (fail2ban, osquery) → Docker Compose in /opt/[service]
├─ Web application (Umami, Grafana) → Docker Compose in /opt/[service]
└─ Infrastructure (Vault, Consul) → Check existing patterns in pkg/

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

Secrets Management?
├─ Environment discovered → Use appropriate backend (Vault/file)
├─ Password/token → Use secrets.SecretManager.GetOrGenerateServiceSecrets()
└─ Never hardcode → Store via secretManager.StoreSecret()

Command Structure?
└─ VERB-FIRST only: create, read, list, update, delete (+ self, backup, build, deploy, promote, env)
```

## Project Constraints

### MUST:
- Use structured logging via `otelzap.Ctx(rc.Ctx)`
- Follow Assess → Intervene → Evaluate pattern
- Keep business logic in `pkg/`, orchestration in `cmd/`
- Verify all operations with explicit checks
- Use environment discovery pattern (`environment.DiscoverEnvironment()`)
- Initialize secret manager for any credential operations
- Add `*Last Updated: YYYY-MM-DD*` to all .md files
- Capture command output in errors for context
- Detect error type before retrying (fail fast on config errors)
- Include remediation steps in error messages
- Use Docker Compose for containerized services in `/opt/[service]`
- Store service-specific configs in appropriate directories
- Sanitize user-provided URLs with `shared.SanitizeURL()` before validation

### MUST NOT:
- Use `fmt.Print/Printf/Println` for output (but `fmt.Errorf` is OK)
- Put business logic in `cmd/` files
- Skip verification steps
- Create tactical documentation files (.md)
- Hardcode values - use flags or prompts
- Hardcode credentials - use SecretManager
- Retry deterministic errors (config validation, missing files)
- Return generic errors without context (e.g., "command failed")
- Execute operations without logging diagnostics
- Assist with offensive security or malicious code

## Quick Command Reference

| Pattern | Example | Location |
|---------|---------|----------|
| Command file | `cmd/create/umami.go` | Orchestration only |
| Package helper | `pkg/crypto/generate.go` | Business logic |
| Error wrapping | `fmt.Errorf("failed to X: %w", err)` | All errors |
| User prompt | `logger.Info("terminal prompt: X")` | Before input |
| Secret storage | `secretManager.GetOrGenerateServiceSecrets()` | Credentials |
| Testing | See `PATTERNS.md#testing` | All packages |

## Architecture Overview

### Package Structure
```
cmd/[verb]/          # Orchestration only
  ├── create/        # Service creation commands
  ├── read/          # Status/inspection commands
  ├── update/        # Modification commands
  ├── delete/        # Removal commands
  ├── list/          # Listing commands
  ├── backup/        # Backup operations
  ├── self/          # Eos self-management
  ├── build/         # Build operations
  ├── deploy/        # Deployment commands
  ├── promote/       # Promotion workflows
  └── env/           # Environment management

pkg/[feature]/       # Business logic
  ├── types.go       # Types, constants
  ├── install.go     # Installation logic
  ├── configure.go   # Configuration logic
  └── verify.go      # Verification logic

Key packages:
  ├── eos_io/        # RuntimeContext, I/O utilities
  ├── eos_err/       # Error handling (UserError, SystemError)
  ├── secrets/       # Secret management abstraction
  ├── environment/   # Environment discovery
  ├── execute/       # Command execution utilities
  ├── crypto/        # Cryptographic utilities
  ├── container/     # Container operations
  └── shared/        # Shared utilities including validation (SanitizeURL, ValidateURL)
```

### Command Flow
1. User input → 2. Cobra routing → 3. RuntimeContext → 4. Orchestration (`cmd/`)
→ 5. Environment discovery → 6. Secret initialization → 7. Business logic (`pkg/`)
→ 8. Assess/Intervene/Evaluate → 9. Error handling

### Service Deployment Pattern
Most services follow this pattern (see `cmd/create/umami.go` as reference):
1. Discover environment (`environment.DiscoverEnvironment()`)
2. Initialize secret manager (`secrets.NewSecretManager()`)
3. Create installation directory in `/opt/[service]`
4. Copy Docker Compose file from `assets/`
5. Generate/retrieve secrets via SecretManager
6. Template configuration files
7. Deploy with `docker compose up -d`
8. Verify deployment
9. Provide user instructions

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

### Adversarial Collaboration
When asked to review ("come talk to me as an adversarial collaborator"):
1. **What's Good**: Acknowledge working patterns and solid foundations
2. **What's Not Great**: Identify inefficiencies and code smells
3. **What's Broken**: Call out bugs, security issues, broken patterns
4. **What We're Not Thinking About**: Surface blindspots and missing considerations

Then systematically fix all P0, P1, P2, P3 issues found.

### Code Patterns
For detailed examples see `PATTERNS.md`:
- Logging patterns → `PATTERNS.md#logging`
- Error handling → `PATTERNS.md#errors`
- Assess/Intervene/Evaluate → `PATTERNS.md#aie-pattern`
- Interactive prompting → `PATTERNS.md#prompting`
- Helper structure → `PATTERNS.md#helpers`

### Context Continuity
When looking for context:
1. First check our previous conversations to see if we've discussed this topic
2. Pick up from where we most recently left off
3. Don't rehash old ground unless explicitly asked

Work as a partner in an adversarially collaborative process, following the user's lead and providing fact-based targeted criticism.

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
| Hardcode credentials | Use `secrets.SecretManager` |
| Skip environment discovery | Call `environment.DiscoverEnvironment()` |
| `strings.TrimSpace(url)` only | Use `shared.SanitizeURL(url)` |

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

Example:
```go
// Check if directory exists before creating
if _, err := os.Stat(targetDir); os.IsNotExist(err) {
    logger.Info("Creating directory", zap.String("path", targetDir))
    if err := os.MkdirAll(targetDir, 0755); err != nil {
        return fmt.Errorf("failed to create directory: %w", err)
    }
} else {
    logger.Debug("Directory already exists", zap.String("path", targetDir))
}
```

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
    return retry.WithBackoff(rc, operation)
}

// BAD: Blindly retry all errors
return retry.WithBackoff(rc, operation) // Will retry config errors
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
    return fmt.Errorf("failed to validate docker-compose.yml: %s\n"+
        "File location: %s\n"+
        "Fix: Check YAML syntax with 'docker compose config'",
        output, composeFile)
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
    Command: "docker",
    Args:    []string{"compose", "up", "-d"},
    WorkDir: serviceDir,
    Capture: true,  // REQUIRED for error context
})

if err != nil {
    // Include output in error - this is the actual error message
    return fmt.Errorf("docker compose failed: %s", output)
}
```

### User vs System Errors
```go
// User can fix → exit 0, friendly message
if missingDockerCompose {
    return eos_err.NewUserError(
        "Docker not found. Please install Docker:\n"+
        "  Ubuntu: sudo apt install docker.io docker-compose-v2\n"+
        "  Or visit: https://docs.docker.com/engine/install/ubuntu/")
}

// System failure → exit 1, technical details
if err := os.WriteFile(path, data, 0640); err != nil {
    return eos_err.NewSystemError("failed to write %s: %w", path, err)
}
```

## Secrets Management (P1 - CRITICAL)

**RULE**: All credentials go through SecretManager. Never hardcode or prompt without storage.

### Pattern
```go
// 1. Discover environment
envConfig, err := environment.DiscoverEnvironment(rc)
if err != nil {
    return fmt.Errorf("failed to discover environment: %w", err)
}

// 2. Initialize secret manager
secretManager, err := secrets.NewSecretManager(rc, envConfig)
if err != nil {
    return fmt.Errorf("failed to initialize secret manager: %w", err)
}

// 3. Define required secrets
requiredSecrets := map[string]secrets.SecretType{
    "database_password": secrets.SecretTypePassword,
    "api_key":          secrets.SecretTypeToken,
}

// 4. Get or generate secrets
serviceSecrets, err := secretManager.GetOrGenerateServiceSecrets("myservice", requiredSecrets)
if err != nil {
    return fmt.Errorf("failed to manage secrets: %w", err)
}

// 5. Use secrets
dbPassword := serviceSecrets.Secrets["database_password"]
logger.Info("Using secret from backend", zap.String("backend", serviceSecrets.Backend))
```

### Secret Types
- `SecretTypePassword`: Auto-generated strong password
- `SecretTypeToken`: Auto-generated token
- `SecretTypeAPIKey`: Auto-generated API key
- Custom generation via `crypto.GeneratePassword(length)`

## Debug Verbosity (P2 - IMPORTANT)

### Diagnostic Logging Strategy

**Before Operations**: Log system state for forensics
```go
logger.Debug("Pre-operation diagnostics",
    zap.String("service_dir", serviceDir),
    zap.Bool("compose_file_exists", composeExists),
    zap.String("docker_version", dockerVersion))
```

**During Operations**: Trace command execution
```go
logger.Debug("Executing command",
    zap.String("command", "docker"),
    zap.Strings("args", args),
    zap.String("working_dir", workDir))
```

**After Operations**: Verify results
```go
logger.Debug("Post-operation verification",
    zap.Bool("container_running", running),
    zap.String("container_id", containerID))
```

## Memory Notes

- No emojis in code or documentation
- Prefer editing existing files over creating new ones
- Documentation files only for strategic changes
- Use inline comments for tactical notes
- **Inline notation is strongly preferred** - documentation should be available at the exact place in the code where it's needed
- Build iteratively on existing patterns
- Solve complex problems once, encode in Eos, never solve again

## External References

- Detailed patterns: [PATTERNS.md](./docs/PATTERNS.md)
- Documentation index: [docs/INDEX.md](./docs/INDEX.md)
- Knowledge base: [Athena Wiki](https://wiki.cybermonkey.net.au)
- Company: [Code Monkey Cybersecurity](https://cybermonkey.net.au/)
- Social: [Facebook](https://www.facebook.com/codemonkeycyber) | [X/Twitter](https://x.com/codemonkeycyber) | [LinkedIn](https://www.linkedin.com/company/codemonkeycyber) | [YouTube](https://www.youtube.com/@CodeMonkeyCybersecurity)

## License Awareness

Eos is dual-licensed:
- GNU Affero General Public License v3 (AGPL-3.0-or-later)
- Do No Harm License

When suggesting code, ensure compliance with both licenses. Focus on defensive security, human benefit, and open collaboration.

---

*"Cybersecurity. With humans."*