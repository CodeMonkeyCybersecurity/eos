# CLAUDE.md

*Last Updated: 2025-10-21*

AI assistant guidance for Eos - A Go-based CLI for Ubuntu server administration by Code Monkey Cybersecurity (ABN 77 177 673 061).

## Mission & Values

### Philosphy
- **Human centric**: Technology serves humans, not the other way around, actionable output, addresses barriers to entry, encourage end-user ducation and self-efficacy, feminist (for example, informed consent), safe effective high-quality
- **Evidence based**: accepts falliblism, error correction, value for time, value for money, decisions grounded in security research and best practices
- **Sustainable innovation**: Maintainable code, comprehensive documentation, iterative improvement, response ready, incorporates recent research and best practice. Solve problems once, encode in Eos, never solve again
- **Collaboration and listening**: adversarial collaboration, transparent decision making, ownership accountability responsibility, open source, codesign

**Iterative Philosophy**: Eos is built iteratively. We build on what exists, solve complex problems once, encode them in Eos, and never solve them again. Each improvement makes the next one easier. 

##  CRITICAL RULES (P0 - Breaking)

These violations cause immediate failure:

1. **Logging**: ONLY use `otelzap.Ctx(rc.Ctx)` - NEVER `fmt.Print*/Println`
2. **Architecture**: Business logic in `pkg/`, orchestration ONLY in `cmd/` (see Architecture Enforcement below). Use official and well supported SDKs and APIs where possible.
3. **Pattern**: ALWAYS follow Assess → Intervene → Evaluate in helpers
4. **Context**: Always use `*eos_io.RuntimeContext` for all operations
5. **Completion**: Must pass `go build`, `golangci-lint run`, `go test -v ./pkg/...`
6. **Secrets**: Use `secrets.SecretManager` for credentials - NEVER hardcode. Use `secrets.SecretManager.GetOrGenerateServiceSecrets()` for service secrets. And leverage vault for secrets management.
7. **Security**: Complease a red team code review and generic targetted criticism of your work before you commit
8. **evidence-based, adverserially collaborative** approach always with yourself and with me


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

Writing New Command?
├─ In cmd/[verb]/*.go (ORCHESTRATION ONLY):
│  ├─ Define cobra.Command with flags
│  ├─ Parse flags into config struct
│  ├─ Call pkg/[feature]/Function(rc, config)
│  └─ Return result (no business logic!)
│  └─ RULE: If cmd/ file >100 lines, move logic to pkg/
│
└─ In pkg/[feature]/*.go (ALL BUSINESS LOGIC):
   ├─ ASSESS: Check current state
   ├─ INTERVENE: Apply changes if needed
   ├─ EVALUATE: Verify and report results
   └─ Use RuntimeContext, structured logging

Secret/Config Delivery?
├─ Secrets (passwords, API keys, tokens):
│  ├─ Store: Vault via secrets.SecretManager
│  ├─ Deliver: Vault Agent template rendering
│  └─ Rotate: Automatic via Vault Agent watch
│
├─ Non-secret config (ports, URLs, feature flags):
│  ├─ Store: Consul KV at service/[name]/config/
│  ├─ Deliver: Consul Template or direct read
│  └─ Update: Dynamic via Consul KV updates
│
└─ Mixed (secrets + config):
   └─ Use Consul Template with both Vault and Consul backends
```

## Secret and Configuration Management (P0 - CRITICAL)

**Philosophy**: Secrets belong in Vault, configuration belongs in Consul, delivery is automated.

### Storage Layer

#### Secrets (Vault)
**What belongs in Vault:**
- Passwords (database, service accounts)
- API keys (third-party services, internal APIs)
- Tokens (JWT secrets, session keys, ACL tokens)
- TLS certificates and private keys
- Encryption keys

**Storage pattern:**
```go
// At service installation time
secretManager, err := secrets.NewSecretManager(rc, envConfig)
requiredSecrets := map[string]secrets.SecretType{
    "db_password":    secrets.SecretTypePassword,
    "api_key":        secrets.SecretTypeAPIKey,
    "jwt_secret":     secrets.SecretTypeToken,
}
serviceSecrets, err := secretManager.GetOrGenerateServiceSecrets("myservice", requiredSecrets)

// Secrets stored at: secret/myservice/{db_password,api_key,jwt_secret}
```

**Path convention**: `secret/[service-name]/[secret-key]`

#### Configuration (Consul KV)
**What belongs in Consul KV:**
- Feature flags (enable_rag, enable_audit_log)
- Service endpoints (http://service:port)
- Port numbers
- Timeouts and retry limits
- Log levels
- Non-sensitive connection strings

**Storage pattern:**
```go
// Write config to Consul KV
consul.KV().Put(&api.KVPair{
    Key:   "service/myservice/config/port",
    Value: []byte("8080"),
}, nil)

consul.KV().Put(&api.KVPair{
    Key:   "service/myservice/config/feature_flags/enable_rag",
    Value: []byte("true"),
}, nil)
```

**Path convention**: `service/[service-name]/config/[category]/[key]`

### Delivery Layer

#### Option 1: Vault Agent Template (Secrets Only)

**When to use:**
- Service only needs secrets from Vault
- No dynamic configuration from Consul
- Simple .env file or config file generation
- Examples: PostgreSQL passwords, API keys

**How it works:**
1. Vault Agent runs as systemd service (`vault-agent-eos.service`)
2. Agent authenticates via AppRole
3. Renders template files with secrets from Vault
4. Watches Vault for changes, re-renders on rotation

**Implementation:**
```hcl
# /etc/vault.d/templates/myservice.env.ctmpl
DATABASE_PASSWORD={{ with secret "secret/myservice/db_password" }}{{ .Data.data.value }}{{ end }}
API_KEY={{ with secret "secret/myservice/api_key" }}{{ .Data.data.value }}{{ end }}
JWT_SECRET={{ with secret "secret/myservice/jwt_secret" }}{{ .Data.data.value }}{{ end }}
```

```hcl
# Add to vault agent config
template {
  source      = "/etc/vault.d/templates/myservice.env.ctmpl"
  destination = "/opt/myservice/.env"
  perms       = "0640"
  command     = "docker compose -f /opt/myservice/docker-compose.yml up -d --force-recreate"
}
```

**Pros:**
- Already integrated in Eos (vault-agent-eos.service exists)
- Automatic secret rotation
- Secure: secrets never written to disk except in final config
- Simple for secrets-only scenarios

**Cons:**
- Cannot access Consul KV
- Vault Agent must be running
- Limited to Vault data sources

#### Option 2: Consul Template (Secrets + Config)

**When to use:**
- Service needs both Vault secrets AND Consul configuration
- Dynamic configuration changes without redeployment
- Service discovery via Consul
- Examples: Multi-tenant apps, microservices with dynamic config

**How it works:**
1. Consul Template runs as systemd service or Docker sidecar
2. Connects to both Consul and Vault
3. Renders templates combining both data sources
4. Watches both for changes, re-renders on updates

**Implementation:**
```hcl
# /etc/consul-template.d/myservice.env.ctmpl
# From Consul KV
PORT={{ key "service/myservice/config/port" }}
ENABLE_RAG={{ key "service/myservice/config/feature_flags/enable_rag" }}
LOG_LEVEL={{ key "service/myservice/config/log_level" }}

# From Vault
DATABASE_PASSWORD={{ with secret "secret/myservice/db_password" }}{{ .Data.data.value }}{{ end }}
API_KEY={{ with secret "secret/myservice/api_key" }}{{ .Data.data.value }}{{ end }}

# Service discovery via Consul
{{ range service "database" }}
DATABASE_URL=postgresql://user:password@{{ .Address }}:{{ .Port }}/mydb
{{ end }}
```

```hcl
# /etc/consul-template.d/myservice.hcl
consul {
  address = "localhost:8500"
}

vault {
  address = "https://localhost:8200"
  token   = "{{ file "/run/eos/vault_agent_eos.token" }}" # Reuse Vault Agent token
  unwrap_token = false
  renew_token = true
}

template {
  source      = "/etc/consul-template.d/myservice.env.ctmpl"
  destination = "/opt/myservice/.env"
  perms       = "0640"
  command     = "docker compose -f /opt/myservice/docker-compose.yml up -d --force-recreate"
  wait {
    min = "2s"
    max = "10s"
  }
}
```

**Pros:**
- Access to both Vault AND Consul
- Service discovery built-in
- Dynamic config updates
- Can template ANY file format (env, JSON, YAML, HCL)

**Cons:**
- Additional service to manage
- More complex than Vault Agent alone
- Requires both Consul and Vault to be healthy

#### Option 3: Custom Entrypoint (Simple/Legacy)

**When to use:**
- Quick prototyping
- Legacy services not yet migrated
- Temporary deployments
- Services that don't support file-based config

**Implementation:**
```bash
#!/bin/bash
# /opt/myservice/entrypoint.sh

# Fetch secrets from Vault using agent token
export DATABASE_PASSWORD=$(VAULT_TOKEN=$(cat /run/eos/vault_agent_eos.token) vault kv get -field=value secret/myservice/db_password)
export API_KEY=$(VAULT_TOKEN=$(cat /run/eos/vault_agent_eos.token) vault kv get -field=value secret/myservice/api_key)

# Fetch config from Consul
export PORT=$(consul kv get service/myservice/config/port)
export ENABLE_RAG=$(consul kv get service/myservice/config/feature_flags/enable_rag)

# Start main process
exec /app/myservice
```

**Pros:**
- Simple, no additional daemons
- Works with any service
- Easy to debug

**Cons:**
- No automatic rotation
- Secrets in environment variables (less secure)
- No watch/reload on changes
- Must restart container for updates

### Decision Matrix

| Scenario | Storage | Delivery | Example |
|----------|---------|----------|---------|
| **Secrets only, static** | Vault | Vault Agent Template | Database passwords, TLS certs |
| **Secrets + static config** | Vault + .env file | Vault Agent + static file | Simple web apps |
| **Secrets + dynamic config** | Vault + Consul KV | Consul Template | Multi-tenant SaaS, microservices |
| **Service discovery needed** | Vault + Consul | Consul Template | Distributed systems |
| **Quick prototype** | Vault | Custom entrypoint | Development, testing |

### Eos Standard Pattern (Recommended)

For new services in Eos, use **Consul Template** as the standard:

**Rationale:**
1. **Unified approach**: One tool for all use cases
2. **Future-proof**: Supports adding Consul config later without refactoring
3. **Service discovery**: Built-in support for Consul catalog
4. **Consistent**: All services use same pattern
5. **Observable**: Consul Template has built-in monitoring

**Implementation checklist:**
- [ ] Store secrets in Vault via `secrets.SecretManager.GetOrGenerateServiceSecrets()`
- [ ] Store non-secret config in Consul KV at `service/[name]/config/`
- [ ] Create template file at `/etc/consul-template.d/[service].env.ctmpl`
- [ ] Create Consul Template config at `/etc/consul-template.d/[service].hcl`
- [ ] Add systemd service `consul-template-[service].service` OR Docker sidecar
- [ ] Template renders to `/opt/[service]/.env` with perms 0640
- [ ] Command triggers service restart on template change

### Migration Path

**Existing services using static .env:**
1. Phase 1: Continue using `secretManager.GetOrGenerateServiceSecrets()` (no change)
2. Phase 2: Create Consul Template to render .env from Vault (secrets.SecretManager still stores)
3. Phase 3: Move non-secret config to Consul KV
4. Phase 4: Remove static .env generation from Eos install code

**Example: BionicGPT Migration**
```
Current: Eos writes .env file at install time with secrets from Vault
Target:  Consul Template renders .env from Vault (secrets) + Consul KV (config)

Steps:
1. Create /etc/consul-template.d/bionicgpt.env.ctmpl
2. Create /etc/consul-template.d/bionicgpt.hcl
3. Create consul-template-bionicgpt.service
4. Move feature flags to Consul KV (ENABLE_RAG, ENABLE_AUDIT_LOG)
5. Keep secrets in Vault (POSTGRES_PASSWORD, JWT_SECRET, LITELLM_MASTER_KEY)
6. Remove static .env generation from pkg/bionicgpt/install.go
```

### Reference Implementation

See existing patterns:
- Vault Agent: [pkg/vault/phase13_write_agent_config.go](pkg/vault/phase13_write_agent_config.go)
- Vault Agent template: [pkg/shared/vault_agent.go](pkg/shared/vault_agent.go)
- Secret storage: [pkg/secrets/manager.go](pkg/secrets/manager.go)

## Architecture Enforcement: cmd/ vs pkg/

**The Iron Rule**: `cmd/` = Cobra orchestration ONLY. `pkg/` = ALL business logic.

### Good Example: cmd/fix/consul.go (✓ ~60 lines)
```go
// cmd/fix/consul.go - PURE ORCHESTRATION
func runConsulFix(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    // Parse flags
    dryRun, _ := cmd.Flags().GetBool("dry-run")
    permissionsOnly, _ := cmd.Flags().GetBool("permissions-only")

    // Create config
    config := &fix.Config{
        DryRun:          dryRun,
        PermissionsOnly: permissionsOnly,
    }

    // Delegate to pkg/ - ALL business logic lives there
    return fix.RunFixes(rc, config)
}
```

### Bad Example: Business Logic in cmd/ (✗ 400+ lines)
```go
// cmd/fix/something.go - VIOLATES ARCHITECTURE
func runSomethingFix(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    // ✗ WRONG: File operations in cmd/
    info, err := os.Stat("/etc/something/config.hcl")
    if err != nil { ... }

    // ✗ WRONG: Permission fixing in cmd/
    if err := os.Chmod(path, 0640); err != nil { ... }

    // ✗ WRONG: Loops and complex logic in cmd/
    for _, path := range paths {
        // Business logic here...
    }

    // This should ALL be in pkg/something/fix/fix.go!
}
```

### Correct Pattern: Move to pkg/
```go
// cmd/fix/something.go (~60 lines)
func runSomethingFix(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    config := parseFlags(cmd)
    return somethingfix.RunFixes(rc, config) // ✓ Delegate to pkg/
}

// pkg/something/fix/fix.go
func RunFixes(rc *eos_io.RuntimeContext, config *Config) error {
    // ✓ ASSESS
    issues := assessPermissions(rc)

    // ✓ INTERVENE
    if !config.DryRun {
        results := fixPermissions(rc, issues)
    }

    // ✓ EVALUATE
    displayResults(rc, results)
    return nil
}
```

### Enforcement Heuristics
- **cmd/ file >100 lines?** → Move business logic to pkg/
- **File operations (os.Stat, os.Chmod)?** → Must be in pkg/
- **Loops over data structures?** → Must be in pkg/
- **Complex conditionals?** → Must be in pkg/
- **Only cobra, flag parsing, delegation?** → OK in cmd/

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

### Pre-Completion Review Checklist

Before completing any task, verify:

**Architecture Compliance (P0)**:
- [ ] All business logic is in `pkg/`
- [ ] `cmd/` files only contain orchestration
- [ ] `cmd/` files are <100 lines (if not, refactor to pkg/)
- [ ] No file operations (os.Stat, os.Chmod) in cmd/
- [ ] No loops or complex conditionals in cmd/

**Pattern Compliance (P0)**:
- [ ] pkg/ functions follow Assess → Intervene → Evaluate
- [ ] All operations use RuntimeContext
- [ ] All logging uses otelzap.Ctx(rc.Ctx)
- [ ] Secrets use SecretManager
- [ ] Errors include context and remediation

**Testing (P0)**:
- [ ] `go build -o /tmp/eos-build ./cmd/` compiles
- [ ] `go vet ./pkg/...` passes
- [ ] `go vet ./cmd/...` passes
- [ ] `gofmt -l` returns nothing

## Common Anti-Patterns

| Never Do This | Always Do This |
|--------------|----------------|
| `fmt.Println("text")` | `logger.Info("text")` |
| Business logic in `cmd/` | Delegate to `pkg/` (see Architecture Enforcement) |
| `os.Stat()` in `cmd/*.go` | Move to `pkg/*/assess.go` |
| File operations in `runCommand()` | Create `pkg/*/fix.go` with business logic |
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