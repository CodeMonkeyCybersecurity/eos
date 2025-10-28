# CLAUDE.md

*Last Updated: 2025-01-28*

AI assistant guidance for Eos - A Go-based CLI for Ubuntu server administration by Code Monkey Cybersecurity (ABN 77 177 673 061).

## Mission & Values

### Philosphy
- **Human centric**: Technology serves humans, not the other way around, actionable output, addresses barriers to entry, encourage end-user ducation and self-efficacy, feminist (for example, informed consent), safe effective high-quality
- **Evidence based**: accepts falliblism, error correction, value for time, value for money, decisions grounded in security research and best practices
- **Sustainable innovation**: Maintainable code, comprehensive documentation, iterative improvement, response ready, incorporates recent research and best practice. Solve problems once, encode in Eos, never solve again
- **Collaboration and listening**: adversarial collaboration, transparent decision making, ownership accountability responsibility, open source, codesign

**Iterative Philosophy**: Eos is built iteratively. We build on what exists, solve complex problems once, encode them in Eos, and never solve them again. Each improvement makes the next one easier.

**Code Integration Philosophy**: When writing new code, ALWAYS iterate on existing functions rather than creating new ones. Check for existing functionality in the codebase first. If similar functionality exists, enhance it rather than duplicate it. Only deprecate functions if absolutely necessary - prefer evolution over replacement. Ensure all new code is properly wired into existing systems and follows established patterns.

##  CRITICAL RULES (P0 - Breaking)

These violations cause immediate failure:

1. **Logging**: ONLY use `otelzap.Ctx(rc.Ctx)` - NEVER `fmt.Print*/Println`
   - **CRITICAL**: Structured logging (`logger.Info/Warn/Error`) goes to BOTH terminal AND telemetry
   - User sees ALL logger output on their terminal in real-time
   - `fmt.Println` is unstructured - breaks telemetry, forensics, and debugging
   - This is a dev tool - verbose structured output is fine and helps debugging
   - **NO EXCEPTIONS**: Always use logger, even for user-facing output
2. **Architecture**: Business logic in `pkg/`, orchestration ONLY in `cmd/` (see Architecture Enforcement below). Use official and well supported SDKs and APIs where possible.
3. **Pattern**: ALWAYS follow Assess → Intervene → Evaluate in helpers
4. **Context**: Always use `*eos_io.RuntimeContext` for all operations
5. **Completion**: Must pass `go build`, `golangci-lint run`, `go test -v ./pkg/...`
6. **Secrets**: Use `secrets.SecretManager` for credentials - NEVER hardcode. Use `secrets.SecretManager.GetOrGenerateServiceSecrets()` for service secrets. And leverage vault for secrets management.
7. **Security**: Complete a red team code review and generic targeted criticism of your work before you commit
8. **Evidence-based, adversarially collaborative** approach always with yourself and with me
9. **READMEs** Put a README.md in each directory to document the purpose of the directory and how to use it.
10. **Pre-commit validation**: ALWAYS run `go build -o /tmp/eos-build ./cmd/` before completing a task. If build fails, fix ALL errors before responding to user. Zero tolerance for compile-time errors.
11. **Code Integration & Iteration (P0 - CRITICAL)**: Before writing new code, search for existing functionality. ALWAYS iterate on and enhance existing functions rather than creating duplicates. Ensure all code is properly wired into existing systems. Only deprecate when absolutely necessary - prefer evolution over replacement. Verify integration points work correctly.
12. **Constants - SINGLE SOURCE OF TRUTH (ZERO HARDCODED VALUES - P0)**: NEVER use hardcoded literal values in code. Each value must be a named constant defined in EXACTLY ONE place.
    - **Service-specific constants**: `pkg/[service]/constants.go`
      - Vault: `pkg/vault/constants.go`
      - Consul: `pkg/consul/constants.go`
      - Nomad: `pkg/nomad/constants.go`
    - **Shared infrastructure**: `pkg/shared/`
      - Ports: `pkg/shared/ports.go`
      - Common paths: `pkg/shared/paths.go`
    - **COMPREHENSIVE list of FORBIDDEN hardcoded values**:
      - ✗ **File paths**: `"/usr/local/bin/vault"`, `"/etc/vault.d"`, `"/opt/vault"`
      - ✗ **IP addresses**: `"shared.GetInternalHostname"`, `"0.0.0.0"`, `"localhost"`
      - ✗ **Port numbers**: `8200`, `8500`, `4646`
      - ✗ **Hostnames**: `"localhost"`, `"vault"`, `"consul"`
      - ✗ **User/Group names**: `"vault"`, `"consul"`, `"root"`
      - ✗ **UID/GID values**: `995`, `0`, `1000` (lookup dynamically via user.Lookup)
      - ✗ **File permissions**: `0755`, `0644`, `0600`
      - ✗ **Environment variable names**: `"VAULT_ADDR"`, `"CONSUL_HTTP_ADDR"`
      - ✗ **Service names**: `"vault.service"`, `"consul.service"`
      - ✗ **URLs/Endpoints**: `"https://shared.GetInternalHostname:8200"`, `"/v1/sys/health"`
      - ✗ **Timeouts/Durations**: `5 * time.Second`, `30 * time.Minute`
      - ✗ **Retry counts**: `5`, `3`, delay values
      - ✗ **Storage paths**: `"secret/vault"`, `"service/consul/config"`
    - **Violation examples**:
      - ✗ `os.MkdirAll("/etc/vault.d", 0755)` → use `vault.VaultConfigDir, vault.VaultDirPerm`
      - ✗ `net.Listen("tcp", "shared.GetInternalHostname:8200")` → use `vault.LocalhostIP, shared.PortVault`
      - ✗ `exec.Command("systemctl", "start", "vault.service")` → use `vault.VaultServiceName`
    - **Circular import exception**: Document with `// NOTE: Duplicates B.ConstName to avoid circular import`
    - **Enforcement**: Run monthly audit: `scripts/audit_hardcoded_values.sh`
12. **File Permissions - SECURITY CRITICAL (P0)**: NEVER hardcode chmod/chown permissions (0755, 0600, etc.) in code. Use centralized permission constants.
    - **Vault permissions**: ONLY in `pkg/vault/constants.go` (VaultConfigPerm, VaultTLSKeyPerm, etc.)
    - **Consul permissions**: ONLY in `pkg/consul/constants.go`
    - **MUST document security rationale**: Each permission constant must include:
      - `// RATIONALE: Why this permission level`
      - `// SECURITY: What threats this mitigates`
      - `// THREAT MODEL: Attack scenarios prevented`
    - **Violation examples**:
      - ✗ `os.MkdirAll(dir, 0755)` - use `vault.VaultDirPerm`
      - ✗ `os.WriteFile(file, data, 0600)` - use `vault.VaultSecretFilePerm`
      - ✗ `os.Chmod(file, 0644)` - use `vault.VaultConfigPerm`
    - **Required for**: SOC2, PCI-DSS, HIPAA compliance audits
13. **Required Flag Prompting - HUMAN-CENTRIC (P0 - BREAKING)**: If a required flag is missing, NEVER fail immediately. ALWAYS offer interactive fallback with informed consent.
    - **Philosophy**: "Technology serves humans, not the other way around" - missing flags are barriers to entry that violate human-centric design
    - **Violation example**: `if flag == "" { return fmt.Errorf("--flag is required") }` ← BREAKS HUMAN-CENTRICITY
    - **Correct pattern**: Use fallback chain with informed consent:
      1. CLI flag (if explicitly set via `cmd.Flags().Changed()`)
      2. Environment variable (if configured, e.g., `VAULT_TOKEN`)
      3. Interactive prompt (if TTY available, with help text explaining WHY and HOW)
      4. Default value (if `AllowEmpty` is true and default makes sense)
      5. Error with remediation (if non-interactive mode, include clear steps)
    - **Required elements** (all MUST be present):
      - ✓ **Help text**: WHY is this required? HOW to get the value? (e.g., "Get via: vault token create")
      - ✓ **Source logging**: ALWAYS log which fallback was used (CLI/env/prompt) for observability
      - ✓ **Validation**: Validate input, retry with clear guidance (max 3 attempts)
      - ✓ **Security**: Use `IsSecret: true` for passwords/tokens (no terminal echo)
      - ✓ **Non-interactive handling**: Detect early, return error with actionable remediation
      - ✓ **Empty detection**: Use `cmd.Flags().Changed()` to distinguish `--flag=""` from not provided
    - **Implementation pattern**:
      ```go
      // GOOD: Human-centric with fallback chain
      tokenFlag, _ := cmd.Flags().GetString("token")
      tokenWasSet := cmd.Flags().Changed("token")

      result, err := interaction.GetRequiredString(rc, tokenFlag, tokenWasSet, &interaction.RequiredFlagConfig{
          FlagName:      "token",
          EnvVarName:    "VAULT_TOKEN",
          PromptMessage: "Enter Vault root token: ",
          HelpText:      "Required for cluster operations. Get via: vault token create",
          IsSecret:      true,
      })
      if err != nil {
          return fmt.Errorf("failed to get vault token: %w", err)
      }

      log.Info("Using Vault token", zap.String("source", string(result.Source)))
      ```
    - **Reference implementation**: [cmd/update/vault_cluster.go:287-334](cmd/update/vault_cluster.go#L287-L334) (`getAuthenticatedVaultClient` helper demonstrates pattern)
    - **Migration**: Required for NEW code starting 2025-01-28. Existing ad-hoc patterns grandfathered but encouraged to migrate.


## Quick Decision Trees

```
New Service Deployment?
├─ System service (fail2ban, osquery) → Docker Compose in /opt/[service]
├─ Web application (Umami, Grafana) → Docker Compose in /opt/[service]
└─ Infrastructure (Vault, Consul) → Check existing patterns in pkg/

Need User Input (P0 - Human-Centric)?
├─ Flag explicitly provided (cmd.Flags().Changed) → Use it
├─ Env var set (and configured in RequiredFlagConfig) → Use it, log source
├─ Flag required & missing & TTY available → Use interaction.GetRequiredString(...)
│  ├─ Show help text (WHY needed, HOW to get)
│  ├─ Prompt with validation (IsSecret: true for passwords)
│  ├─ Retry on validation failure (max 3 attempts)
│  └─ Log which source provided value (observability)
├─ Flag required & missing & non-interactive → Error with remediation steps
└─ Flag optional → Use default value, don't prompt

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
└─ VERB-FIRST only: create, read, list, update (includes --fix), delete (+ self, backup, build, deploy, promote, env)

Configuration Drift Correction (P0 - NEW PATTERN)?
├─ Service has drifted from canonical state (permissions, config values)?
│  ├─ Use: eos update <service> --fix
│  ├─ Compares: Current state vs. 'eos create <service>' canonical state
│  ├─ Corrects: Permissions, ownership, config values, duplicate binaries
│  ├─ Verifies: Post-fix state matches canonical
│  └─ Example: eos update vault --fix
│
├─ Want to check drift without fixing?
│  ├─ Use: eos update <service> --fix --dry-run
│  ├─ Pattern: --dry-run works consistently across all update operations
│  ├─ Example: eos update consul --fix --dry-run
│  └─ Example: eos update vault --ports X->Y --dry-run
│
├─ CI/CD pipeline verification?
│  └─ Use: eos update <service> --fix --dry-run && check exit code
│
└─ Old 'eos fix' commands?
   ├─ DEPRECATED: Use 'eos update <service> --fix' instead
   ├─ eos fix vault       →  eos update vault --fix
   ├─ eos fix consul      →  eos update consul --fix
   ├─ eos fix mattermost  →  eos update mattermost --fix
   └─ Will be removed in Eos v2.0.0 (approximately 6 months)

Adding a Constant?
├─ Vault-related path/URL → pkg/vault/constants.go ONLY
├─ Consul-related path/URL → pkg/consul/constants.go ONLY
├─ Port number → pkg/shared/ports.go ONLY
├─ Service-specific config → pkg/[service]/constants.go
├─ Found duplicate constant → DELETE all but ONE, update all references
└─ Circular import prevents use → Document duplication reason in comment

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

Docker Operations (P1 - CRITICAL)?
├─ Container operations (start, stop, inspect, logs):
│  └─ ALWAYS use Docker SDK (github.com/docker/docker/client)
│  └─ Example: pkg/container/docker.go, pkg/docker/compose_precipitate.go
│
├─ Docker Compose validation:
│  ├─ ALWAYS use: docker.ValidateComposeWithShellFallback(ctx, composeFile, envFile)
│  ├─ Strategy: SDK first (35μs), shell fallback if SDK fails
│  │  1. SDK validation (pkg/docker/compose_validate.go:ValidateComposeFile)
│  │     - YAML parsing + variable substitution + image validation
│  │     - No docker CLI dependency, works in CI
│  │  2. Shell fallback ('docker compose config')
│  │     - Handles edge cases, authoritative validation
│  ├─ Example: pkg/hecate/validation_files.go:49 ✓
│  └─ Tests: pkg/docker/compose_validate_test.go (12 tests, all passing)
│
├─ User-facing operations (docker compose up -d):
│  ├─ Shell acceptable (user needs to see output)
│  └─ BUT validate with SDK FIRST
│
└─ Template rendering:
   └─ Use pkg/templates/render.go (unified, security-hardened)
   └─ NO ad-hoc template.New() scattered in packages

Flag Validation (P0 - CRITICAL)?
└─ Command accepts positional args (cobra.ExactArgs, cobra.MaximumNArgs)?
   ├─ ALWAYS add at start of RunE: if err := verify.ValidateNoFlagLikeArgs(args); err != nil { return err }
   ├─ Prevents '--' separator bypass (e.g., 'eos delete env prod -- --force')
   ├─ Required for ALL commands with positional arguments
   └─ See: pkg/verify/validators.go:ValidateNoFlagLikeArgs()

Dependency Not Found (P0 - CRITICAL - Human-Centric)?
├─ NEVER error out immediately when dependency missing
├─ ALWAYS offer informed consent to install:
│  ├─ Explain what the dependency is and why it's needed
│  ├─ Show installation command(s) clearly
│  ├─ Ask y/N (default No for safety)
│  └─ If yes: attempt auto-install OR guide user through manual install
│
└─ Pattern (use pkg/interaction/dependency.go):
   ├─ Check: interaction.CheckDependencyWithPrompt(rc, interaction.DependencyConfig{...})
   ├─ Provides: Clear explanation, install commands, consent prompt
   ├─ Handles: Auto-install (if safe) or graceful exit with instructions
   └─ Example: Ollama, Docker, system packages
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
- [ ] Required flags use interaction.GetRequiredString() with fallback chain (P0 #13)

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
| Error when dependency missing | Offer informed consent to install (see Dependency Not Found) |
| Silent dependency checks | Use `interaction.CheckDependencyWithPrompt()` |
| `eos fix vault` | `eos update vault --fix` (fix is deprecated) |
| `eos fix consul` | `eos update consul --fix` |
| `eos fix mattermost` | `eos update mattermost --fix` |
| `if flag == "" { return error }` | Use `interaction.GetRequiredString()` (P0 - human-centric) |
| Ad-hoc flag prompting in cmd/ | Use unified `pkg/interaction/required_flag.go` pattern |
| Prompt without help text | Always include HelpText (WHY needed, HOW to get) |
| Silent env var fallback | Always log which source provided value (observability) |
| Can't detect `--flag=""` vs missing | Use `cmd.Flags().Changed()` to distinguish |

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

## Vault Cluster Authentication (P1 - CRITICAL)

**RULE**: Vault cluster operations require admin-level tokens. Use hierarchical authentication with clear security boundaries.

### Architecture Pattern

Vault cluster operations (Raft, Autopilot, snapshots) use **shell commands** (`vault operator raft ...`) rather than SDK clients. This creates a unique authentication pattern:

1. **Token-only return**: Functions return `token string`, not `*api.Client`
2. **Environment variable usage**: Token set via `VAULT_TOKEN` env var for shell commands
3. **Validation before use**: Token validated via SDK, then used in shell commands

### Authentication Hierarchy

Authentication attempts in order (fail-fast on deterministic errors):

```go
// 1. --token flag (highest priority - explicit user input)
if token, _ := cmd.Flags().GetString("token"); token != "" {
    // Validate token has required capabilities
    _, err := vault.GetVaultClientWithToken(rc, token)
    if err != nil {
        return "", fmt.Errorf("invalid token: %w", err)
    }
    return token, nil
}

// 2. VAULT_TOKEN environment variable (CI/CD, scripted usage)
if token := os.Getenv("VAULT_TOKEN"); token != "" {
    _, err := vault.GetVaultClientWithToken(rc, token)
    if err != nil {
        return "", fmt.Errorf("invalid token: %w", err)
    }
    return token, nil
}

// 3. Admin authentication (Vault Agent → AppRole → Root with consent)
adminClient, err := vault.GetAdminClient(rc)
if err != nil {
    return "", fmt.Errorf("admin authentication failed: %w", err)
}
return adminClient.Token(), nil
```

### Token Validation Sequence

Validation order matters - fail fast on infrastructure issues:

```go
// Check 0: Vault seal status (BEFORE token validation)
sealStatus, err := client.Sys().SealStatus()
if err != nil {
    return fmt.Errorf("cannot connect to Vault: %w", err)
}
if sealStatus.Sealed {
    return fmt.Errorf("Vault is sealed - unseal first")
}

// Check 1: Token validity
secret, err := client.Auth().Token().LookupSelf()
if err != nil {
    return fmt.Errorf("token invalid or expired: %w", err)
}

// Check 2: Token TTL (Time To Live)
ttlSeconds := secret.Data["ttl"].(json.Number).Int64()
if ttlSeconds < 60 {
    return fmt.Errorf("token expires in %ds - too short for cluster operations", ttlSeconds)
}
if ttlSeconds < 300 {
    logger.Warn("Token expires soon", zap.Int64("ttl_seconds", ttlSeconds))
}

// Check 3: Required policies
hasAdminPolicy := false
for _, policy := range secret.Data["policies"].([]interface{}) {
    if policy == "root" || policy == shared.EosAdminPolicyName {
        hasAdminPolicy = true
        break
    }
}
if !hasAdminPolicy {
    return fmt.Errorf("token lacks eos-admin-policy or root")
}

// Check 4: Specific capabilities
capabilities, err := client.Sys().CapabilitiesSelf("sys/storage/raft/configuration")
if err != nil {
    return fmt.Errorf("cannot verify capabilities: %w", err)
}
hasCapability := false
for _, cap := range capabilities {
    if cap == "root" || cap == "sudo" || cap == "read" {
        hasCapability = true
        break
    }
}
if !hasCapability {
    return fmt.Errorf("token lacks required Raft capabilities")
}
```

### Token Security

**CRITICAL**: Tokens are secrets and MUST NOT be logged.

```go
// GOOD: Never log token values
logger.Info("Using token from --token flag")  // ✓ No token value

// BAD: Logging token exposes secrets
logger.Info("Token", zap.String("value", token))  // ✗ NEVER DO THIS

// GOOD: Use sanitization helper if you need to reference token
logger.Debug("Token type", zap.String("token", sanitizeTokenForLogging(token)))
// Output: "Token type: hvs.***"
```

**Token sanitization helper** (in `pkg/vault/auth_cluster.go`):
```go
// sanitizeTokenForLogging returns safe version for logging
func sanitizeTokenForLogging(token string) string {
    if len(token) <= 4 {
        return "***"
    }
    prefix := token[:4]
    if prefix == "hvs." || prefix == "s.12" {
        return prefix + "***"
    }
    return "***"
}
```

### Error Messages

Errors must be **actionable** with clear remediation steps:

```go
// GOOD: Clear remediation
return fmt.Errorf("Vault is sealed - cannot perform cluster operations\n\n"+
    "Unseal Vault first:\n"+
    "  vault operator unseal\n"+
    "  Or: eos update vault unseal\n\n"+
    "Seal status:\n"+
    "  Sealed: %t\n"+
    "  Progress: %d/%d keys provided",
    sealStatus.Sealed, sealStatus.Progress, sealStatus.T)

// BAD: Vague error
return fmt.Errorf("operation failed")  // ✗ Not actionable
```

### Implementation Files

- **Orchestration**: [cmd/update/vault_cluster.go](cmd/update/vault_cluster.go) - Command handlers, flag parsing
- **Business Logic**: [pkg/vault/auth_cluster.go](pkg/vault/auth_cluster.go) - Authentication, validation
- **Cluster Operations**: [pkg/vault/raft_*.go](pkg/vault/) - Raft, Autopilot, snapshot functions

### Common Pitfalls

1. **✗ Returning unused client**: Cluster ops use shell commands, not SDK client
   ```go
   // BAD: Returns client that's never used
   func getAuth(rc *RC, cmd *cobra.Command) (*api.Client, string, error)

   // GOOD: Returns only token
   func getAuth(rc *RC, cmd *cobra.Command) (string, error)
   ```

2. **✗ Validating token before seal check**: Sealed Vault fails token lookup
   ```go
   // BAD: Token validation fails on sealed Vault with confusing error
   secret, err := client.Auth().Token().LookupSelf()  // ✗ Fails if sealed

   // GOOD: Check seal status FIRST
   sealStatus, err := client.Sys().SealStatus()  // ✓ Check seal first
   if sealStatus.Sealed { return fmt.Errorf("vault sealed") }
   secret, err := client.Auth().Token().LookupSelf()  // Then validate token
   ```

3. **✗ Ignoring token TTL**: Long operations fail mid-execution
   ```go
   // BAD: No TTL check, cluster snapshot may take 10+ minutes
   err := vault.TakeRaftSnapshot(rc, token, outputPath)  // ✗ May fail if token expires

   // GOOD: Reject short-lived tokens upfront
   if ttlSeconds < 60 {
       return fmt.Errorf("token expires in %ds - get longer-lived token", ttlSeconds)
   }
   ```

4. **✗ Logging token values**: Exposes secrets in logs/telemetry
   ```go
   // BAD: Token in logs
   logger.Info("Token", zap.String("value", token))  // ✗ SECURITY VIOLATION

   // GOOD: Never log tokens
   logger.Info("Using token from --token flag")  // ✓ No value logged
   ```

### Reference Implementation

See complete working example: [cmd/update/vault_cluster.go:272-324](cmd/update/vault_cluster.go#L272-L324)

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

### Automatic Debug Output Capture (PLANNED - Infrastructure Ready)

**Current Status**: Infrastructure implemented in [pkg/debug/capture.go](pkg/debug/capture.go) (151 lines), but NOT YET integrated into debug commands.

**Evidence of Non-Integration**:
- ✅ `pkg/debug/capture.go` exists with `CaptureDebugOutput()` and `CaptureStdoutFunc()`
- ❌ Zero debug commands in `cmd/debug/*.go` use these functions
- ❌ Commands like [cmd/debug/vault.go:266-285](cmd/debug/vault.go#L266-L285) implement their own file writing instead

**When to Migrate**: After completing current work (drift correction, Ceph integration), migrate debug commands one at a time with comprehensive testing.

**Target Philosophy**: All `eos debug ...` commands automatically save their output to the user's directory for forensic analysis. No flags required - fully automatic, non-fatal if capture fails.

**Target Capture Location**: `~/.eos/debug/eos-debug-{service}-{timestamp}.{ext}`
- Fallback to `/tmp` if home directory unavailable
- Timestamped filenames: `20060102-150405` format
- Format-aware extensions: `.txt`, `.json`, `.md`

**Two Available Capture Patterns**:

1. **Direct Capture** (for commands returning strings):
```go
// EXAMPLE - Not yet implemented in actual commands
func runVaultDebug(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    output, err := vault.GenerateDebugReport(rc, format)
    if err != nil {
        return fmt.Errorf("failed to generate debug report: %w", err)
    }

    // Automatic capture
    captureConfig := &debug.CaptureConfig{
        ServiceName: "vault",
        Output:      output,
        Format:      format,
    }
    if _, captureErr := debug.CaptureDebugOutput(rc, captureConfig); captureErr != nil {
        logger.Warn("Failed to auto-capture debug output", zap.Error(captureErr))
    }

    fmt.Print(output)
    return nil
}
```

2. **Stdout Wrapper** (for commands printing directly):
```go
// EXAMPLE - Not yet implemented in actual commands
func runDebugConsul(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    return debug.CaptureStdoutFunc(rc, "consul", func() error {
        return consuldebug.RunDiagnostics(rc, config)
    })
}
```

**Migration Checklist (Per Debug Command)**:
- [ ] Read current command implementation
- [ ] Identify if command returns output string or prints to stdout
- [ ] Choose appropriate capture pattern (Direct vs Stdout Wrapper)
- [ ] Integrate capture function
- [ ] Remove any existing `--output` flag logic (replaced by automatic capture)
- [ ] Test with `go build && sudo eos debug [service]`
- [ ] Verify file saved to `~/.eos/debug/`
- [ ] Verify user sees log message with file location
- [ ] Verify output still displays correctly to user

**Affected Commands** (13 files to migrate):
```
cmd/debug/vault.go          (266 lines - has --output flag, remove it)
cmd/debug/consul.go         (272 lines)
cmd/debug/nomad.go          (512 lines)
cmd/debug/bionicgpt.go      (9210 bytes)
cmd/debug/ceph.go           (5451 bytes)
cmd/debug/hecate.go         (2889 bytes)
cmd/debug/mattermost.go     (2586 bytes)
cmd/debug/openwebui.go      (12715 bytes)
cmd/debug/wazuh.go          (5160 bytes)
cmd/debug/bootstrap.go      (26483 bytes - may not need capture)
cmd/debug/iris.go           (48743 bytes - may not need capture)
cmd/debug/watchdog_traces.go (10189 bytes - may not need capture)
```

**Reference**: See [pkg/debug/capture.go](pkg/debug/capture.go) for implementation details

### Evidence Collection (PLANNED - Infrastructure Ready)

**Current Status**: Infrastructure implemented in [pkg/remotedebug/evidence.go](pkg/remotedebug/evidence.go) (265 lines), but NOT YET integrated into remotedebug commands.

**Evidence of Non-Integration**:
- ✅ `pkg/remotedebug/evidence.go` exists with full evidence repository implementation
- ❌ Zero commands in `cmd/` use `NewEvidenceRepository()`, `CreateEvidence()`, or `StoreSession()`
- ❌ Remote debug SSH command doesn't persist evidence to disk yet

**Why We Built This**: Original remotedebug implementation had critical gaps:
- ❌ Evidence only lived in memory during execution
- ❌ No forensic trail if remotedebug crashed or connection dropped
- ❌ Evidence was only human-readable strings, not machine-parseable
- ❌ No metadata for chain of custody or integrity verification

**Solution Built (Not Yet Used)**: Structured evidence collection with automatic capture to disk.

**Evidence vs Debug Output (Important Distinction)**:
- **Debug output**: Interactive diagnostic sessions, capture is backup
- **Evidence collection**: Automated gathering over SSH, capture IS the primary artifact
- **Different requirements**: Evidence needs chain of custody, integrity verification, structured storage

**Evidence Types**:
```go
type EvidenceType string

const (
    EvidenceTypeFile      EvidenceType = "file"       // File system evidence
    EvidenceTypeCommand   EvidenceType = "command"    // Command output
    EvidenceTypeLogEntry  EvidenceType = "log"        // Log file entry
    EvidenceTypeMetric    EvidenceType = "metric"     // System metric
    EvidenceTypeConfig    EvidenceType = "config"     // Configuration file
    EvidenceTypeProcess   EvidenceType = "process"    // Process information
    EvidenceTypeNetwork   EvidenceType = "network"    // Network state
    EvidenceTypeSnapshot  EvidenceType = "snapshot"   // System snapshot
)
```

**Structured Evidence**:
```go
type StructuredEvidence struct {
    Type      EvidenceType      // Type of evidence
    Timestamp time.Time         // When collected
    Source    string            // Where from (hostname/IP)
    Collector string            // Who collected (user@host)
    Data      json.RawMessage   // Actual evidence (structured JSON)
    Checksum  string            // SHA256 for integrity verification
    Metadata  map[string]string // Additional context
}
```

**Evidence Session**:
```go
type EvidenceSession struct {
    SessionID   string               // Unique session identifier
    StartTime   time.Time            // Session start
    EndTime     time.Time            // Session end
    Host        string               // Target hostname
    Collector   string               // Who ran the collection
    Command     string               // Command that triggered collection
    Evidence    []StructuredEvidence // All collected evidence
    Issues      []Issue              // Detected issues
    Warnings    []Warning            // Warnings
    Report      *SystemReport        // Complete system report
}
```

**Storage Structure**:
```
~/.eos/evidence/
  ├── index.json                      # Searchable index (future)
  ├── 20251022-143052-vhost5/        # Per-session evidence
  │   ├── manifest.json               # Session metadata
  │   ├── evidence.json               # All structured evidence
  │   ├── issues.json                 # Detected issues with evidence
  │   ├── warnings.json               # Warnings
  │   ├── report.json                 # Complete system report
  │   └── summary.txt                 # Human-readable summary
```

**Usage Pattern**:
```go
// Create evidence repository
repo, err := remotedebug.NewEvidenceRepository()
if err != nil {
    return fmt.Errorf("failed to create evidence repository: %w", err)
}

// Create evidence item
diskEvidence, err := remotedebug.CreateEvidence(
    remotedebug.EvidenceTypeMetric,
    hostname,
    diskInfo, // Any struct that can be marshaled to JSON
)

// Store complete session
session := &remotedebug.EvidenceSession{
    SessionID:   "session-" + time.Now().Format("20060102-150405"),
    StartTime:   startTime,
    EndTime:     time.Now(),
    Host:        hostname,
    Collector:   "user@workstation",
    Command:     "eos remotedebug ssh",
    Evidence:    collectedEvidence,
    Issues:      analyzedIssues,
    Warnings:    warnings,
    Report:      systemReport,
}

sessionDir, err := repo.StoreSession(session)
if err != nil {
    logger.Warn("Failed to store evidence session", zap.Error(err))
} else {
    logger.Info("Evidence session saved",
        zap.String("location", sessionDir),
        zap.Int("evidence_count", len(session.Evidence)))
}
```

**Integrity Verification**:
```go
// Verify evidence hasn't been tampered with
if evidence.VerifyEvidence() {
    logger.Info("Evidence integrity verified")
} else {
    logger.Error("Evidence checksum mismatch - possible tampering")
}
```

**What We Did NOT Implement (With Reasons)**:

1. **❌ Evidence Signing/Encryption**
   - **WHY NOT**: Dev/ops tool, not forensic investigation tool
   - **ALTERNATIVE**: File permissions + checksums sufficient for integrity
   - **IF NEEDED**: Add when compliance requirements are clear

2. **❌ Chain-of-Custody Signatures**
   - **WHY NOT**: No legal requirement stated
   - **ALTERNATIVE**: Metadata tracking sufficient for troubleshooting
   - **IF NEEDED**: Add for specific compliance (SOC2, PCI-DSS, etc.)

3. **❌ Centralized Evidence Server**
   - **WHY NOT**: Over-engineering, network dependency
   - **ALTERNATIVE**: Local storage + optional rsync to central location
   - **IF NEEDED**: Users script `rsync ~/.eos/evidence/` to server

4. **❌ Automatic Retention/Rotation**
   - **WHY NOT**: User's machine, user's policy
   - **ALTERNATIVE**: Manual cleanup: `rm -rf ~/.eos/evidence/2024*`
   - **IF NEEDED**: Add optional `--cleanup` flag later

**Cleanup Commands**:
```bash
# View evidence sessions
ls -lh ~/.eos/evidence/

# View specific session
cat ~/.eos/evidence/20251022-143052-vhost5/summary.txt

# Cleanup old evidence (manual)
find ~/.eos/evidence/ -type d -mtime +30 -exec rm -rf {} \;

# Cleanup by size (keep only 1GB)
du -sh ~/.eos/evidence/ | awk '$1 > 1 {print "Evidence directory exceeds 1GB"}'
```

**Reference**: See `pkg/remotedebug/evidence.go` for implementation details

## Flag Bypass Vulnerability Prevention (P0 - CRITICAL)

### The Vulnerability

When Cobra encounters the `--` separator in command-line arguments, it **stops parsing flags** and treats everything after it as positional arguments. This creates a security vulnerability where users can accidentally (or maliciously) bypass flag-based safety checks.

**Example:**
```bash
# User intends to use --force flag
sudo eos delete env production -- --force

# What Cobra sees:
# - Command: delete env
# - Args: ["production", "--force"]  # Both are positional args!
# - Flags: force=false  # Flag was never set!
```

**Security Impact:**
- Bypasses `--force` safety checks (production deletion, running VM deletion)
- Bypasses `--dry-run` validation
- Bypasses `--emergency-override` authentication
- Bypasses approval workflow requirements

### Affected Commands (40+ files)

Any command using `cobra.ExactArgs()`, `cobra.MaximumNArgs()`, or `cobra.MinimumNArgs()` is vulnerable.

**Priority 1 (Safety-Critical):**
- `cmd/delete/env.go` - Production environment deletion
- `cmd/delete/kvm.go` - Running VM forced deletion
- `cmd/promote/approve.go` - Emergency approval override
- `cmd/promote/stack.go` - Multi-environment promotion

**All affected:** See backup/*, create/*, delete/*, update/*, promote/* commands

### Mandatory Mitigation Pattern

**RULE**: ALL commands that accept positional arguments MUST validate them at the start of `RunE`.

```go
// REQUIRED at start of every RunE that accepts args
RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    logger := otelzap.Ctx(rc.Ctx)

    // CRITICAL: Detect flag-like args (--force, -f, etc.)
    if err := verify.ValidateNoFlagLikeArgs(args); err != nil {
        return err  // User-friendly error with remediation
    }

    // Rest of command logic...
})
```

### Implementation Details

See [pkg/verify/validators.go:271-294](pkg/verify/validators.go#L271-L294) for the validator implementation.

**What it catches:**
- Long flags: `--force`, `--dry-run`, `--emergency-override`
- Short flags: `-f`, `-v`, `-i`
- Allows negative numbers: `-1`, `-42` (distinguishes from flags)

**Error message example:**
```
argument 1 looks like a long flag: '--force'
Did you use the '--' separator by mistake?
Remove the '--' separator to use flags properly.
Example: Use 'eos delete env prod --force' instead of 'eos delete env prod -- --force'
```

### Migration Checklist

When adding this to existing commands:

1. Add import: `"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"`
2. Add validation as FIRST line in RunE (after logger initialization)
3. Test with: `eos [command] arg -- --flag` (should error)
4. Test normal usage: `eos [command] arg --flag` (should work)

### Testing

```bash
# Should FAIL with clear error
eos delete env production -- --force
eos create config -- hecate
eos promote approve id -- --emergency-override

# Should SUCCEED
eos delete env production --force
eos create config --hecate
eos promote approve id --emergency-override
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