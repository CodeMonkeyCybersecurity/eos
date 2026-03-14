---
description: Eos Go patterns — architecture, constants, logging, idempotency, retry logic
paths:
  - "**/*.go"
  - "pkg/**/*.go"
---

# Eos Go Patterns

## Architecture: cmd/ vs pkg/ (P0 — Breaking)

**cmd/**: Orchestration ONLY.
- Define `cobra.Command` with flags
- Parse flags into config struct
- Call `pkg/[feature]/Function(rc, config)`
- Return result — NO business logic
- **If cmd/ file exceeds 100 lines → move logic to pkg/**

**pkg/**: ALL business logic.
- Pattern: **ASSESS → INTERVENE → EVALUATE**
  1. ASSESS: Check current state
  2. INTERVENE: Apply changes if needed
  3. EVALUATE: Verify and report results
- Always use `*eos_io.RuntimeContext` for all operations

```go
// Good cmd/ file (thin orchestration)
RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    cfg := &vault.ClusterConfig{Token: tokenFlag}
    return vault.UpdateCluster(rc, cfg)  // all logic in pkg/
})

// Bad cmd/ file (business logic in cmd/)
RunE: func(cmd *cobra.Command, args []string) error {
    client := api.NewClient(...)  // WRONG — this belongs in pkg/
    resp, err := client.Do(...)   // WRONG
    return err
}
```

## Logging (P0 — Breaking)

**ALWAYS** use `otelzap.Ctx(rc.Ctx)` — structured logging goes to terminal AND telemetry.

**NEVER** use `fmt.Print*` / `fmt.Println` in pkg/ or cmd/ (except one exception below).

**Exception — cmd/debug/ final report rendering ONLY:**
```go
// CORRECT: diagnostics via logger, final output via fmt
logger.Info("Checking Vault config")    // diagnostic — telemetry captured
logger.Warn("Seal status: sealed")      // diagnostic
fmt.Print(report.Render())              // ONLY at end, after all telemetry
```

## Constants — Single Source of Truth (P0 — Breaking)

NEVER hardcode literal values. Every value must be a named constant defined in EXACTLY ONE place.

| Value type | Location |
|------------|----------|
| Port numbers | `pkg/shared/ports.go` |
| Common paths | `pkg/shared/paths.go` |
| Vault paths/URLs | `pkg/vault/constants.go` |
| Consul paths | `pkg/consul/constants.go` |
| Service-specific | `pkg/[service]/constants.go` |

**FORBIDDEN hardcoded values:**
```go
// WRONG — hardcoded everywhere
os.MkdirAll("/etc/vault.d", 0755)
net.Listen("tcp", "localhost:8200")
exec.Command("systemctl", "start", "vault.service")

// CORRECT — named constants
os.MkdirAll(vault.VaultConfigDir, vault.VaultDirPerm)
net.Listen("tcp", fmt.Sprintf("%s:%d", shared.LocalhostIP, shared.PortVault))
exec.Command("systemctl", "start", vault.VaultServiceName)
```

**Circular import exception**: Document with `// NOTE: Duplicates B.ConstName to avoid circular import`

**File permissions** must have security rationale in the constant definition:
```go
// VaultTLSKeyPerm restricts private key access to vault user only.
// RATIONALE: Private keys must not be world-readable.
// SECURITY: Prevents credential theft via filesystem access.
// THREAT MODEL: Mitigates insider threat and container escape attacks.
const VaultTLSKeyPerm = 0600
```

## Idempotency (P1)

All pkg/ operations MUST be safe to run multiple times:
- Check before creating: verify state before applying changes
- Use `os.MkdirAll` not `os.Mkdir` (no error if exists)
- Use upsert patterns for config writes
- Compare current state to desired state before modifying

## Retry Logic (P1)

**Transient failures → retry with backoff:**
- Network timeouts, connection refused (service starting)
- Lock contention, resource temporarily unavailable
- HTTP 429/503 (rate limiting, service overloaded)

**Deterministic failures → fail fast, no retry:**
- Config/validation errors, missing required files
- Authentication failures (wrong credentials)
- Permission denied

```go
// Transient: retry
err := retry.Do(func() error {
    return vault.CheckHealth(rc)
}, retry.Attempts(5), retry.Delay(2*time.Second))

// Deterministic: fail fast
if cfg.Token == "" {
    return fmt.Errorf("vault token required: %w", ErrMissingConfig)
}
```

## Error Context (P1)

Wrap errors with context at EVERY layer:
```go
// WRONG — no context
return err

// CORRECT — context at each layer
return fmt.Errorf("failed to initialize vault cluster: %w", err)
```

User-facing errors use typed error wrappers:
```go
return eos_err.NewUserError("vault token expired — run: vault token renew")
return eos_err.NewSystemError("vault unsealing failed", err)
```

Capture command output in errors:
```go
out, err := cmd.CombinedOutput()
if err != nil {
    return fmt.Errorf("command failed: %w\noutput: %s", err, out)
}
```

## Code Integration (P0)

**Before writing new code**, search for existing functionality:
- `grep -r "FunctionName" pkg/` to find existing implementations
- ALWAYS enhance existing functions rather than creating duplicates
- NEVER create a second HTTP client for the same service — add methods to the existing one
- Only deprecate functions if absolutely necessary — prefer evolution over replacement
- Verify integration points: ensure new code is wired into existing callers

## Common Anti-Patterns

| Anti-pattern | Correct approach |
|---|---|
| `fmt.Println("done")` in pkg/ | `logger.Info("operation complete", zap.String("op", "done"))` |
| New HTTP client for existing service | Add method to existing client in `pkg/[service]/client.go` |
| Hardcoded `"/etc/vault.d"` | Use `vault.VaultConfigDir` constant |
| `os.MkdirAll(dir, 0755)` | Use `vault.VaultDirPerm` or `consul.ConsulDirPerm` |
| Business logic in `cmd/*.go` | Move to `pkg/[feature]/*.go` |
| `_ = someFunc()` (discarding errors) | `if err != nil { return fmt.Errorf(...): %w", err) }` |
| Standalone `*.md` docs (except ROADMAP.md, README.md) | Put in inline comments or update ROADMAP.md |
