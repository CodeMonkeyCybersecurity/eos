---
description: Eos debugging patterns — diagnostic logging, debug commands, evidence collection
paths:
  - "cmd/debug/**"
  - "pkg/**/*.go"
---

# Debugging Patterns

## Diagnostic Logging Strategy

In `cmd/debug/` handlers, use two distinct output modes:

| Phase | Output method | Purpose |
|---|---|---|
| Diagnostic checks (health, config validation) | `logger.Info/Warn/Error(...)` | Structured — captured by telemetry |
| Progress indicators | `logger.Debug(...)` or `logger.Info(...)` | Visible to user in real-time |
| Issue detection | `logger.Warn/Error(...)` with zap fields | Structured error data |
| **Final report rendering** | `fmt.Print(report.Render())` ONLY | Terminal-formatted output AFTER telemetry |

```go
// CORRECT: cmd/debug handler pattern
func runVaultDiagnostic(rc *eos_io.RuntimeContext) error {
    logger := otelzap.Ctx(rc.Ctx)

    // Phase 1: diagnostics via structured logger (telemetry captured)
    logger.Info("Checking Vault seal status")
    sealed, err := vault.CheckSealStatus(rc)
    if err != nil {
        logger.Error("Failed to check seal status", zap.Error(err))
    }
    logger.Info("Vault seal status", zap.Bool("sealed", sealed))

    // Phase 2: terminal-formatted report ONLY after all diagnostics done
    report := buildVaultReport(sealed, ...)
    fmt.Print(report.Render())  // OK here — final output only
    return nil
}
```

## Evidence Collection

When collecting diagnostic evidence, capture:
1. **State**: current configuration, running services, connectivity
2. **Timestamps**: when check was performed, service start times
3. **Context**: environment variables (redacted secrets), config file hashes
4. **Errors**: full error chains including root cause

```go
// Evidence struct pattern
type DiagnosticEvidence struct {
    Timestamp   time.Time         `json:"timestamp"`
    ServiceName string            `json:"service_name"`
    Checks      []CheckResult     `json:"checks"`
    Errors      []string          `json:"errors"`
    Config      map[string]string `json:"config"` // no secret values
}
```

## Debug Command Structure

Debug commands live in `cmd/debug/` and follow this pattern:

```
eos debug [service]         # full diagnostic check
eos debug [service] --fix   # diagnose and attempt auto-remediation
eos debug [service] --json  # machine-readable output for CI/automation
```

Output format:
- Human mode (default): coloured terminal report with summary + details
- JSON mode (`--json`): structured JSON for parsing by other tools

## Automatic Debug Output Capture

For commands that call external tools (`vault`, `consul`, `docker`):
```go
// Capture stdout+stderr for evidence
cmd := exec.CommandContext(rc.Ctx, "vault", "status")
out, err := cmd.CombinedOutput()
if err != nil {
    logger.Error("vault status failed",
        zap.Error(err),
        zap.String("output", string(out)),  // attach full output
    )
}
```

## Anti-Patterns

| Anti-pattern | Why it's wrong | Do this instead |
|---|---|---|
| `fmt.Println("checking vault...")` in diagnostic phase | Bypasses telemetry, no structured fields | `logger.Info("checking vault status")` |
| `fmt.Print(...)` in pkg/ functions | pkg/ functions have no terminal context | Return structured data, let cmd/ render |
| Swallowing errors in diagnostics | Hidden failures give false-positive health | Log and continue: `logger.Warn("...", zap.Error(err))` |
| `log.Fatal(...)` in pkg/ | Kills process without cleanup | Return error, let cmd/ handle exit |
