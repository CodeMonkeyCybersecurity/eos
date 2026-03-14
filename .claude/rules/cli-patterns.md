---
description: Eos CLI patterns — cobra commands, flag validation, human-centric input handling
paths:
  - "cmd/**/*.go"
  - "pkg/interaction/**"
  - "pkg/verify/**"
---

# Eos CLI Patterns

## Command Structure

Verb-first with flag-based operations:
```
eos [verb] [noun] --[operation] [target] [--flags...]

eos update hecate --add bionicgpt --dns example.com
eos update vault --fix --dry-run
eos delete env production --force
```

Exception: standard CRUD verbs use positional args:
```
eos update services start nginx   # 'start' is a verb, not an operation flag
```

## Human-Centric Flag Handling (P0 — Breaking)

If a required flag is missing, NEVER fail immediately. ALWAYS offer interactive fallback with informed consent.

**Violation**: `if flag == "" { return fmt.Errorf("--token is required") }`

**Correct pattern** — use the full fallback chain:
1. CLI flag (if explicitly set via `cmd.Flags().Changed()`)
2. Environment variable (if configured)
3. Interactive prompt (if TTY available, with help text explaining WHY and HOW)
4. Default value (if `AllowEmpty` is true)
5. Error with clear remediation steps (non-interactive mode only)

```go
// CORRECT: Human-centric with fallback chain
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
logger.Info("Using Vault token", zap.String("source", string(result.Source)))
```

Required elements:
- **Help text**: WHY is this needed? HOW to get the value?
- **Source logging**: always log which fallback was used (CLI/env/prompt/default)
- **Validation**: validate input, retry with clear guidance (max 3 attempts)
- **Security**: `IsSecret: true` for passwords/tokens (no terminal echo)

## Missing Dependencies (P0 — Breaking)

NEVER error out immediately when a dependency is missing. ALWAYS offer informed consent to install:
```go
interaction.CheckDependencyWithPrompt(rc, interaction.DependencyConfig{
    Name:        "docker",
    Description: "Container runtime required for service deployment",
    InstallCmd:  "curl -fsSL https://get.docker.com | sh",
    AskConsent:  true,
})
```

## Flag Bypass Vulnerability Prevention (P0 — Breaking)

Cobra's `--` separator stops flag parsing and passes everything as positional args. This bypasses safety flags.

**Vulnerable pattern** (user types `eos delete env prod -- --force`):
- Cobra sees args: `["prod", "--force"]` — flags are NOT set
- `--force` check passes silently — production deleted without confirmation

**MANDATORY MITIGATION**: ALL commands accepting positional arguments MUST call `verify.ValidateNoFlagLikeArgs` as the first line of `RunE`:

```go
RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    logger := otelzap.Ctx(rc.Ctx)

    // CRITICAL: Detect flag-like args passed as positional (-- bypass)
    if err := verify.ValidateNoFlagLikeArgs(args); err != nil {
        return err  // clear user-facing error with remediation
    }

    // rest of command logic...
})
```

Affected command types (any using `cobra.ExactArgs`, `cobra.MaximumNArgs`, `cobra.MinimumNArgs`):
- Safety-critical: `cmd/delete/`, `cmd/promote/` — production deletion, approval overrides
- All others: `cmd/backup/`, `cmd/create/`, `cmd/update/`

See `pkg/verify/validators.go:ValidateNoFlagLikeArgs` for implementation.

## Drift Correction Pattern

Services that drift from canonical state (wrong permissions, config values):
```
eos update <service> --fix           # detect and correct drift
eos update <service> --fix --dry-run # preview corrections without applying
```

NEVER create separate `eos fix <service>` commands — use `--fix` flag on existing `eos update` commands.

## Configuration Drift Decision

```
Service has drifted?
├─ Use: eos update <service> --fix
├─ Compares: Current state vs. canonical state from eos create
├─ Corrects: Permissions, ownership, config values
└─ Verifies: Post-fix state matches canonical

Want to check only?
└─ Use: eos update <service> --fix --dry-run

DEPRECATED: eos fix vault → use eos update vault --fix
```
