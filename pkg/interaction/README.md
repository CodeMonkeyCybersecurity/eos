# pkg/interaction

*Last Updated: 2025-01-28*

Human-centric interaction utilities for Eos following the principle: **Technology serves humans, not the other way around.**

## Purpose

This package provides utilities for interacting with users in a respectful, informative, and consent-based manner. All interactions follow the feminist principle of **informed consent** - users should always know what will happen, why it's needed, and have the ability to decline.

## Key Modules

### Required Flag Prompting (`required_flag.go`) - P0 REQUIREMENT

**NEW**: Human-centric required flag resolution with fallback chain. This implements CLAUDE.md P0 #13: "Technology serves humans" - never fail immediately when a required flag is missing.

#### Philosophy

Traditional CLI tools fail immediately when required flags are missing:
```bash
$ eos update vault-cluster autopilot
Error: --token is required
# User must re-run entire command with --token
# This is HOSTILE UX - technology dictating to humans
```

Human-centric approach offers informed consent and fallback chain:
```bash
$ eos update vault-cluster autopilot
Vault token required for Autopilot configuration
No token provided via --token flag or VAULT_TOKEN environment variable

Required for cluster operations. Get via: vault token create

Enter Vault root token: ****
Using Vault token from interactive prompt
✓ Autopilot configured successfully
```

#### Fallback Chain (P0 Requirement)

Every required flag follows this precedence:

1. **CLI flag** (if explicitly set via `cmd.Flags().Changed()`)
2. **Environment variable** (if configured, e.g., `VAULT_TOKEN`)
3. **Interactive prompt** (if TTY available, with help text explaining WHY and HOW)
4. **Default value** (if `AllowEmpty` is true and default makes sense)
5. **Error with remediation** (if non-interactive mode, include clear steps)

#### Core Functions

```go
// GetRequiredString resolves a required string flag with fallback chain
func GetRequiredString(
    rc *eos_io.RuntimeContext,
    flagValue string,
    flagWasSet bool,
    config *RequiredFlagConfig,
) (*FlagResult, error)

// GetRequiredInt resolves a required int flag (prompts as string, parses to int)
func GetRequiredInt(
    rc *eos_io.RuntimeContext,
    flagValue int,
    flagWasSet bool,
    config *RequiredFlagConfig,
) (int, FlagSource, error)
```

#### RequiredFlagConfig Fields

```go
type RequiredFlagConfig struct {
    // Metadata
    FlagName   string   // For error messages: "token"
    EnvVarName string   // Optional: "VAULT_TOKEN", "" if no env var

    // User-facing prompt (only used if prompting needed)
    PromptMessage string   // "Enter Vault root token: "
    HelpText      string   // "Required for cluster operations. Get via: vault token create"

    // Behavior
    IsSecret     bool     // Use PromptSecurePassword (no echo)
    AllowEmpty   bool     // Can user press enter for empty?
    DefaultValue string   // Used if AllowEmpty && user presses enter

    // Validation
    Validator func(string) error   // Optional custom validation
}
```

#### Example Usage - String Flag

```go
// cmd/update/vault_cluster.go
func runVaultClusterAutopilot(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
    log := otelzap.Ctx(rc.Ctx)

    // STEP 1: Get flag value and detect if it was explicitly set
    tokenFlag, _ := cmd.Flags().GetString("token")
    tokenWasSet := cmd.Flags().Changed("token")

    // STEP 2: Use unified interface to resolve with fallback chain
    result, err := interaction.GetRequiredString(rc, tokenFlag, tokenWasSet, &interaction.RequiredFlagConfig{
        FlagName:      "token",
        EnvVarName:    "VAULT_TOKEN",
        PromptMessage: "Enter Vault root token: ",
        HelpText:      "Required for Autopilot configuration. Get via: vault token create",
        IsSecret:      true,
    })
    if err != nil {
        return fmt.Errorf("failed to get vault token: %w", err)
    }

    // STEP 3: Log which source was used (observability)
    log.Info("Using Vault token", zap.String("source", string(result.Source)))

    token := result.Value

    // ... proceed with business logic
}
```

#### Example Usage - Int Flag

```go
portFlag, _ := cmd.Flags().GetInt("port")
portWasSet := cmd.Flags().Changed("port")

port, source, err := interaction.GetRequiredInt(rc, portFlag, portWasSet, &interaction.RequiredFlagConfig{
    FlagName:      "port",
    EnvVarName:    "SERVICE_PORT",
    PromptMessage: "Enter service port: ",
    HelpText:      "Port number for service (1024-65535)",
    Validator: func(s string) error {
        p, _ := strconv.Atoi(s)
        if p < 1024 || p > 65535 {
            return fmt.Errorf("port must be between 1024 and 65535")
        }
        return nil
    },
})
if err != nil {
    return fmt.Errorf("failed to get port: %w", err)
}

log.Info("Using service port", zap.Int("port", port), zap.String("source", string(source)))
```

#### FlagSource Type

Track where flag values came from for observability:

```go
type FlagSource string

const (
    FlagSourceCLI     FlagSource = "command-line flag"
    FlagSourceEnv     FlagSource = "environment variable"
    FlagSourcePrompt  FlagSource = "interactive prompt"
    FlagSourceDefault FlagSource = "default value"
)
```

#### Required Elements (P0 Compliance)

When using `GetRequiredString()` or `GetRequiredInt()`, you MUST:

- ✓ **Help text**: Explain WHY required and HOW to get (e.g., "Get via: vault token create")
- ✓ **Source logging**: ALWAYS log which fallback was used (observability)
- ✓ **Changed() detection**: Use `cmd.Flags().Changed()` to distinguish `--flag=""` from not provided
- ✓ **Security**: Set `IsSecret: true` for passwords/tokens (no terminal echo)
- ✓ **Remediation**: Error messages include actionable steps (auto-generated by `buildRemediationError()`)

#### What the User Sees

**Scenario: Flag provided via CLI**
```bash
$ eos update vault-cluster autopilot --token s.abc123
Using Vault token from command-line flag
✓ Autopilot configured successfully
```

**Scenario: Flag provided via environment variable**
```bash
$ export VAULT_TOKEN=s.abc123
$ eos update vault-cluster autopilot
Using Vault token from environment variable
✓ Autopilot configured successfully
```

**Scenario: Interactive prompt**
```bash
$ eos update vault-cluster autopilot
Required for Autopilot configuration. Get via: vault token create

Enter Vault root token: ****
Using Vault token from interactive prompt
✓ Autopilot configured successfully
```

**Scenario: Non-interactive mode (CI/CD)**
```bash
$ eos update vault-cluster autopilot
Error: Required flag --token not provided
  • Purpose: Required for Autopilot configuration. Get via: vault token create
  • Provide via: --token=<value>
  • Or set: export VAULT_TOKEN=<value>
  • Or run in interactive terminal to be prompted
```

#### Testing

See `required_flag_test.go` for comprehensive test coverage:
- ✓ Fallback 1: CLI flag provided
- ✓ Fallback 2: Environment variable
- ✓ Fallback 4: Default value
- ✓ Fallback 5: Error with remediation
- ✓ Precedence: CLI > env > prompt > default
- ✓ Empty detection: `Changed()` vs not provided
- ✓ Int parsing: CLI, env, default
- ✓ Error messages: Remediation quality

Note: Fallback 3 (interactive prompt) tested manually due to TTY requirements.

#### Migration from Ad-Hoc Patterns

**Before** (ad-hoc, 20+ lines per command):
```go
token, _ := cmd.Flags().GetString("token")
if token == "" {
    token = os.Getenv("VAULT_TOKEN")
}
if token == "" {
    log.Info("Vault token required for Autopilot configuration")
    log.Info("No token provided via --token flag or VAULT_TOKEN environment variable")
    log.Info("")

    var err error
    token, err = eos_io.PromptSecurePassword(rc, "Enter Vault root token: ")
    if err != nil {
        return fmt.Errorf("failed to read vault token: %w", err)
    }

    if token == "" {
        return fmt.Errorf("vault token cannot be empty")
    }
}
// ... proceed with token
```

**After** (unified, 7 lines):
```go
tokenFlag, _ := cmd.Flags().GetString("token")
tokenWasSet := cmd.Flags().Changed("token")

result, err := interaction.GetRequiredString(rc, tokenFlag, tokenWasSet, &interaction.RequiredFlagConfig{
    FlagName: "token", EnvVarName: "VAULT_TOKEN",
    PromptMessage: "Enter Vault root token: ", HelpText: "Required for Autopilot configuration",
    IsSecret: true,
})
if err != nil { return fmt.Errorf("failed to get vault token: %w", err) }

log.Info("Using Vault token", zap.String("source", string(result.Source)))
token := result.Value
```

**Benefits**:
- ✓ DRY: Eliminates 20+ lines of boilerplate per command
- ✓ Observability: Logs which source provided value
- ✓ Validation: Centralized, testable
- ✓ Security: Proper secret handling
- ✓ Human-centric: Clear help text, informed consent
- ✓ Testable: No cobra dependency in business logic

#### Reference Implementation

See [cmd/update/vault_cluster.go:287-334](../../cmd/update/vault_cluster.go#L287-L334) for production usage (`getAuthenticatedVaultClient` helper).

### Prompting (`prompt.go`)

Standard user input prompts with structured logging:

- `PromptYesNo(ctx, prompt, defaultYes)` - Yes/No questions with configurable defaults
- `PromptInput(ctx, prompt, defaultValue)` - Text input with optional defaults (accepts default or custom value)
- `PromptSecret(ctx, prompt)` - Hidden input for passwords/secrets
- `PromptSelect(ctx, prompt, options)` - Multiple choice selection

All prompts:
- Log to structured logging (never `fmt.Print*`)
- Use stderr for prompts to preserve stdout for automation
- Support context cancellation
- Provide clear defaults

### Dependency Checking (`dependency.go`)

**Human-centric dependency checking with informed consent** - the flagship feature of this package.

#### Philosophy

When a dependency is missing, NEVER:
- Silently fail
- Auto-install without asking
- Show cryptic error messages
- Leave users confused

ALWAYS:
- Explain what the dependency does
- Show how to install it manually
- Ask for informed consent before installing
- Provide clear remediation steps

#### Core Function

```go
func CheckDependencyWithPrompt(rc *eos_io.RuntimeContext, config DependencyConfig) (*DependencyCheckResult, error)
```

Pattern: **ASSESS → INFORM → CONSENT → INTERVENE → EVALUATE**

1. **ASSESS**: Check if dependency exists
2. **INFORM**: Explain what it is and why it's needed
3. **CONSENT**: Ask user permission to install (y/N default)
4. **INTERVENE**: Install if user consents
5. **EVALUATE**: Verify installation succeeded

#### DependencyConfig Fields

```go
type DependencyConfig struct {
    Name          string   // Friendly name (e.g., "Ollama", "Docker")
    Description   string   // What it's for (explain in plain language)
    CheckCommand  string   // Command to check if installed
    CheckArgs     []string // Args for check command
    InstallCmd    string   // Installation command (shown to user)
    StartCmd      string   // Optional: command to start service
    Required      bool     // If true, operation cannot continue without it
    AutoInstall   bool     // If true, attempt automatic installation (must be safe)
    AutoStart     bool     // If true, attempt automatic start (must be safe)
    CustomCheckFn func(context.Context) error // Optional custom check
}
```

#### Safety Guidelines

**AutoInstall should only be `true` when:**
- Installation is via official, trusted script (e.g., `get.docker.com`, `ollama.ai/install.sh`)
- No system-wide changes beyond the tool itself
- Easy to reverse/uninstall
- Well-tested and documented

**AutoInstall should be `false` for:**
- System packages requiring repository changes
- Anything needing manual configuration
- Tools with complex dependencies
- Anything modifying critical system files

#### Example Usage

See [dependency_example.go](dependency_example.go) for comprehensive examples.

**Quick example - Ollama dependency:**

```go
depConfig := interaction.DependencyConfig{
    Name:        "Ollama",
    Description: "Local LLM server for embeddings. Runs models locally for FREE.",
    InstallCmd:  "curl -fsSL https://ollama.ai/install.sh | sh",
    StartCmd:    "ollama serve &",
    Required:    true,
    AutoInstall: true,  // Safe - official install script
    AutoStart:   false, // Let user start manually
    CustomCheckFn: preflight.CheckOllama,
}

result, err := interaction.CheckDependencyWithPrompt(rc, depConfig)
if err != nil {
    return err
}

if !result.Found {
    // User declined - handle gracefully
    return eos_err.NewUserError("Cannot continue without Ollama")
}

// Dependency available - proceed with business logic
```

**What the user sees:**

```
INFO terminal prompt:
INFO terminal prompt: ========================================
INFO terminal prompt: Missing Dependency: Ollama
INFO terminal prompt: ========================================
INFO terminal prompt:
INFO terminal prompt: What it does: Local LLM server for embeddings. Runs models locally for FREE.
INFO terminal prompt:
INFO terminal prompt: Current status: NOT INSTALLED
INFO terminal prompt:
INFO terminal prompt: To install manually, run:
INFO terminal prompt:   curl -fsSL https://ollama.ai/install.sh | sh
INFO terminal prompt:
INFO terminal prompt: To start the service, run:
INFO terminal prompt:   ollama serve &
INFO terminal prompt:
INFO terminal prompt: Would you like Eos to install this for you?
INFO terminal prompt:
Install Ollama automatically [y/N]: y

INFO terminal prompt: Installing Ollama...
[Installation output...]
INFO terminal prompt: ✓ Ollama is now ready
```

### Input Validation (`validate.go`)

Input sanitization and validation helpers.

### Reader Utilities (`reader.go`)

Low-level reading utilities:
- `ReadLine(ctx, reader, label)` - Read single line with logging
- `ReadLines(rc, reader, label, count)` - Read multiple lines

### Fallback Handling (`fallback.go`)

Utilities for handling scenarios where normal interaction isn't possible (non-TTY, automation, etc.)

## Integration with Other Packages

### With `preflight`

The preflight package provides check functions that can be used as `CustomCheckFn`:

```go
depConfig := interaction.DependencyConfig{
    Name: "Docker",
    CustomCheckFn: preflight.CheckDocker,
    // ... other config
}
```

### With `eos_err`

Use `eos_err.NewUserError()` for graceful user-facing errors:

```go
if !result.Found && result.UserDecline {
    return eos_err.NewUserError(
        "Ollama is required but you declined installation.\n\n" +
        "To install manually:\n  %s", depConfig.InstallCmd)
}
```

### With `execute`

Installation commands use `execute.Run()` for consistent command execution:

```go
output, err := execute.Run(rc.Ctx, execute.Options{
    Command: "/bin/bash",
    Args:    []string{"-c", config.InstallCmd},
    Capture: true,
})
```

## Testing

See `fuzz_test.go` for fuzzing tests of input validation.

## Design Principles

1. **Informed Consent**: Users must know what will happen before it happens
2. **Clear Communication**: Plain language, no jargon
3. **Safe Defaults**: Default to "No" for destructive/installing actions
4. **Graceful Degradation**: Handle declined actions respectfully
5. **Logging All Actions**: Structured logging for audit trail
6. **Respect Automation**: Use stderr for prompts, stdout for data

## Related Documentation

- [CLAUDE.md](../../CLAUDE.md) - See "Dependency Not Found" decision tree
- [dependency_example.go](dependency_example.go) - Comprehensive usage examples
- [PATTERNS.md](../../docs/PATTERNS.md) - Eos coding patterns

---

**"Cybersecurity. With humans."**
