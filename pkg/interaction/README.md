# pkg/interaction

*Last Updated: 2025-10-21*

Human-centric interaction utilities for Eos following the principle: **Technology serves humans, not the other way around.**

## Purpose

This package provides utilities for interacting with users in a respectful, informative, and consent-based manner. All interactions follow the feminist principle of **informed consent** - users should always know what will happen, why it's needed, and have the ability to decline.

## Key Modules

### Prompting (`prompt.go`)

Standard user input prompts with structured logging:

- `PromptYesNo(ctx, prompt, defaultYes)` - Yes/No questions with configurable defaults
- `PromptInput(ctx, prompt, defaultValue)` - Text input with optional defaults
- `PromptSecret(ctx, prompt)` - Hidden input for passwords/secrets
- `PromptSelect(ctx, prompt, options)` - Multiple choice selection
- `PromptConfirmOrValue(ctx, prompt, defaultValue)` - Accept default or enter custom value

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
