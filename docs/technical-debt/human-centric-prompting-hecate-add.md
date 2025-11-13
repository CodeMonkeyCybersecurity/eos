# Technical Debt: Human-Centric Prompting for `eos update hecate --add`

**Status**: Deferred (P0 requirement, but acceptable interim solution in place)
**Created**: 2025-10-28
**Target**: Q1 2026 (when adding interactive mode support)
**CLAUDE.md Reference**: P0 #13 - Required Flag Prompting

## Background

Per CLAUDE.md P0 #13:
> "If a required flag is missing, NEVER fail immediately. ALWAYS offer interactive fallback with informed consent."
> "Philosophy: Technology serves humans, not the other way around - missing flags are barriers to entry"

### Current Behavior (Acceptable Interim)

```bash
$ eos update hecate --add bionicgpt
Error: --dns flag is required when using --add
Example: eos update hecate --add bionicgpt --dns chat.example.com --upstream 100.64.0.1:8080
```

**Why This Is Acceptable**:
- Clear error message with actionable example
- Fast feedback (<1ms)
- Doesn't waste user time
- Example includes realistic values

**Why It's Not Ideal**:
- Still a barrier (user must re-run command)
- Breaks interactive workflow
- Not aligned with "technology serves humans" philosophy

### Target Behavior (Human-Centric)

```bash
$ eos update hecate --add bionicgpt

Route (domain/subdomain) is required for Hecate reverse proxy configuration.
This will be the public domain name for accessing your service.

Examples:
  - chat.example.com
  - app.mycompany.net
  - service.internal.local

Enter route: █
```

User types `chat.codemonkey.net.au`, then:

```bash
Backend (upstream address) is required to proxy traffic.
This should be the IP:port or hostname:port where your service is running.

For bionicgpt, the default port is 8513. You can:
  - Specify just the IP (port will be auto-detected): 100.71.196.79
  - Specify IP and custom port: 100.71.196.79:7703

Enter upstream: █
```

User types `100.71.196.79`, system appends `:8513`, continues with installation.

## Implementation Guide

### Step 1: Replace Hard Validation with Interactive Fallback

**File**: `cmd/update/hecate.go:122-127`

**Current** (fail fast):
```go
// Validate required flags early (fail fast)
if dns == "" {
    return fmt.Errorf("--dns flag is required when using --add\nExample: eos update hecate --add %s --dns chat.example.com --upstream 100.64.0.1:8080", service)
}
if upstream == "" {
    return fmt.Errorf("--upstream flag is required when using --add\nExample: eos update hecate --add %s --dns chat.example.com --upstream 100.64.0.1:8080", service)
}
```

**Target** (human-centric):
```go
// Use human-centric prompting for required flags (CLAUDE.md P0 #13)
dnsResult, err := interaction.GetRequiredString(rc, dns, cmd.Flags().Changed("dns"), &interaction.RequiredFlagConfig{
    FlagName:      "dns",
    EnvVarName:    "", // No env var for DNS routes
    PromptMessage: "Enter route (domain/subdomain): ",
    HelpText: `Route is the public domain name for accessing your service.

Examples:
  - chat.example.com
  - app.mycompany.net
  - service.internal.local

This will be configured in Hecate's reverse proxy (Caddy).`,
    IsSecret:      false,
    Validator:     validateDNSFormat, // Optional: validate format before accepting
})
if err != nil {
    return fmt.Errorf("failed to get route: %w", err)
}
dns = dnsResult.Value

upstreamResult, err := interaction.GetRequiredString(rc, upstream, cmd.Flags().Changed("upstream"), &interaction.RequiredFlagConfig{
    FlagName:      "upstream",
    PromptMessage: "Enter upstream (backend address): ",
    HelpText: fmt.Sprintf(`Upstream is the IP:port or hostname:port where %s is running.

For %s, the default port is %d. You can:
  - Specify just the IP (port auto-detected): 100.71.196.79
  - Specify IP and custom port: 100.71.196.79:7703`, service, service, getDefaultPort(service)),
    IsSecret:      false,
    Validator:     validateUpstreamFormat,
})
if err != nil {
    return fmt.Errorf("failed to get upstream: %w", err)
}
upstream = upstreamResult.Value

// Log which source provided the values (observability)
logger.Info("Configuration sources",
    zap.String("dns_source", string(dnsResult.Source)),      // "flag", "env", or "prompt"
    zap.String("upstream_source", string(upstreamResult.Source)))
```

### Step 2: Add Validators (Optional but Recommended)

**File**: `cmd/update/hecate.go` (add helper functions)

```go
// validateDNSFormat checks if DNS entry is valid
func validateDNSFormat(value string) error {
    if value == "" {
        return fmt.Errorf("DNS cannot be empty")
    }
    // Basic DNS validation (FQDN or hostname)
    if !shared.IsValidDNS(value) {
        return fmt.Errorf("invalid DNS format: %s\nMust be a valid domain name (e.g., chat.example.com)", value)
    }
    return nil
}

// validateUpstreamFormat checks if upstream is valid (ip:port or hostname:port)
func validateUpstreamFormat(value string) error {
    if value == "" {
        return fmt.Errorf("upstream cannot be empty")
    }
    // Allow IP-only for known services (port will be added)
    if !shared.IsValidUpstream(value) {
        return fmt.Errorf("invalid upstream format: %s\nMust be hostname:port, ip:port, or just IP for known services", value)
    }
    return nil
}
```

### Step 3: Add `getDefaultPort` Helper

**File**: `cmd/update/hecate.go`

```go
// getDefaultPort returns the default port for a service, or 0 if unknown
func getDefaultPort(service string) int {
    // Use the serviceDefaultPorts map from pkg/hecate/add/port_defaults.go
    // (may need to export it or duplicate here)
    defaultPorts := map[string]int{
        "bionicgpt": 8513,
        "openwebui": 8501,
        "authentik": 9000,
    }
    return defaultPorts[service] // Returns 0 if not found
}
```

### Step 4: Update Tests

**File**: Create `cmd/update/hecate_interactive_test.go`

```go
package update

import (
    "testing"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
)

func TestHecateAddInteractivePrompting(t *testing.T) {
    // Test 1: Flag provided, no prompt
    // Test 2: Flag missing, TTY available, prompts user
    // Test 3: Flag missing, no TTY, returns error
    // Test 4: Validator rejects bad input, re-prompts
    // Test 5: User cancels prompt (Ctrl+C), exits gracefully
}
```

### Step 5: Handle Non-Interactive Mode

**Important**: The implementation must detect non-TTY environments (CI/CD, scripts) and fail fast with clear error instead of hanging waiting for input.

```go
// In interaction.GetRequiredString():
if !valueProvided && !envVarProvided {
    // Need to prompt - check if TTY available
    if !interaction.IsTTY() {
        return StringResult{}, fmt.Errorf(
            "--%s is required (no TTY for interactive prompt)\n"+
            "Provide via:\n"+
            "  - Flag: --%s <value>\n"+
            "  - Environment: %s=<value>\n"+
            "Example: eos update hecate --add bionicgpt --dns chat.example.com --upstream 100.64.0.1:8080",
            config.FlagName, config.FlagName, config.EnvVarName)
    }
    // TTY available - proceed with prompt
}
```

## Estimated Effort

- **Implementation**: 2-3 hours
- **Testing**: 1-2 hours (interactive testing is manual)
- **Documentation**: 30 minutes

**Total**: ~4-6 hours

## Dependencies

1. **Existing**: `pkg/interaction/required_flag.go` already implements this pattern
2. **Existing**: `pkg/interaction/tty.go` handles TTY detection
3. **Need**: Export or duplicate `serviceDefaultPorts` from `pkg/hecate/add/port_defaults.go`
4. **Need**: Implement `validateDNSFormat` and `validateUpstreamFormat` helpers

## Testing Strategy

### Unit Tests
- Validator functions (quick)
- Non-interactive mode behavior (quick)

### Integration Tests (Manual)
1. Run without flags in terminal (should prompt)
2. Run without flags in CI/CD (should fail fast)
3. Run with one flag missing (should prompt for missing one only)
4. Run with invalid input (should re-prompt with validation error)
5. Test Ctrl+C during prompt (should exit gracefully)

## Migration Notes

- **Backward Compatible**: Flag-based usage continues to work
- **User Perception**: May see this as "slower" if they prefer fail-fast
- **Solution**: Add `--no-prompt` flag to opt-out of interactive mode

## Why Deferred

1. **Complexity vs Value**: Adds 4-6 hours of work for marginal UX improvement
2. **Current Solution Acceptable**: Error messages are clear and actionable
3. **Limited Use Case**: Most usage is scripted (deployment pipelines, automation)
4. **Priority**: P0 #1 (missing EnsureBackendHasPort) was blocking production - fixed first
5. **Timing**: Better to implement alongside other interactive features (Q1 2026 roadmap)

## When to Implement

Trigger this work when:
- **User feedback**: 3+ users request interactive mode
- **Related feature**: Adding interactive wizard for service creation
- **Roadmap item**: Q1 2026 "Enhanced CLI UX" sprint

## References

- CLAUDE.md P0 #13: Required Flag Prompting
- pkg/interaction/required_flag.go: Reference implementation
- cmd/update/vault_cluster.go:287-334: Working example of GetRequiredString pattern
