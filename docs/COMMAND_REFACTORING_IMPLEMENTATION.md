# Command Refactoring Implementation Guide

*Last Updated: 2025-10-20*

## Quick Reference: Wazuh Example

### Current State
```
cmd/read/wazuh.go              → parent with subcommands
cmd/read/wazuh_ccs.go          → top-level command "wazuh-ccs"
cmd/read/wazuh_version.go      → top-level command "wazuh-version"
cmd/read/wazuh_agents.go       → subcommand "agents"
cmd/read/wazuh_api.go          → subcommand "api"
cmd/read/wazuh_config.go       → subcommand "config"
cmd/read/wazuh_credentials.go  → subcommand "credentials"
cmd/read/wazuh_users.go        → subcommand "users"
```

### Desired State
```
cmd/read/wazuh.go              → parent with flags AND subcommands
  Flags:
    --ccs         (was wazuh-ccs command)
    --version     (was wazuh-version command)

  Subcommands (unchanged):
    agents        (stays as subcommand)
    api           (stays as subcommand)
    config        (stays as subcommand)
    credentials   (stays as subcommand)
    users         (stays as subcommand)
```

### User Experience
```bash
# OLD (scattered)
eos read wazuh --help          # Only shows subcommands
eos read wazuh-ccs --help      # Separate help
eos read wazuh-version --help  # Separate help

# NEW (unified)
eos read wazuh --help          # Shows EVERYTHING
  Flags:
    --ccs       Show MSSP platform
    --version   Show version

  Subcommands:
    agents      Watch agents
    ...
```

---

## Implementation Pattern

### Step 1: Update Parent Command

```go
// cmd/read/wazuh.go
var readWazuhCmd = &cobra.Command{
    Use:   "wazuh",
    Short: "Read Wazuh data",
    Long: `Read Wazuh data and status information.

Available flags:
  --ccs        Show MSSP platform status
  --version    Show version information

Available subcommands:
  agents       Watch agents table
  ...

Examples:
  eos read wazuh              # Default behavior
  eos read wazuh --ccs        # Show CCS platform
  eos read wazuh --version    # Show version
  eos read wazuh agents       # Subcommand`,
    RunE: eos.Wrap(runReadWazuh),
}

func init() {
    // Add flags
    readWazuhCmd.Flags().Bool("ccs", false, "Show MSSP platform status")
    readWazuhCmd.Flags().Bool("version", false, "Show version information")

    // Add subcommands (keep as-is)
    readWazuhCmd.AddCommand(wazuhAgentsCmd)
    readWazuhCmd.AddCommand(wazuhAPICmd)
    // ... other subcommands
}
```

### Step 2: Create Router Function

```go
func runReadWazuh(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    logger := otelzap.Ctx(rc.Ctx)

    // Get flags
    ccs, _ := cmd.Flags().GetBool("ccs")
    version, _ := cmd.Flags().GetBool("version")

    // Count active flags
    flagCount := 0
    if ccs { flagCount++ }
    if version { flagCount++ }

    // Validate: only one flag
    if flagCount > 1 {
        return fmt.Errorf("only one flag can be specified")
    }

    // Route to handler
    if ccs {
        return runReadWazuhCCS(rc, cmd, args)
    }
    if version {
        return runReadWazuhVersion(rc, cmd, args)
    }

    // No flags and no subcommand = show help
    if len(args) == 0 {
        logger.Info("terminal prompt: Run 'eos read wazuh --help'")
        return cmd.Help()
    }

    return fmt.Errorf("unknown argument: %s", args[0])
}
```

### Step 3: Extract Handler Functions

From `wazuh_ccs.go`, extract the `runReadWazuhCCS` function and make it callable.

**Option A: Keep in separate file**
```go
// wazuh_ccs.go
// Remove the Command definition, keep only the handler
func runReadWazuhCCS(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    // Existing implementation
}
```

**Option B: Move to wazuh.go**
```go
// wazuh.go
// Copy the entire runReadWazuhCCS function here
```

### Step 4: Remove Old Top-Level Registration

```go
// OLD: cmd/read/wazuh_ccs.go init()
func init() {
    ReadCmd.AddCommand(ReadWazuhCCSCmd)  // DELETE THIS
}

// NEW: Not registered at top level anymore
// It's now accessed via: eos read wazuh --ccs
```

### Step 5: Add Deprecated Alias (Optional)

For backward compatibility:

```go
// cmd/read/wazuh_ccs.go
var ReadWazuhCCSCmd = &cobra.Command{
    Use:   "wazuh-ccs",
    Short: "DEPRECATED: Use 'eos read wazuh --ccs'",
    RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
        logger := otelzap.Ctx(rc.Ctx)
        logger.Warn("Command 'wazuh-ccs' is deprecated")
        logger.Info("terminal prompt: Use 'eos read wazuh --ccs' instead")

        // Forward to new implementation
        return runReadWazuhCCS(rc, cmd, args)
    }),
    Deprecated: "use 'eos read wazuh --ccs' instead",
}
```

---

## Testing Checklist

- [ ] `eos read wazuh --help` shows all flags and subcommands
- [ ] `eos read wazuh` shows help (no default behavior yet)
- [ ] `eos read wazuh --ccs` works (routes to CCS handler)
- [ ] `eos read wazuh --version` works (routes to version handler)
- [ ] `eos read wazuh --ccs --version` fails with clear error
- [ ] `eos read wazuh agents` still works (subcommand unchanged)
- [ ] `eos read wazuh agents --help` shows agent-specific help
- [ ] Old command `eos read wazuh-ccs` shows deprecation warning
- [ ] Old command `eos read wazuh-ccs` still works (backward compat)

---

## Files to Modify: Wazuh

1. **cmd/read/wazuh.go**
   - Add flags: `--ccs`, `--version`
   - Implement router: `runReadWazuh()`
   - Keep subcommands registered

2. **cmd/read/wazuh_ccs.go**
   - Remove from ReadCmd registration in init()
   - Keep `runReadWazuhCCS()` function
   - Optionally: Add deprecated alias command

3. **cmd/read/wazuh_version.go**
   - Remove from ReadCmd registration in init()
   - Keep `runReadWazuhVersion()` function
   - Optionally: Add deprecated alias command

4. **cmd/read/read.go**
   - No changes needed (wazuh.go handles registration)

---

## Files to Modify: Vault

1. **Create cmd/read/vault.go** (if doesn't exist)
2. **Modify cmd/read/vault_status.go** → extract handler
3. **Modify cmd/read/vault_init.go** → extract handler

Pattern is identical to Wazuh above.

---

## Files to Modify: Database

1. **Create cmd/read/database.go** (new parent command)
2. **Modify cmd/read/database_credentials.go** → extract handler
3. **Modify cmd/read/database_status.go** → extract handler

---

## Implementation Order

1. ✅ **Plan created** (COMMAND_REFACTORING_PLAN.md)
2. ✅ **Implementation guide created** (this file)
3. ⏳ **Wazuh** (reference implementation)
   - Update wazuh.go
   - Update wazuh_ccs.go
   - Update wazuh_version.go
   - Test all combinations
4. ⏳ **Vault** (second example)
5. ⏳ **Database** (third example)
6. ⏳ **Document pattern** for contributors
7. ⏳ **Roll out remaining groups**

---

## Common Pitfalls

### Pitfall 1: Flags vs Subcommands Confusion
**Problem**: Cobra sees `eos read wazuh agents` as a subcommand, not as `args[0]`

**Solution**: In `runReadWazuh()`, check if a subcommand was invoked first:
```go
if cmd.HasSubCommands() && len(args) > 0 {
    // Subcommand will be handled by Cobra
    // We shouldn't reach here
    return nil
}
```

### Pitfall 2: Flag Inheritance
**Problem**: Flags from parent leak into subcommands

**Solution**: Use local flags, not persistent:
```go
cmd.Flags().Bool("ccs", false, "...")  // Local only
// NOT: cmd.PersistentFlags().Bool(...)
```

### Pitfall 3: Mutually Exclusive Flags
**Problem**: User runs `eos read wazuh --ccs --version`

**Solution**: Validate flag combinations:
```go
flagCount := 0
if ccs { flagCount++ }
if version { flagCount++ }
if flagCount > 1 {
    return fmt.Errorf("only one flag allowed")
}
```

---

## Quick Start: Implement Wazuh Now

```bash
# 1. Backup current files
cp cmd/read/wazuh.go cmd/read/wazuh.go.backup
cp cmd/read/wazuh_ccs.go cmd/read/wazuh_ccs.go.backup
cp cmd/read/wazuh_version.go cmd/read/wazuh_version.go.backup

# 2. Edit wazuh.go
#    - Add flags
#    - Add router function
#    - Test: go build ./cmd/...

# 3. Edit wazuh_ccs.go
#    - Remove ReadCmd.AddCommand() from init()
#    - Keep handler function
#    - Test: go build ./cmd/...

# 4. Test the new structure
eos read wazuh --help       # Should show flags
eos read wazuh --ccs        # Should route to CCS
eos read wazuh agents       # Should still work

# 5. If everything works, delete backups
rm cmd/read/wazuh*.backup
```

---

## Next Steps

1. Implement Wazuh refactoring (1-2 hours)
2. Test thoroughly
3. Implement Vault refactoring (30 mins)
4. Implement Database refactoring (30 mins)
5. Document the pattern in PATTERNS.md
6. Create PR with Phase 1 complete
