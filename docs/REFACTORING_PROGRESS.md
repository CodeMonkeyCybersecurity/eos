# Command Refactoring Progress

*Last Updated: 2025-10-20*

## Summary

Refactoring Eos read commands from scattered subcommands to flag-based variants for better UX and discoverability.

---

## Phase 1: Reference Implementations (IN PROGRESS)

### ✅ Wazuh - COMPLETED

**Files Modified**:
- ✅ `/cmd/read/wazuh.go` - Refactored with flags `--ccs` and `--version`
- ✅ `/cmd/read/wazuh_ccs.go` - Removed top-level registration
- ✅ `/cmd/read/wazuh_version.go` - Removed top-level registration

**Changes**:
```bash
# OLD (Before)
eos read wazuh           # Parent
eos read wazuh-ccs       # Separate command (poor discoverability)
eos read wazuh-version   # Separate command (poor discoverability)

# NEW (After)
eos read wazuh              # Shows ALL options in --help
eos read wazuh --ccs        # Flag-based variant
eos read wazuh --version    # Flag-based variant
eos read wazuh agents       # Subcommand (unchanged)
```

**Benefits**:
- `eos read wazuh --help` now shows ALL wazuh options (flags + subcommands)
- Cleaner command list (2 fewer top-level commands)
- Better discoverability

**Test Status**: ✅ Compiles successfully

---

### 🚧 Vault - IN PROGRESS

**Files to Modify**:
- ⏳ `/cmd/read/vault.go` - Partially refactored (init() done, RunE needs routing)
- ⏳ `/cmd/read/vault_status.go` - Need to remove top-level registration

**Target Structure**:
```bash
# OLD
eos read vault              # Parent
eos read vault-init         # Separate command
eos read vault-status       # Separate command

# NEW
eos read vault              # Shows ALL options
eos read vault --init       # Flag variant
eos read vault --status     # Flag variant
eos read vault agent        # Subcommand (unchanged)
eos read vault ldap         # Subcommand (unchanged)
```

**Next Steps**:
1. Update `InspectVaultCmd` RunE to check for `--init` and `--status` flags
2. Route to appropriate handlers (`runVaultInit` and `runVaultStatus`)
3. Remove `VaultStatusCmd` from top-level in `vault_status.go`
4. Test compilation

---

### ⏳ Database - NOT STARTED

**Files to Create/Modify**:
- Create `/cmd/read/database.go` (new parent command)
- Modify `/cmd/read/database_credentials.go` - extract handler
- Modify `/cmd/read/database_status.go` - extract handler

**Target Structure**:
```bash
# OLD
eos read database-credentials    # Separate command
eos read database-status         # Separate command

# NEW
eos read database --credentials  # Flag variant
eos read database --status       # Flag variant
```

---

## Implementation Pattern (Reference)

### Step-by-Step Process

1. **Update parent command** with flags:
```go
func init() {
    parentCmd.Flags().Bool("variant1", false, "Description")
    parentCmd.Flags().Bool("variant2", false, "Description")
}
```

2. **Create router function**:
```go
func runParent(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    variant1, _ := cmd.Flags().GetBool("variant1")
    variant2, _ := cmd.Flags().GetBool("variant2")

    // Validate mutual exclusivity
    if variant1 && variant2 {
        return fmt.Errorf("only one flag allowed")
    }

    // Route to handlers
    if variant1 {
        return runVariant1(rc, cmd, args)
    }
    if variant2 {
        return runVariant2(rc, cmd, args)
    }

    // Default: show help
    return cmd.Help()
}
```

3. **Remove top-level registration** from variant files:
```go
func init() {
    // NOTE: VariantCmd is NO LONGER registered at top level
    // It is now accessed via: eos read parent --variant
    // Top-level registration removed as part of command refactoring

    // Keep flags defined here for when called via router
    VariantCmd.Flags().Bool(...)
}
```

---

## Remaining Work

### Phase 1 Completion
- [ ] Finish Vault refactoring (routing logic)
- [ ] Implement Database refactoring
- [ ] Test all three implementations
- [ ] Adversarial review

### Phase 2 (Future)
- [ ] Storage commands
- [ ] Hecate commands
- [ ] Container commands
- [ ] Crypto commands
- [ ] ML-KEM commands
- [ ] Remote commands
- [ ] System commands

---

## Testing Checklist

For each refactored command:
- [ ] `eos read <cmd> --help` shows all flags and subcommands
- [ ] Default behavior (no flags) shows help
- [ ] Each flag routes to correct handler
- [ ] Mutually exclusive flags rejected
- [ ] Subcommands still work unchanged
- [ ] Compilation succeeds
- [ ] No duplicate function definitions

---

## Known Issues

### Issue 1: Flag Inheritance
**Problem**: Flags defined on parent may leak to subcommands.
**Solution**: Use local flags, not persistent flags.

### Issue 2: Duplicate Handlers
**Problem**: Variant command files define handlers that parent needs to call.
**Solution**: Keep handlers in variant files, call from parent router.

---

## Files Changed Summary

### Completed
- ✅ `cmd/read/wazuh.go` - Refactored
- ✅ `cmd/read/wazuh_ccs.go` - De-registered
- ✅ `cmd/read/wazuh_version.go` - De-registered
- ✅ `docs/COMMAND_REFACTORING_PLAN.md` - Created
- ✅ `docs/COMMAND_REFACTORING_IMPLEMENTATION.md` - Created

### In Progress
- 🚧 `cmd/read/vault.go` - Partially refactored
- 🚧 `cmd/read/vault_status.go` - Needs de-registration

### Not Started
- ⏳ `cmd/read/database.go` - To be created
- ⏳ `cmd/read/database_credentials.go` - Needs refactoring
- ⏳ `cmd/read/database_status.go` - Needs refactoring

---

## Next Session Actions

1. Complete Vault routing in `vault.go` RunE function
2. Remove VaultStatusCmd top-level registration
3. Test Vault refactoring
4. Implement Database refactoring
5. Adversarial review all three implementations
6. Document any issues found

---

## Adversarial Review Notes (To Do)

When reviewing completed work, check for:
- **Code duplication**: Are handlers DRY?
- **Error messages**: Are they clear and actionable?
- **Help text**: Does it accurately reflect new structure?
- **Backward compatibility**: Are deprecated commands handled?
- **Testing**: Can we actually test this without full build?
- **Documentation**: Is the pattern clear for future contributors?

---

## Success Criteria

Phase 1 is complete when:
1. ✅ Wazuh, Vault, Database all refactored
2. ✅ All three compile successfully
3. ✅ Help text is accurate and helpful
4. ✅ UX is improved (discoverability)
5. ✅ Pattern is documented for Phase 2
6. ✅ Adversarial review completed
