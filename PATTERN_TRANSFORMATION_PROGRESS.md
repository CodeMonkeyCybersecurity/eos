# Cobra Command Pattern Transformation Progress

## Overview
This document tracks the progress of transforming Cobra command patterns in the Eos codebase:
- **Pattern 1**: Transform `func NewXxxCmd() *cobra.Command` to `var xxxCmd = &cobra.Command`
- **Pattern 2**: Inline standalone handler functions into the RunE field

## Pattern 1 Progress

### ✅ Completed - update/ directory (4 files)
1. **services.go** - Transformed, built successfully
   - Converted NewServicesCmd and all subcommands
   - Added init() function for flag registration
   - Added prefixed flag variables to avoid conflicts

2. **ab_config.go** - Transformed, built successfully  
   - TODO: Needs parent command registration (appears to be for delphi services)
   - Converted all NewABConfig*Cmd functions to variables
   - Added init() function

3. **authz.go** - Transformed, built successfully
   - TODO: Needs parent command registration (examples show "eos secure permissions")
   - Converted NewPermissionsCmd and subcommands
   - Added init() function

4. **pipeline_prompts.go** - Transformed, built successfully
   - TODO: Needs parent command registration (examples show "eos delphi prompts update")
   - TODO: Renamed from "update" to "prompts-update" to avoid conflict with UpdateCmd
   - Added init() function

### 🔄 Remaining Pattern 1 Files

#### create/ directory (4 files):
- hecate_dns.go
- kvm_template.go 
- kvm_tenant.go
- pipeline_prompts.go

#### read/ directory (1 file):
- delphi.go

### Summary
- **Completed**: 4/9 files (44.4%)
- **Remaining**: 5/9 files (55.6%)

## Pattern 2 Progress

### Files with standalone handlers to inline:
- update/storage.go - has runUpdateStorage()
- create/storage_volume.go - has runCreateStorageVolume()
- create/clusterfuzz.go - has runClusterfuzz()
- Many other files throughout cmd/

### Strategy for Pattern 2:
1. Complete all Pattern 1 transformations first
2. Then systematically inline standalone handlers
3. Test after each file transformation

## TODO Items Found

### Registration Issues
Several commands need proper parent command registration:
- **ab_config.go** - Likely belongs under a "delphi services" structure
- **authz.go** - Examples show "eos secure permissions", needs "secure" parent
- **pipeline_prompts.go** - Examples show "eos delphi prompts", needs prompts parent

### Naming Conflicts
- **pipeline_prompts.go** - Had NewUpdateCmd() which conflicts with main UpdateCmd

## Build/Test Status
✅ All transformed files build successfully
✅ No linting errors that block functionality

## Next Steps
1. Continue Pattern 1 transformation with create/ directory
2. Investigate proper parent commands for orphaned commands
3. After Pattern 1 complete, begin Pattern 2 transformations
4. Run full test suite after each directory completion