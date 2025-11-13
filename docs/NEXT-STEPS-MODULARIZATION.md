# EOS Modularization - Next Steps

**Date:** 2025-10-09  
**Status:** First P1 File Complete   
**Ready For:** Next P1 File  

---

## Completed: pkg/consul/install.go 

Successfully modularized first P1 file into 13 focused modules:
- **Original:** 1,713 lines
- **Result:** 13 modules averaging 185 lines
- **Orchestrator:** 236 lines (86% reduction)
- **Compilation:**  All modules compile successfully

---

## Next P1 File: cmd/debug/iris.go

**File:** cmd/debug/iris.go  
**Size:** 1,659 lines  
**Priority:** P1 (>1000 lines, critical diagnostics)  

### Identified Responsibilities (Preliminary)
1. Iris service diagnostics
2. Infrastructure checks (Temporal, PostgreSQL, Redis)
3. Configuration validation
4. Service health monitoring
5. Workflow execution testing
6. Alert system testing
7. Dependency verification
8. Diagnostic report generation
9. Remediation guidance

### Proposed Module Structure
```
cmd/debug/iris/
├── main.go (orchestrator, <150 lines)
├── checks/
│   ├── infrastructure.go  # Temporal, DB, Redis checks
│   ├── configuration.go   # Config validation
│   ├── services.go        # Service health checks
│   └── dependencies.go    # Go dependencies verification
├── testing/
│   ├── workflow.go        # Workflow execution tests
│   └── alerts.go          # Alert system tests
├── reporting/
│   ├── formatter.go       # Report formatting
│   ├── display.go         # Terminal output
│   └── remediation.go     # Remediation suggestions
└── types.go               # Shared types (checkResult, etc.)
```

### Estimated Effort
- **Analysis:** 30 minutes
- **Module Creation:** 2 hours
- **Testing:** 30 minutes
- **Documentation:** 20 minutes
- **Total:** ~3 hours

---

## Remaining P1 Files (14 files)

### High Priority (Next 5)
1.  **pkg/consul/install.go** (1,713 lines) - COMPLETE
2. ⏳ **cmd/debug/iris.go** (1,659 lines) - NEXT
3. **cmd/debug/wazuh.go** (1,630 lines) - Wazuh/Wazuh diagnostics
4. **pkg/authentik/import.go** (1,266 lines) - Authentik configuration import
5. **pkg/vault/install.go** (1,253 lines) - Vault installation
6. **pkg/system/orchestration.go** (1,166 lines) - System orchestration

### Medium Priority (Next 5)
7. **cmd/create/iris.go** (1,154 lines) - Iris service creation
8. **pkg/database_management/backup.go** (1,123 lines) - Database backup
9. **pkg/storage/types.go** (1,086 lines) - Storage type definitions
10. **pkg/kvm/inventory.go** (1,080 lines) - KVM inventory management
11. **pkg/inspect/output.go** (1,070 lines) - Output formatting

### Lower Priority (Remaining 4)
12. **pkg/pipeline/system_prompts.go** (1,046 lines) - AI system prompts
13. **pkg/hecate/hybrid/diagnostics.go** (1,021 lines) - Hecate diagnostics
14. **pkg/terraform/consul_templates.go** (979 lines) - Terraform templates
15. **pkg/watchdog/resource_watchdog.go** (974 lines) - Resource monitoring

---

## Established Patterns

### Module Size Guidelines
- **Target:** <200 lines per module
- **Maximum:** 300 lines
- **Orchestrator:** <200 lines (ideally <150)

### Naming Conventions
- **Pattern:** domain-action.go
- **Examples:** infrastructure.go, workflow.go, formatter.go
- **Clear and descriptive**

### Constructor Pattern
```go
func New*Manager(rc *eos_io.RuntimeContext, params) *Manager {
    return &Manager{
        rc:     rc,
        logger: otelzap.Ctx(rc.Ctx),
        // ... dependencies
    }
}
```

### Error Handling Pattern
```go
if err := operation(); err != nil {
    return fmt.Errorf("operation failed: %w", err)
}
```

### Logging Pattern
```go
logger.Info("Operation starting",
    zap.String("param", value),
    zap.Int("count", count))
```

---

## Quality Checklist

For each file modularization:

### Analysis Phase
- [ ] Read entire file
- [ ] List all responsibilities with line numbers
- [ ] Identify dependencies
- [ ] Map security-critical sections
- [ ] Challenge: "Does this REALLY need separation?"

### Design Phase
- [ ] Create module structure
- [ ] Define clear interfaces
- [ ] Plan dependency injection
- [ ] Verify no circular dependencies

### Extraction Phase
- [ ] Create module files
- [ ] Move code with dependencies
- [ ] Update imports
- [ ] Add comprehensive documentation
- [ ] Preserve all security fixes

### Verification Phase
- [ ] Compile each module: `go build ./pkg/...`
- [ ] Verify no circular dependencies
- [ ] Check line counts (<300 lines)
- [ ] Test independently
- [ ] Verify integration

### Documentation Phase
- [ ] Update progress documents
- [ ] Document patterns used
- [ ] Note lessons learned
- [ ] Update architecture docs

---

## Success Metrics

### Per File
-  Every module <300 lines
-  Single responsibility per module
-  Zero circular dependencies
-  All modules compile
-  Tests pass (if applicable)

### Overall Progress
- **P1 Files Completed:** 1/15 (7%)
- **Total Modules Created:** 13
- **Average Module Size:** 185 lines
- **Compilation Success:** 100%

---

## Time Estimates

### Per File (Average)
- **Analysis:** 30 minutes
- **Module Creation:** 2 hours
- **Testing:** 30 minutes
- **Documentation:** 20 minutes
- **Total:** ~3 hours per file

### Full P1 Completion
- **Files:** 15
- **Estimated Time:** 45 hours
- **At 1 file/day:** 15 days
- **Target Completion:** 2025-10-24

### Full Codebase
- **P1 Files:** 15 files (45 hours)
- **P2 Files:** 20 files (40 hours)
- **P3 Files:** 15 files (30 hours)
- **Total:** 115 hours (~3 weeks full-time)

---

## Tools and Commands

### Analysis
```bash
# Find largest files
find ./pkg ./cmd -name "*.go" -not -path "*/vendor/*" | xargs wc -l | sort -n | tail -20

# Count responsibilities (rough estimate)
grep -n "^func " file.go | wc -l

# Check dependencies
grep "^import" file.go -A 20
```

### Compilation
```bash
# Build specific module
go build ./pkg/consul/installer/...

# Build entire package
go build ./pkg/consul/

# Build everything
go build ./...
```

### Verification
```bash
# Check for circular dependencies
go list -f '{{.ImportPath}} {{.Imports}}' ./pkg/... | grep -i cycle

# Run tests
go test ./pkg/consul/...

# Check line counts
wc -l pkg/consul/**/*.go
```

---

## Lessons Learned (File 1)

### What Worked Well 
1. **Evidence-Based Approach** - Line numbers and function names
2. **Adversarial Thinking** - Challenging each decision
3. **Clear Boundaries** - One responsibility per module
4. **Systematic Process** - Read, analyze, design, extract, verify
5. **Dependency Injection** - Explicit dependencies
6. **Context Propagation** - Proper timeout handling

### Challenges Encountered
1. **Type Redeclaration** - Needed to coordinate shared types
2. **Import Organization** - Careful package structure required
3. **Helper Functions** - Deciding where to place utilities

### Solutions Applied
1. **Shared Types** - Keep in original file or types.go
2. **Package Structure** - Clear subdirectories by domain
3. **Helper Modules** - Group by domain, not by "utils"

---

## Ready to Proceed

### Prerequisites Met 
- [x] First P1 file complete
- [x] Patterns established
- [x] Quality standards defined
- [x] Tools and commands documented
- [x] Success metrics clear

### Next Actions
1. **Analyze** cmd/debug/iris.go
2. **Design** module structure
3. **Extract** systematically
4. **Verify** compilation
5. **Document** progress

---

**Status:** Ready for next P1 file  
**Target:** cmd/debug/iris.go (1,659 lines)  
**Estimated Completion:** 3 hours  
**Start When:** User confirms readiness  

---

**Last Updated:** 2025-10-09 01:30:00  
**Progress:** 1/15 P1 files complete (7%)  
**Momentum:** Strong - patterns established, ready to scale
