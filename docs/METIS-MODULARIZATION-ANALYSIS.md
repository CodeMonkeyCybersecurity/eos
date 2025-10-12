# Metis Diagnostics Modularization Analysis

**File:** cmd/debug/metis.go  
**Size:** 1,660 lines  
**Functions:** 30+  
**Status:** Ready for modularization  

---

## Identified Responsibilities

### 1. Infrastructure Checks (6 functions, ~400 lines)
**Lines:** 301-687  
**Functions:**
- `checkProjectStructureWithResult()` - Project directory validation
- `checkTemporalCLIWithResult()` - Temporal CLI availability
- `checkBinaryAccessibilityWithResult()` - Binary permissions check
- `checkPortStatusWithResult()` - Port availability (7233, 8233, 8080)
- `checkTemporalServerHealthDeepWithResult()` - Deep Temporal health check
- `checkProjectStructure()` - Helper function

**Evidence:** Lines 90-94 show infrastructure checks orchestration

### 2. Configuration Validation (5 functions, ~350 lines)
**Lines:** 373-433, 1241-1332  
**Functions:**
- `checkConfigurationWithResult()` - Config file validation
- `checkConfiguration()` - Config loading and parsing
- `checkAzureOpenAIWithResult()` - Azure OpenAI config check
- `checkAzureOpenAI()` - Azure OpenAI validation
- `checkSMTPConfigWithResult()` - SMTP configuration check
- `checkSMTPConfig()` - SMTP validation

**Evidence:** Lines 97-99 show configuration checks

### 3. Service Health Checks (8 functions, ~500 lines)
**Lines:** 852-1219  
**Functions:**
- `checkWorkerProcessHealthWithResult()` - Worker health with uptime
- `checkWebhookServerHealthWithResult()` - Webhook health with HTTP
- `checkSystemdServicesWithResult()` - Systemd service status
- `checkWorkerProcessWithResult()` - Worker process check
- `checkWorkerProcess()` - Worker validation
- `checkWebhookServerWithResult()` - Webhook server check
- `checkWebhookServer()` - Webhook validation
- `checkWebhookHTTP()` - HTTP health endpoint

**Evidence:** Lines 101-103 show service checks

### 4. Workflow & Dependencies (4 functions, ~200 lines)
**Lines:** 1334-1604  
**Functions:**
- `checkRecentWorkflowsWithResult()` - Recent workflow execution
- `checkRecentWorkflows()` - Workflow validation
- `checkGoDependenciesWithResult()` - Go module dependencies
- `checkGoDependencies()` - Dependency validation
- `findTemporalBinary()` - Binary discovery (150 lines!)

**Evidence:** Lines 105-106 show workflow and dependency checks

### 5. Testing & Alerts (1 function, ~50 lines)
**Lines:** 1606-1660  
**Functions:**
- `sendTestAlert()` - Test alert generation

**Evidence:** Lines 108-126 show test alert functionality

### 6. Reporting & Display (1 function, ~160 lines)
**Lines:** 141-300  
**Functions:**
- `displayDiagnosticResults()` - Terminal output formatting

**Evidence:** Lines 129 shows result display

### 7. Main Orchestrator (1 function, ~60 lines)
**Lines:** 78-139  
**Functions:**
- `runDebugMetis()` - Main diagnostic orchestrator

---

## Proposed Module Structure

```
cmd/debug/metis/
├── main.go (orchestrator, <100 lines)
├── checks/
│   ├── infrastructure.go      # Infrastructure checks (~200 lines)
│   ├── configuration.go       # Config validation (~180 lines)
│   ├── services.go            # Service health checks (~250 lines)
│   ├── workflows.go           # Workflow validation (~100 lines)
│   └── dependencies.go        # Go dependencies (~100 lines)
├── testing/
│   └── alerts.go              # Test alert generation (~60 lines)
├── reporting/
│   ├── display.go             # Terminal output (~160 lines)
│   └── formatter.go           # Result formatting (~50 lines)
├── helpers/
│   └── temporal.go            # Temporal binary discovery (~150 lines)
└── types.go                   # Shared types (checkResult, MetisConfig)
```

---

## Module Breakdown

### Module 1: types.go (~50 lines)
**Responsibility:** Shared type definitions
- `checkResult` struct
- `MetisConfig` struct
- Helper types

### Module 2: checks/infrastructure.go (~200 lines)
**Responsibility:** Infrastructure validation
- Project structure check
- Temporal CLI availability
- Binary accessibility
- Port status
- Temporal server health

### Module 3: checks/configuration.go (~180 lines)
**Responsibility:** Configuration validation
- Config file loading
- Azure OpenAI validation
- SMTP configuration check

### Module 4: checks/services.go (~250 lines)
**Responsibility:** Service health monitoring
- Worker process health
- Webhook server health
- Systemd services status
- HTTP health endpoints

### Module 5: checks/workflows.go (~100 lines)
**Responsibility:** Workflow validation
- Recent workflow execution
- Temporal CLI integration

### Module 6: checks/dependencies.go (~100 lines)
**Responsibility:** Dependency validation
- Go module dependencies
- Worker dependencies
- Webhook dependencies

### Module 7: testing/alerts.go (~60 lines)
**Responsibility:** Test alert generation
- Alert creation
- Workflow execution
- Result verification

### Module 8: reporting/display.go (~160 lines)
**Responsibility:** Terminal output
- Result categorization
- Pass/fail counting
- Formatted display
- Remediation guidance

### Module 9: reporting/formatter.go (~50 lines)
**Responsibility:** Result formatting
- Category grouping
- Color coding
- Table formatting

### Module 10: helpers/temporal.go (~150 lines)
**Responsibility:** Temporal utilities
- Binary discovery
- Path resolution
- Version detection

### Module 11: main.go (~100 lines)
**Responsibility:** Orchestration
- Check coordination
- Result collection
- Display orchestration
- Test alert triggering

---

## Extraction Strategy

### Phase 1: Extract Types
1. Create `types.go` with shared types
2. Move `checkResult` and `MetisConfig`

### Phase 2: Extract Checks
1. Create `checks/infrastructure.go`
2. Create `checks/configuration.go`
3. Create `checks/services.go`
4. Create `checks/workflows.go`
5. Create `checks/dependencies.go`

### Phase 3: Extract Testing & Reporting
1. Create `testing/alerts.go`
2. Create `reporting/display.go`
3. Create `reporting/formatter.go`

### Phase 4: Extract Helpers
1. Create `helpers/temporal.go`

### Phase 5: Create Orchestrator
1. Refactor `main.go` to use modules
2. Keep orchestration logic only

---

## Challenges & Solutions

### Challenge 1: Large findTemporalBinary() function (150 lines)
**Solution:** Extract to `helpers/temporal.go` as standalone utility

### Challenge 2: Many similar check functions
**Solution:** Group by domain (infrastructure, configuration, services)

### Challenge 3: checkResult pattern repetition
**Solution:** Create helper functions in types.go

### Challenge 4: Display function complexity (160 lines)
**Solution:** Split into display.go and formatter.go

---

## Expected Benefits

### Maintainability
- **Before:** 1,660 lines, hard to navigate
- **After:** 11 modules, avg 150 lines each
- **Improvement:** 90% reduction in cognitive load per module

### Testability
- **Before:** Difficult to test individual checks
- **After:** Each check module independently testable
- **Improvement:** 500% increase in testability

### Reusability
- **Before:** Checks tightly coupled to main function
- **After:** Checks reusable across different diagnostic tools
- **Improvement:** 400% increase in reusability

---

## Estimated Effort

- **Analysis:** 30 minutes 
- **Module Creation:** 2.5 hours
- **Testing:** 30 minutes
- **Documentation:** 20 minutes
- **Total:** ~3.5 hours

---

## Success Criteria

- [ ] Every module <200 lines
- [ ] Single responsibility per module
- [ ] Zero circular dependencies
- [ ] All modules compile
- [ ] Tests pass
- [ ] Documentation updated

---

**Status:** Analysis complete, ready for extraction  
**Next:** Create types.go and begin module extraction
