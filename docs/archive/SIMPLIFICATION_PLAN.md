# Eos Codebase Simplification Plan

## Current State Analysis

Based on CLAUDE.md compliance analysis, we've identified major architectural issues:

### 1. Logging Violations (1078+ instances)
- **Problem**: Using `fmt.Printf/Println` instead of `otelzap.Ctx(rc.Ctx)`
- **Impact**: No structured logging, difficult debugging, violates core principle
- **Priority**: HIGH - Easy to fix, high impact

### 2. Business Logic in cmd/ (36+ files)
- **Problem**: Direct execution of business logic in command files
- **Examples**: 
  - `cmd/create/ollama.go` - Docker operations, file writes
  - `cmd/self/ai/ai.go` - Complex AI operations
- **Impact**: Untestable, violates architectural boundaries
- **Priority**: HIGH - Critical for maintainability

### 3. Manager Pattern Overuse (54+ managers)
- **Problem**: Classes with methods that should be package functions
- **Examples**: `VaultManager`, `ServiceManager`, `GitManager`
- **Impact**: Unnecessary complexity, harder to test
- **Priority**: MEDIUM - Significant simplification opportunity

### 4. Missing Assess → Intervene → Evaluate Pattern
- **Problem**: Operations without proper validation and verification
- **Impact**: Less reliable operations, inconsistent error handling
- **Priority**: MEDIUM - Improves reliability

### 5. HTTP Client Proliferation (38+ implementations)
- **Problem**: Every package creates its own HTTP client
- **Impact**: Inconsistent configuration, no shared middleware
- **Priority**: LOW - Good consolidation opportunity

## Implementation Strategy

### Phase 1: Fix Logging Violations (Week 1)
```bash
# Automated replacement patterns:
sed -i 's/fmt\.Printf("\(.*\)\\n"/logger.Info("terminal prompt: \1"/g'
sed -i 's/fmt\.Println("\(.*\)"/logger.Info("terminal prompt: \1"/g'
sed -i 's/fmt\.Print("\(.*\)"/logger.Info("terminal prompt: \1"/g'
```

Key patterns to replace:
- User prompts: `logger.Info("terminal prompt: message")`
- Debug info: `logger.Debug("operation detail", zap.String("key", value))`
- Errors: `logger.Error("error description", zap.Error(err))`

### Phase 2: Extract Business Logic (Week 2-3)
For each violating cmd file:
1. Create corresponding pkg if missing
2. Move business logic to pkg functions
3. Update cmd to only parse flags and call pkg functions

Example transformation:
```go
// BEFORE (cmd/create/ollama.go)
err := execute.RunSimple(rc.Ctx, "docker", "rm", "-f", containerName)
if err != nil {
    log.Warn("Failed to remove container", zap.Error(err))
}

// AFTER (cmd/create/ollama.go)
if err := ollama.RemoveContainer(rc, containerName); err != nil {
    return err
}

// NEW (pkg/ollama/container.go)
func RemoveContainer(rc *eos_io.RuntimeContext, name string) error {
    logger := otelzap.Ctx(rc.Ctx)
    
    // ASSESS
    logger.Info("Assessing container removal", zap.String("container", name))
    
    // INTERVENE
    logger.Info("Removing container", zap.String("container", name))
    if err := execute.RunSimple(rc.Ctx, "docker", "rm", "-f", name); err != nil {
        logger.Warn("Failed to remove container", 
            zap.String("container", name),
            zap.Error(err))
        return nil // Non-fatal
    }
    
    // EVALUATE
    logger.Info("Container removed successfully", zap.String("container", name))
    return nil
}
```

### Phase 3: Simplify Managers (Week 4)
Convert manager methods to package functions:

```go
// BEFORE
type ServiceManager struct {
    config Config
}
func (m *ServiceManager) ListServices(filter string) ([]Service, error)

// AFTER
func ListServices(rc *eos_io.RuntimeContext, config Config, filter string) ([]Service, error)
```

### Phase 4: Implement A→I→E Pattern (Week 5)
Retrofit existing functions with proper pattern:
- Add prerequisite checks (ASSESS)
- Clear logging for operations (INTERVENE)
- Verify success (EVALUATE)

### Phase 5: Consolidate HTTP Clients (Week 6)
- Use pkg/httpclient everywhere
- Remove custom client implementations
- Standardize timeout and retry logic

## Success Metrics
- Zero fmt.Print* usage in codebase
- All business logic in pkg/ with <10 lines per cmd function
- 50% reduction in manager classes
- 100% of operations follow A→I→E pattern
- Single HTTP client implementation

## Migration Order
1. High-traffic commands first (create, read, update)
2. Security-critical operations next
3. Utility commands last