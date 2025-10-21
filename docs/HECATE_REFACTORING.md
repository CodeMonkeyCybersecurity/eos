# Hecate Package Refactoring Plan

*Last Updated: 2025-10-21*

## Executive Summary

The `pkg/hecate` package has grown into a 68-file monolith (~500KB) with multiple architectural issues:
- Template code duplicated across 5+ packages
- Shell commands instead of Docker SDK
- DNS code misplaced (should be separate package)
- Duplicate Terraform logic
- 22KB god file (`yaml_generator.go`)

This document proposes a systematic refactoring to improve maintainability, reduce duplication, and follow Eos architectural principles.

## Current State Analysis

### Package Inventory (68 files, ~500KB)

```
pkg/hecate/
├── **Template Generation** (5 files, 60KB) ← DUPLICATED LOGIC
│   ├── yaml_generator.go (22KB) - GIANT file with inline templates
│   ├── caddyfile_generator.go (6.5KB)
│   ├── config_generator.go (18KB)
│   ├── terraform_templates.go (6.6KB)
│   └── utils.go (5.4KB) - renderTemplateFromString (duplicates pkg/fileops)
│
├── **Infrastructure** (11 files, ~100KB) ✓ GOOD
│   ├── phase1-8_*.go - Phased deployment (good separation)
│   ├── lifecycle_create*.go - Orchestration
│   ├── preflight_checks.go (22KB) - Comprehensive validation
│   └── lifecycle_compat.go (NEW) - Legacy compatibility shim
│
├── **State Management** (6 files, ~70KB) ✓ GOOD
│   ├── state_manager.go (15KB)
│   ├── config_storage.go (6.5KB)
│   ├── consul_config.go (8.2KB)
│   └── consul_integration.go (9.3KB)
│
├── **Auth & SSO** (4 files, ~55KB) ✓ GOOD
│   ├── auth.go, auth_complete.go, auth_manager.go
│   └── bootstrap_credentials.go
│
├── **DNS Management** (7 files, ~70KB) ✗ WRONG LOCATION
│   ├── dns_manager.go (18KB) - Should be pkg/dns
│   ├── dns_security.go (11KB)
│   ├── dns_validation.go (7.4KB)
│   ├── dns_challenge.go (6.8KB)
│   └── 3 more... - DNS is cross-cutting, not Hecate-specific!
│
├── **Terraform** (3 files, ~19KB) ✗ DUPLICATE
│   ├── client_terraform.go (12KB)
│   ├── terraform_templates.go (6.6KB)
│   └── terraform_config.go (417B)
│   └── pkg/terraform/ already exists! Duplicate logic!
│
└── **30+ other files**: validation, types, streams, secrets, routes, etc.
```

### Critical Issues (P0)

#### 1. Template Rendering Duplication

**Problem**: 5+ packages reinvent template rendering with NO shared infrastructure:

```go
// hecate/utils.go:35
func renderTemplateFromString(tmplStr string, data interface{}) (string, error) {
    tmpl, err := template.New("compose").Parse(tmplStr)
    ...
}

// fileops/template_operations.go:35 (BETTER - has security)
type TemplateOperations struct {
    rateLimiter *rate.Limiter  // ✓ Rate limiting
    // ✓ Max template size checks (1MB limit)
    // ✓ Timeout enforcement (30s)
}

// ALSO DUPLICATED IN:
// - pkg/minio/deployer.go
// - pkg/kvm/templates.go
// - pkg/nomad/job_generator.go
// - pkg/terraform/*.go
```

**Impact**:
- Code duplication (~500 lines across packages)
- Inconsistent security (only fileops has rate limiting)
- No standardization (different error messages, timeout values)

#### 2. Shell Commands Instead of Docker SDK

**Problem**: Validation uses `exec.Command("docker", "compose", ...)` when SDK is available:

```go
// pkg/hecate/validation_files.go:83 - SHELLS OUT ✗
cmd := exec.CommandContext(ctx, "docker", "compose", "-f", composeFile, "config")

// BUT pkg/container/compose.go:17-21 - IMPORTS SDK ✓
import (
    "github.com/docker/docker/api/types/container"
    "github.com/docker/docker/client"
)

// AND pkg/docker/compose_precipitate.go - USES SDK CORRECTLY ✓
client, err := client.NewClientWithOpts(client.FromEnv)
inspect, err := client.ContainerInspect(ctx, containerID)
```

**Why This Matters**:
- Shell commands are brittle (fail if `docker` not in PATH)
- SDK provides structured errors (better debugging)
- SDK is faster (no process fork overhead)
- Inconsistent with rest of codebase

**False Positive in Validation**:
The current validator (`docker compose config --env-file .env`) gives false positives because it validates the SUBSTITUTED output, not the raw template. This allowed the `$${}` bug to pass validation.

#### 3. yaml_generator.go God File (22KB)

**Structure**:
- Lines 1-100: Imports, HecateSecrets type, secret generation
- Lines 100-215: Caddyfile template (115 lines inline string)
- Lines 217-386: Docker Compose template (169 lines!)
- Lines 388-500: nginx.conf template (112 lines)
- Lines 500-600: .env file generation
- Lines 600-761: Orchestration logic

**Violations**:
- Single Responsibility Principle (does EVERYTHING)
- 169-line docker-compose template as const string (unmaintainable)
- No template reusability
- Hard to test individual templates

### What's Working Well ✓

1. **Phase-based deployment** (phase1-8) - Clear separation of concerns
2. **Preflight checks** - Comprehensive validation before deployment
3. **State management** - Consul integration for distributed config
4. **Type separation** - types_docker.go, types_caddy.go, types_nginx.go
5. **Validation error messages** - Good remediation guidance

## Proposed Architecture

### Target Structure

```
pkg/
├── templates/           ← **NEW**: Unified template system
│   ├── render.go        Security-hardened renderer (from fileops)
│   ├── types.go         TemplateData, RenderOptions
│   └── hecate/          Extracted from yaml_generator.go
│       ├── docker.tmpl  Docker Compose template
│       ├── caddy.tmpl   Caddyfile template
│       ├── nginx.tmpl   nginx.conf template
│       └── env.tmpl     .env file template
│
├── dns/                 ← **NEW**: Extracted from hecate
│   ├── manager.go       From hecate/dns_manager.go
│   ├── security.go      From hecate/dns_security.go
│   ├── validation.go    From hecate/dns_validation.go
│   └── challenge.go     From hecate/dns_challenge.go
│
├── hecate/              ← **SLIMMED**: 68 files → ~40 files
│   ├── generator.go     Orchestration only (uses pkg/templates)
│   ├── phase*.go        Unchanged (already good)
│   ├── lifecycle*.go    Unchanged
│   ├── preflight*.go    Unchanged
│   ├── auth*.go         Unchanged
│   ├── state*.go        Unchanged
│   ├── types*.go        Unchanged
│   ├── validation.go    UPDATED: Use Docker SDK, not shell
│   ├── lifecycle_compat.go (NEW) Shim for old GenerateCompleteHecateStack
│   └── **DELETED**: dns_*, terraform_*, compose_generator.go
│
├── docker/              ← **ENHANCED**
│   ├── compose_validate.go  NEW: SDK-based validation
│   ├── compose_precipitate.go (exists, uses SDK ✓)
│   └── cleanup.go       (exists)
│
└── container/           ← **Already good** ✓
    ├── compose.go       Uses SDK for parsing
    ├── docker.go        Uses SDK for operations
    └── client.go        SDK client management
```

### Migration Phases

#### Phase 1: Create Unified Template Infrastructure (P1 - High Priority)

**Goal**: Single source of truth for template rendering

**Tasks**:
1. Create `pkg/templates/render.go`:
   - Copy security features from `pkg/fileops/template_operations.go`
   - Rate limiting (10/min)
   - Size limits (1MB max)
   - Timeout enforcement (30s)
   - Structured logging

2. Create `pkg/templates/types.go`:
   ```go
   type TemplateData struct {
       Data map[string]interface{}
       Funcs template.FuncMap
   }

   type RenderOptions struct {
       MaxSize time.Duration
       Timeout time.Duration
   }
   ```

3. Extract templates from `yaml_generator.go` to `.tmpl` files:
   - `pkg/templates/hecate/docker.tmpl` (169 lines)
   - `pkg/templates/hecate/caddy.tmpl` (115 lines)
   - `pkg/templates/hecate/nginx.tmpl` (112 lines)
   - `pkg/templates/hecate/env.tmpl` (new)

**Benefits**:
- Eliminates ~500 lines of duplicate code
- Consistent security across all templates
- Easy to test templates independently
- Templates can be edited without recompiling

**Risks**:
- Breaking changes if template syntax changes
- Requires migration of 5+ packages

**Mitigation**:
- Keep old `renderTemplateFromString()` as deprecated wrapper
- Migrate packages one at a time
- Add comprehensive tests

#### Phase 2: Docker SDK Migration (P1 - High Priority)

**Goal**: Replace shell commands with Docker SDK calls

**Tasks**:
1. Create `pkg/docker/compose_validate.go`:
   ```go
   func ValidateComposeFile(ctx context.Context, composePath, envPath string) error {
       // Parse YAML
       composeData, err := os.ReadFile(composePath)
       var compose map[string]interface{}
       yaml.Unmarshal(composeData, &compose)

       // Validate services
       services := compose["services"].(map[string]interface{})
       for name, svc := range services {
           // Check image format
           // Check port mappings
           // Check volume mounts
           // Check network references
       }

       // Substitute variables from .env
       envVars := parseEnvFile(envPath)
       substituteVariables(&compose, envVars)

       return nil
   }
   ```

2. Update `pkg/hecate/validation_files.go`:
   - Replace `exec.Command("docker", "compose", "config")`
   - Use `pkg/docker/compose_validate.go`
   - Keep shell as fallback with warning

**Benefits**:
- More reliable (no dependency on docker CLI)
- Better error messages (structured, not stderr parsing)
- Faster (no process fork)
- Catches template bugs (validates RAW template, not substituted)

**Risks**:
- Docker Compose spec is complex (may miss edge cases)
- SDK validation != docker compose validation

**Mitigation**:
- Keep shell validation as fallback
- Add comprehensive test suite
- Log warnings when SDK and shell disagree

#### Phase 3: Extract DNS Package (P2 - Medium Priority)

**Goal**: DNS is cross-cutting, should be reusable

**Tasks**:
1. Create `pkg/dns/` package
2. Move 7 files from `pkg/hecate/dns_*.go`:
   - `dns_manager.go` → `pkg/dns/manager.go`
   - `dns_security.go` → `pkg/dns/security.go`
   - `dns_validation.go` → `pkg/dns/validation.go`
   - `dns_challenge.go` → `pkg/dns/challenge.go`
   - `dns_integration.go` → `pkg/dns/integration.go`
   - `dns_error_handling_test.go` → `pkg/dns/errors_test.go`
   - `route_dns_integration_test.go` → `pkg/dns/routes_test.go`

3. Update imports in hecate package:
   ```go
   // OLD
   import "github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
   hecate.ValidateDNSRecord(...)

   // NEW
   import "github.com/CodeMonkeyCybersecurity/eos/pkg/dns"
   dns.ValidateRecord(...)
   ```

**Benefits**:
- Reusable across other packages (Helen, Delphi, etc.)
- Clearer separation of concerns
- Easier to test DNS logic independently

**Risks**:
- May break existing code if imports not updated
- DNS logic may be tightly coupled to Hecate

**Mitigation**:
- Use interface abstraction: `type DNSManager interface`
- Keep hecate-specific logic in hecate package
- Comprehensive grep for import changes

#### Phase 4: Consolidate Terraform Code (P2 - Medium Priority)

**Goal**: One Terraform package, not two

**Tasks**:
1. Audit `pkg/hecate/client_terraform.go`:
   - Is this Hecate-specific or generic?
   - Can it be merged into `pkg/terraform/`?

2. Delete duplicates:
   - `pkg/hecate/terraform_templates.go`
   - `pkg/hecate/terraform_config.go`
   - `pkg/hecate/client_terraform.go` (if generic)

3. Move Hecate-specific Terraform to `pkg/terraform/hecate.go`

**Benefits**:
- Single source of truth for Terraform operations
- Reduces pkg/hecate by ~19KB

**Risks**:
- May break existing Hecate deployments
- Hecate Terraform logic may have unique requirements

**Mitigation**:
- Thorough testing before deletion
- Keep deprecated wrappers for 1-2 releases

#### Phase 5: Refactor yaml_generator.go (P3 - Low Priority)

**Goal**: Break up god file

**Tasks**:
1. Move templates to `pkg/templates/hecate/*.tmpl` (done in Phase 1)
2. Slim down to pure orchestration:
   ```go
   // yaml_generator.go (NEW: ~200 lines, down from 761)
   func GenerateFromYAML(rc, config, outputDir, envConfig) error {
       // 1. Load templates from pkg/templates/hecate
       // 2. Generate secrets
       // 3. Render templates
       // 4. Write files
       // 5. Validate
   }
   ```

**Benefits**:
- Single Responsibility Principle
- Easier to test
- Templates can be hot-reloaded in development

**Risks**:
- Large refactor (761 lines → multiple files)
- May introduce bugs

**Mitigation**:
- Incremental migration
- Comprehensive integration tests
- Keep old code as `_legacy.go` for 1 release

## Implementation Timeline

| Phase | Priority | Effort | Risk | Timeline |
|-------|----------|--------|------|----------|
| 1. Unified Templates | P1 | High (2-3 days) | Medium | Week 1-2 |
| 2. Docker SDK | P1 | Medium (1-2 days) | Low | Week 2-3 |
| 3. Extract DNS | P2 | Low (1 day) | Low | Week 3 |
| 4. Terraform Consolidation | P2 | Low (1 day) | Medium | Week 4 |
| 5. Refactor yaml_generator | P3 | High (2-3 days) | High | Week 5-6 |

**Total Effort**: ~2-3 weeks for complete refactoring

## Testing Strategy

### Unit Tests

```go
// pkg/templates/render_test.go
func TestRenderTemplate_RateLimit(t *testing.T) {
    // Test rate limiting works
}

func TestRenderTemplate_SizeLimit(t *testing.T) {
    // Test 1MB limit enforced
}

// pkg/docker/compose_validate_test.go
func TestValidateComposeFile_InvalidImage(t *testing.T) {
    // Test catches invalid image references
}

func TestValidateComposeFile_VariableSubstitution(t *testing.T) {
    // Test ${VAR} vs $${VAR} handling
}
```

### Integration Tests

```go
// pkg/hecate/generator_test.go
func TestGenerateFromYAML_FullStack(t *testing.T) {
    // End-to-end test: YAML → docker-compose.yml
    // Validates with Docker SDK
    // Checks all files created
}
```

### Regression Tests

- Keep old `compose_generator.go` code as golden tests
- Compare output of old vs new generator
- Ensure byte-for-byte compatibility (except whitespace)

## Success Metrics

- **Code Reduction**: 68 files → ~40 files (-40%)
- **Duplication Removal**: ~500 lines of duplicate template code eliminated
- **Build Time**: No regression (should improve slightly)
- **Test Coverage**: Maintain 70%+ coverage
- **Zero Breaking Changes**: All existing commands continue to work

## Rollback Plan

If refactoring causes issues:

1. **Phase 1-2**: Revert to old `renderTemplateFromString()` wrapper
2. **Phase 3**: Re-add `pkg/hecate/dns_*.go` files with git revert
3. **Phase 4**: Restore deleted Terraform files
4. **Phase 5**: Keep `yaml_generator.go` as-is, mark as "needs refactoring"

All phases should be isolated commits for easy rollback.

## Open Questions

1. **Template Format**: Keep inline strings or switch to `.tmpl` files?
   - **Recommendation**: `.tmpl` files (easier to edit, syntax highlighting)

2. **Docker SDK Coverage**: Does SDK cover 100% of `docker compose config`?
   - **Recommendation**: Research SDK capabilities, keep shell as fallback

3. **DNS Package API**: What interface should `pkg/dns` expose?
   - **Recommendation**: `type DNSManager interface` with Cloudflare/Route53 implementations

4. **Migration Strategy**: Big bang or incremental?
   - **Recommendation**: Incremental (one phase at a time)

## References

- Existing template code: `pkg/fileops/template_operations.go`
- Docker SDK examples: `pkg/docker/compose_precipitate.go`
- Template patterns: `pkg/kvm/templates.go`, `pkg/nomad/job_generator.go`
- Architecture guidelines: `CLAUDE.md` (updated with Docker SDK rules)

---

**Status**: Draft (2025-10-21)
**Owner**: Eos Architecture Team
**Approvers**: Henry (Code Monkey Cybersecurity)
