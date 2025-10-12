# EOS Codebase Modularization Plan

**Date:** 2025-10-09  
**Status:** Analysis Complete - Ready for Execution  
**Approach:** Adversarial Self-Collaboration with Single Responsibility Principle  

---

## Executive Summary

Analysis of the EOS codebase identified **50+ files** requiring modularization to follow the Single Responsibility Principle (SRP). The codebase contains several files exceeding 1,000 lines with multiple distinct responsibilities that should be separated into focused modules.

**Total Lines Analyzed:** 434,498 lines across Go codebase  
**Files Requiring Modularization:** 50+ files  
**Priority 1 (P1) Files:** 15 files (>1000 lines or >5 responsibilities)  
**Priority 2 (P2) Files:** 20 files (500-1000 lines or 3-5 responsibilities)  
**Priority 3 (P3) Files:** 15+ files (300-500 lines or 2-3 responsibilities)  

---

## Phase 1: Analysis & Prioritization

### Priority 1 (P1) - Immediate Action Required (>1000 lines)

#### 1. **pkg/consul/install.go** (1,713 lines)  CRITICAL
**Current Responsibilities:**
- Consul binary installation (repository & direct download)
- Version detection and management
- System prerequisites validation (memory, disk, ports)
- Configuration file generation
- Systemd service setup and management
- Installation rollback and cleanup
- Network interface detection
- HTTP client operations
- Progress reporting
- User/directory/file management helpers

**Proposed Module Structure:**
```
pkg/consul/
├── install.go (orchestrator, <200 lines)
├── installer/
│   ├── binary.go          # Binary download and installation
│   ├── repository.go      # APT repository installation
│   └── version.go         # Version detection and resolution
├── validation/
│   ├── prerequisites.go   # System requirements validation
│   ├── ports.go          # Port availability checking
│   └── resources.go      # Memory/disk validation
├── config/
│   ├── generator.go      # Configuration file generation
│   └── templates.go      # HCL templates
├── service/
│   ├── systemd.go        # Systemd service management
│   └── lifecycle.go      # Start/stop/restart operations
├── rollback/
│   ├── manager.go        # Rollback orchestration
│   └── cleanup.go        # Cleanup operations
└── helpers/
    ├── network.go        # Network interface detection
    ├── http.go           # HTTP client operations
    ├── progress.go       # Progress reporting
    └── filesystem.go     # File/directory operations
```

**Estimated Effort:** 8-10 hours  
**Dependencies:** pkg/eos_io, pkg/eos_err, pkg/shared  
**Security Considerations:** Preserve all error handling and validation logic  

---

#### 2. **cmd/debug/metis.go** (1,659 lines)  CRITICAL
**Current Responsibilities:**
- Metis service diagnostics
- Infrastructure checks (Temporal, PostgreSQL, Redis)
- Configuration validation
- Service health monitoring
- Workflow execution testing
- Alert system testing
- Dependency verification
- Diagnostic report generation
- Remediation guidance

**Proposed Module Structure:**
```
cmd/debug/metis/
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

**Estimated Effort:** 6-8 hours  
**Dependencies:** pkg/delphi, pkg/metis  
**Security Considerations:** Preserve credential handling in checks  

---

#### 3. **cmd/debug/delphi.go** (1,630 lines)  CRITICAL
**Current Responsibilities:**
- Delphi/Wazuh diagnostics
- Agent connectivity checks
- API endpoint validation
- Database connectivity
- Service health monitoring
- Configuration validation
- Certificate verification
- Diagnostic report generation

**Proposed Module Structure:**
```
cmd/debug/delphi/
├── main.go (orchestrator, <150 lines)
├── checks/
│   ├── agents.go          # Agent connectivity
│   ├── api.go             # API endpoint validation
│   ├── database.go        # Database checks
│   └── certificates.go    # Certificate validation
├── health/
│   ├── services.go        # Service health monitoring
│   └── connectivity.go    # Network connectivity
├── reporting/
│   ├── formatter.go       # Report formatting
│   └── display.go         # Terminal output
└── types.go               # Shared types
```

**Estimated Effort:** 6-8 hours  
**Dependencies:** pkg/delphi  

---

#### 4. **pkg/authentik/import.go** (1,266 lines)  CRITICAL
**Current Responsibilities:**
- Authentik configuration import
- User/group import
- Application configuration
- Provider setup (OAuth2, SAML, LDAP)
- Flow configuration
- Policy management
- Stage configuration
- Binding management

**Proposed Module Structure:**
```
pkg/authentik/import/
├── orchestrator.go (<200 lines)
├── users.go              # User/group import
├── applications.go       # Application configuration
├── providers.go          # Provider setup
├── flows.go              # Flow configuration
├── policies.go           # Policy management
├── stages.go             # Stage configuration
└── bindings.go           # Binding management
```

**Estimated Effort:** 8-10 hours  
**Dependencies:** pkg/authentik/api  

---

#### 5. **pkg/vault/install.go** (1,253 lines)  CRITICAL
**Current Responsibilities:**
- Vault binary installation
- Configuration generation
- Systemd service setup
- TLS certificate management
- Auto-unseal configuration
- Storage backend setup
- Initialization and unsealing
- Root token management
- Prerequisites validation

**Proposed Module Structure:**
```
pkg/vault/
├── install.go (orchestrator, <200 lines)
├── installer/
│   ├── binary.go          # Binary installation
│   ├── repository.go      # Repository installation
│   └── version.go         # Version management
├── config/
│   ├── generator.go       # Config generation
│   ├── storage.go         # Storage backend config
│   └── tls.go             # TLS configuration
├── service/
│   ├── systemd.go         # Systemd management
│   └── lifecycle.go       # Start/stop operations
├── initialization/
│   ├── unsealer.go        # Unseal operations
│   ├── root_token.go      # Root token management
│   └── auto_unseal.go     # Auto-unseal setup
└── validation/
    └── prerequisites.go   # System validation
```

**Estimated Effort:** 8-10 hours  

---

#### 6. **pkg/system/orchestration.go** (1,166 lines)
**Current Responsibilities:**
- System orchestration
- Service deployment
- Configuration management
- Health monitoring
- Rollback management
- State synchronization

**Proposed Module Structure:**
```
pkg/system/orchestration/
├── orchestrator.go (<200 lines)
├── deployment.go         # Service deployment
├── configuration.go      # Config management
├── health.go             # Health monitoring
├── rollback.go           # Rollback operations
└── state.go              # State synchronization
```

**Estimated Effort:** 6-8 hours  

---

#### 7. **cmd/create/metis.go** (1,154 lines)
**Current Responsibilities:**
- Metis service creation
- Temporal setup
- Database provisioning
- Worker configuration
- Webhook server setup
- Service registration

**Proposed Module Structure:**
```
cmd/create/metis/
├── main.go (<150 lines)
├── temporal.go           # Temporal setup
├── database.go           # Database provisioning
├── workers.go            # Worker configuration
├── webhook.go            # Webhook server
└── registration.go       # Service registration
```

**Estimated Effort:** 6-8 hours  

---

#### 8. **pkg/database_management/backup.go** (1,123 lines)
**Current Responsibilities:**
- Database backup operations
- Backup scheduling
- Retention management
- Compression
- Encryption
- Cloud storage integration
- Restore operations

**Proposed Module Structure:**
```
pkg/database_management/backup/
├── manager.go (<200 lines)
├── operations.go         # Backup/restore operations
├── scheduling.go         # Backup scheduling
├── retention.go          # Retention policies
├── compression.go        # Compression handling
├── encryption.go         # Encryption operations
└── storage.go            # Cloud storage integration
```

**Estimated Effort:** 6-8 hours  

---

#### 9. **pkg/storage/types.go** (1,086 lines)
**Current Responsibilities:**
- Storage type definitions
- Disk information structures
- Partition information
- Volume configuration
- Mount operations
- LVM types
- Health monitoring types
- Safety configuration types

**Proposed Module Structure:**
```
pkg/storage/types/
├── disk.go               # Disk-related types
├── partition.go          # Partition types
├── volume.go             # Volume types
├── lvm.go                # LVM-specific types
├── mount.go              # Mount operation types
├── health.go             # Health monitoring types
└── safety.go             # Safety configuration types
```

**Estimated Effort:** 4-6 hours  
**Note:** Type-only file, simpler to modularize  

---

#### 10. **pkg/kvm/inventory.go** (1,080 lines)
**Current Responsibilities:**
- KVM inventory management
- VM discovery
- Resource tracking
- State management
- Metadata collection
- Performance metrics

**Proposed Module Structure:**
```
pkg/kvm/inventory/
├── manager.go (<200 lines)
├── discovery.go          # VM discovery
├── resources.go          # Resource tracking
├── state.go              # State management
├── metadata.go           # Metadata collection
└── metrics.go            # Performance metrics
```

**Estimated Effort:** 6-8 hours  

---

#### 11. **pkg/inspect/output.go** (1,070 lines)
**Current Responsibilities:**
- Output formatting (JSON, YAML, table)
- Data serialization
- Pretty printing
- Color formatting
- Template rendering

**Proposed Module Structure:**
```
pkg/inspect/output/
├── formatter.go (<200 lines)
├── json.go               # JSON formatting
├── yaml.go               # YAML formatting
├── table.go              # Table formatting
├── color.go              # Color formatting
└── template.go           # Template rendering
```

**Estimated Effort:** 4-6 hours  

---

#### 12. **pkg/pipeline/system_prompts.go** (1,046 lines)
**Current Responsibilities:**
- AI system prompts
- Template management
- Prompt generation
- Context building

**Proposed Module Structure:**
```
pkg/pipeline/prompts/
├── manager.go (<200 lines)
├── templates.go          # Prompt templates
├── generator.go          # Prompt generation
└── context.go            # Context building
```

**Estimated Effort:** 4-6 hours  

---

#### 13. **pkg/hecate/hybrid/diagnostics.go** (1,021 lines)
**Current Responsibilities:**
- Hecate diagnostics
- Frontend/backend health checks
- Connectivity testing
- Configuration validation
- Certificate verification

**Proposed Module Structure:**
```
pkg/hecate/hybrid/diagnostics/
├── manager.go (<200 lines)
├── frontend.go           # Frontend checks
├── backend.go            # Backend checks
├── connectivity.go       # Connectivity tests
├── configuration.go      # Config validation
└── certificates.go       # Certificate checks
```

**Estimated Effort:** 6-8 hours  

---

#### 14. **pkg/terraform/consul_templates.go** (979 lines)
**Current Responsibilities:**
- Terraform template generation for Consul
- Resource definitions
- Variable management
- Output definitions

**Proposed Module Structure:**
```
pkg/terraform/consul/
├── templates.go (<200 lines)
├── resources.go          # Resource definitions
├── variables.go          # Variable management
└── outputs.go            # Output definitions
```

**Estimated Effort:** 4-6 hours  

---

#### 15. **pkg/watchdog/resource_watchdog.go** (974 lines)
**Current Responsibilities:**
- Resource monitoring
- Threshold management
- Alert generation
- Metric collection
- Action execution

**Proposed Module Structure:**
```
pkg/watchdog/resource/
├── watchdog.go (<200 lines)
├── monitoring.go         # Resource monitoring
├── thresholds.go         # Threshold management
├── alerts.go             # Alert generation
├── metrics.go            # Metric collection
└── actions.go            # Action execution
```

**Estimated Effort:** 6-8 hours  

---

### Priority 2 (P2) - High Priority (500-1000 lines)

#### 16. **pkg/terraform/executor.go** (966 lines)
- Terraform execution
- State management
- Plan/apply operations
- Output parsing

#### 17. **pkg/bootstrap/orchestrator.go** (934 lines)
- Bootstrap orchestration
- Node initialization
- Cluster formation
- Service deployment

#### 18. **pkg/bootstrap/common.go** (929 lines)
- Common bootstrap utilities
- Validation helpers
- Configuration helpers

#### 19. **pkg/nomad/removal.go** (904 lines)
- Nomad job removal
- Cleanup operations
- State management

#### 20. **pkg/bootstrap/state_detection.go** (894 lines)
- State detection
- Cluster state analysis
- Node role detection

#### 21-35. Additional P2 files (500-900 lines each)
- Various pkg/ and cmd/ files requiring modularization

---

### Priority 3 (P3) - Medium Priority (300-500 lines)

#### 36-50. Files in 300-500 line range
- Multiple files across pkg/ and cmd/ directories
- Each with 2-3 distinct responsibilities
- Lower priority but should be addressed

---

## Phase 2: Modularization Strategy

### Principles

1. **Single Responsibility Principle (SRP)**
   - Each module does ONE thing well
   - Clear, focused purpose
   - Target: <300 lines per module (ideally <200)

2. **Dependency Injection**
   - Pass dependencies explicitly
   - No hidden global state
   - Mockable for testing

3. **Clear Boundaries**
   - No circular dependencies
   - Well-defined interfaces
   - Minimal coupling

4. **Security Preservation**
   - ALL security fixes preserved
   - Error handling maintained
   - Validation logic intact

5. **Documentation**
   - JSDoc/GoDoc for all exports
   - Clear usage examples
   - Migration notes

### Extraction Process (Per File)

1. **Analyze** (30 minutes)
   - Read entire file
   - List all responsibilities
   - Map dependencies
   - Identify security-critical sections

2. **Design** (45 minutes)
   - Create module structure
   - Define interfaces
   - Plan dependency injection
   - Design rollback strategy

3. **Extract** (2-4 hours)
   - Create new module files
   - Move code with dependencies
   - Update imports
   - Add documentation

4. **Verify** (30 minutes)
   - Run tests
   - Check compilation
   - Verify functionality
   - Security audit

5. **Document** (15 minutes)
   - Update this plan
   - Add migration notes
   - Update architecture docs

---

## Phase 3: Execution Plan

### Week 1: P1 Files 1-5
- Day 1-2: pkg/consul/install.go
- Day 3: cmd/debug/metis.go
- Day 4: cmd/debug/delphi.go
- Day 5: pkg/authentik/import.go + pkg/vault/install.go

### Week 2: P1 Files 6-10
- Day 1: pkg/system/orchestration.go
- Day 2: cmd/create/metis.go
- Day 3: pkg/database_management/backup.go
- Day 4: pkg/storage/types.go
- Day 5: pkg/kvm/inventory.go

### Week 3: P1 Files 11-15
- Day 1: pkg/inspect/output.go
- Day 2: pkg/pipeline/system_prompts.go
- Day 3: pkg/hecate/hybrid/diagnostics.go
- Day 4: pkg/terraform/consul_templates.go
- Day 5: pkg/watchdog/resource_watchdog.go

### Week 4: P2 Files (Top 10)
- 2 files per day

### Week 5: P2 Files (Remaining)
- 2 files per day

### Week 6: P3 Files + Cleanup
- 3 files per day
- Final verification
- Documentation updates

---

## Success Metrics

### Code Quality
-  Every file <300 lines OR single responsibility
-  Zero circular dependencies
-  100% test coverage maintained
-  All security fixes preserved

### Architecture
-  50+ focused modules created
-  Clear dependency graph
-  Proper separation of concerns
-  Testable design

### Functionality
-  100% feature parity
-  Zero regressions
-  All tests passing
-  Production ready

---

## Risk Mitigation

### Risks
1. **Breaking Changes** - Careful interface design and testing
2. **Lost Functionality** - Comprehensive test coverage before/after
3. **Security Regressions** - Security audit after each extraction
4. **Performance Impact** - Benchmark critical paths
5. **Merge Conflicts** - Coordinate with team, work in feature branches

### Mitigation Strategies
1. Feature branches for each file
2. Comprehensive testing before merge
3. Security review checklist
4. Performance benchmarking
5. Rollback plan for each change

---

## Dependencies Map

### Critical Dependencies
- pkg/eos_io - Runtime context (used by 80% of files)
- pkg/eos_err - Error handling (used by 90% of files)
- pkg/shared - Shared utilities (used by 60% of files)

### Module Dependencies (After Modularization)
```
pkg/consul/install.go
├── pkg/consul/installer/
├── pkg/consul/validation/
├── pkg/consul/config/
├── pkg/consul/service/
├── pkg/consul/rollback/
└── pkg/consul/helpers/

cmd/debug/metis.go
├── cmd/debug/metis/checks/
├── cmd/debug/metis/testing/
└── cmd/debug/metis/reporting/

[Similar structure for other P1 files]
```

---

## Next Steps

1.  **Analysis Complete** - This document
2. ⏳ **Start P1 File #1** - pkg/consul/install.go
3. ⏳ **Extract systematically** - Follow extraction process
4. ⏳ **Report progress** - Update this document after each file
5. ⏳ **Continue to P2** - After P1 complete

---

## Progress Tracking

### Completed Files
-  **pkg/consul/install.go** (1,713 lines → 13 modules created - 100% COMPLETE)

### In Progress
- None (ready for next P1 file)
  -  pkg/consul/installer/version.go (110 lines) - Version management
  -  pkg/consul/installer/binary.go (160 lines) - Binary installation
  -  pkg/consul/installer/repository.go (140 lines) - APT repository installation
  -  pkg/consul/validation/prerequisites.go (90 lines) - Prerequisites validation
  -  pkg/consul/validation/resources.go (130 lines) - Memory/disk validation
  -  pkg/consul/validation/ports.go (150 lines) - Port availability checking
  -  pkg/consul/validation/security.go (90 lines) - SELinux/AppArmor checking
  -  pkg/consul/service/lifecycle.go (150 lines) - Service lifecycle
  -  pkg/consul/service/systemd.go (195 lines) - Systemd management
  -  pkg/consul/config/setup.go (280 lines) - Configuration setup
  -  pkg/consul/rollback/manager.go (240 lines) - Rollback management
  -  pkg/consul/helpers/network.go (230 lines) - Network utilities
  - ⏳ Main orchestrator refactor (pending - final step)

### Blocked
- None

---

## Appendix A: File Size Distribution

```
>1500 lines: 3 files
1000-1500 lines: 12 files
500-1000 lines: 20 files
300-500 lines: 15+ files
<300 lines: Majority (already modular)
```

---

## Appendix B: Estimated Total Effort

- **P1 Files (15):** 90-120 hours (2-3 weeks)
- **P2 Files (20):** 80-100 hours (2 weeks)
- **P3 Files (15):** 45-60 hours (1 week)
- **Total:** 215-280 hours (5-6 weeks)

---

**Ready to begin systematic modularization. Awaiting approval to start with pkg/consul/install.go.**
