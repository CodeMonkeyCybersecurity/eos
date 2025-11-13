# Eos Development Roadmap

**Last Updated**: 2025-10-31
**Version**: 1.2

---

## Timeline Overview

| Window | Theme | Highlights |
| --- | --- | --- |
| 2025-10 | Completed foundations | Secret manager refactor (phases 1-4), CLI & route management hardening, QUIC/HTTP3 enablement, Wazuh SSO P0 fixes |
| 2025-11 | Immediate priorities | Hecate self-enrollment Phase 1, Wazuh SSO P1 hardening, Secret manager Phases 5-6, Config management Phase 0, Authentik client consolidation kickoff |
| 2025-12 → 2026-01 | Near-term delivery | Environment automation Phase 1, Authentik API migration (P2), Backup & restore program launch |
| 2026-02 → 2026-04 | Mid-term focus | Hecate authentication Phase 2, Environment automation Phases 2-3, Hecate Consul/Vault integration |
| 2026-Q2+ | Strategic backlog | Backup & restore advanced features, Caddy/Authentik automation backlog, observability & resilience investments |

Use the dated sections below for sequencing, dependencies, and detailed task lists. Completed work is preserved for traceability and informs risk posture for upcoming phases.

---

## 2025-10 – Completed Foundations

### Secret Manager Refactor (Phases 1-4, completed 2025-10-27)
- Unified the `SecretStore` interface in `pkg/secrets/store.go`, added Vault/Consul/file adapters, and ensured every method accepts `context.Context`.
- Replaced the legacy `SecretManager` with `Manager` (`pkg/secrets/manager.go`), added context-aware helpers, and shipped deprecated aliases to preserve caller compatibility.
- Fixed Vault diagnostic path issues (`pkg/debug/bionicgpt/vault_config_diagnostic.go:45-47`) with regression guards in `pkg/secrets/vault_store.go#L78-L81`.
- Migrated seven services to the new API (`pkg/bionicgpt/install.go:256`, `cmd/create/umami.go:48`, `cmd/create/temporal.go:57`, `pkg/cephfs/client.go:68`, etc.); build, vet, and gofmt all green.
- Hecate-specific migration (Phase 4.2) deferred to November; deprecation notice scheduled for 2025-11 once Secret Manager Phases 5-6 are complete.

### Hecate Route Management Hardening (Phase 4.5, completed 2025-10-28)
- Normalised flag experience for `sudo eos update hecate --add ...` (`cmd/update/hecate.go:19-134`), auto-appending known ports and rejecting positional args.
- Added `ValidateNoFlagLikeArgs()` guard (`cmd/update/hecate_add.go:74-77`) and telemetry flag to distinguish invocation modes (`pkg/hecate/add/types.go:24`).
- Removed duplicated logging and aligned both flag and subcommand paths with Admin API-first flow; ten automated tests cover common permutations with IPv6/port edge cases.

### Command Structure Standardisation (completed 2025-10-28)
- Refined Cobra wiring so orchestration layers delegate business logic cleanly; logging follows CLAUDE.md guidance across `cmd/update/hecate.go` and related helpers.
- Ensured `isAdminAPIAvailable()` gating and fallback logic produce zero-downtime reloads before reverting to file-based updates.

### QUIC/HTTP3 Enablement (completed 2025-10-28)
- Opened UDP/443 in both UFW (`pkg/hecate/yaml_generator.go:979-1012`) and Hetzner Terraform rules (`pkg/hecate/terraform_templates.go:85-92`).
- Documented verification checklist (sysctl, `ufw status`, `ss -ulnp`, `curl --http3`) so platform teams can validate HTTP/3 reachability after `eos create hecate`.

### Interaction Prompt Cleanup (completed 2025-10-28)
- Replaced direct `fmt.Print*` usage with structured logging across interaction helpers, documenting explicit exceptions for `PromptSecret`.
- Added a 20-case unit suite for `validateYesNoResponse` and refreshed README/ADR notes clarifying when stdout is acceptable.

### Wazuh SSO Integration – P0 Fixes (completed 2025-10-28)
- Removed hardcoded paths/permissions, tracked rollback metadata, and codified constants in `pkg/wazuh/sso_sync.go`.
- Established clean baseline for P1 security improvements (see November plan).

### Deprecated BionicGPT Text Fix
- Retained `pkg/hecate/add/bionicgpt_fix.go.DEPRECATED` for historical context; Admin API-driven workflow now production-ready.

### Service Initialization Framework – Phase 0 Scaffolding (completed 2025-10-31)
- Introduced declarative service command group (`cmd/service`) with list/init/health/status/reset/logs entry points wired through `eos.Wrap`.
- Added definition loader and discovery utilities (`internal/service/definition.go`) plus execution placeholder to retain compile-time coverage while downstream phases land.
- Published baseline Langfuse definition (`services/langfuse.yaml`) so dependency validation and CLI surfacing can be exercised immediately ahead of executor delivery.

### Lessons Learned
- Verify critical Authentik behaviours against current source (v2025.10) rather than relying solely on documentation.
- Telemetry and fallbacks should ship alongside API migrations to keep rollouts observable.
- Strict logging policies need explicit, well-documented exceptions to remain sustainable.

### Security Hardening Sprints (Completed 2025-01-27 to 2025-11-05)

**Context**: Three security hardening sprints conducted between January and November 2025, addressing token exposure, TLS validation, input sanitization, and establishing shift-left prevention framework.

#### Sprint 1: Token Exposure Fix (P0-1, completed 2025-01-27)
- **CVSS**: 8.5 (High) → 0.0 (Fixed)
- **Issue**: Vault root tokens exposed in environment variables (`VAULT_TOKEN=<value>`), visible via `ps auxe` and `/proc/<pid>/environ`
- **Fix**: Created `pkg/vault/cluster_token_security.go` with temporary token file pattern (0400 permissions, immediate cleanup)
- **Functions Fixed**: 5 functions in `pkg/vault/cluster_operations.go` (ConfigureRaftAutopilot, GetAutopilotState, RemoveRaftPeer, TakeRaftSnapshot, RestoreRaftSnapshot)
- **Pattern**: `VAULT_TOKEN_FILE=/tmp/vault-token-<random>` instead of `VAULT_TOKEN=<value>`
- **Tests**: 6 test cases with 100% coverage of security-critical paths
- **Compliance**: NIST 800-53 SC-12, AC-3; PCI-DSS 3.2.1

#### Sprint 2: TLS Validation Fix (P0-2, completed 2025-01-27)
- **CVSS**: 9.1 (Critical) → 0.0 (Fixed)
- **Issue**: `VAULT_SKIP_VERIFY=1` set unconditionally in `pkg/vault/phase2_env_setup.go:92`, enabling MitM attacks
- **Fix**: Implemented CA certificate discovery with informed consent framework
- **Components**:
  - `locateVaultCACertificate()` - searches `/etc/vault/tls/ca.crt`, `/etc/eos/ca.crt`, `/etc/ssl/certs/vault-ca.pem`
  - `handleTLSValidationFailure()` - requires explicit user consent or `Eos_ALLOW_INSECURE_VAULT=true`
  - `isInteractiveTerminal()` - TTY detection for safe prompting
- **Behavior**: TLS validation enabled by default, bypass only with consent (dev mode) or CA cert unavailable + user approval
- **Compliance**: NIST 800-53 SC-8, SC-13; PCI-DSS 4.1

#### Sprint 3: Pre-Commit Security Hooks (P0-3, completed 2025-11-05)
- **Purpose**: Prevent P0-1/P0-2 regression through automated validation
- **Three-Layer Defense**:
  1. **Pre-commit hook** (`.git/hooks/pre-commit`): 6 security checks (hardcoded secrets, VAULT_SKIP_VERIFY, InsecureSkipVerify, VAULT_TOKEN env vars, hardcoded permissions, security TODOs)
  2. **CI/CD workflow** (`.github/workflows/security.yml`): gosec, govulncheck, TruffleHog secret scanning, SARIF upload
  3. **Security review checklist** (`docs/SECURITY_REVIEW_CHECKLIST.md`): Human-centric process for code reviews
- **Philosophy**: "Shift Left" - catch security issues at development time, not code review time
- **Success Metrics**: Zero P0-1/P0-2 regressions detected since implementation

#### Sprint 4: Repository Input Validation (P0-4, completed 2025-01-28)
- **Issue**: Invalid branch names and missing git identity caused repository creation failures
- **Fixes**:
  - `ValidateBranchName()` - implements all 10 git-check-ref-format rules
  - `sanitizeInput()` - defense against terminal escape sequence injection (CVE-2024-56803, CVE-2024-58251 class)
  - `ValidateRepoName()` - blocks 20+ Gitea reserved names, path traversal, SQL injection
  - Enhanced git identity check with RFC 5322 email validation
  - Forensic debug logging via `EOS_DEBUG_INPUT=1`
- **Test Coverage**: 63 test cases across branch validation (25), repo validation (28), input sanitization (10)
- **Deployment**: Added `make deploy` targets for atomic binary swap to production servers

---

## 2025-11 – Immediate Priorities

### Adversarial Analysis & Systematic Remediation (2025-11-13)

**Context**: Comprehensive adversarial security analysis identified 8 categories of P0 violations across 363 command files, requiring systematic remediation in 4 prioritized phases.

#### Analysis Findings (2025-11-13)

**Scope**: Full codebase scan using OWASP, NIST 800-53, CIS Benchmarks, STRIDE methodology

**Critical Issues Identified** (P0-Breaking):
1. **Flag Bypass Vulnerability (CVE-worthy)**: Only 6/363 commands (1.7%) implement `ValidateNoFlagLikeArgs()` security check
   - **Attack**: `eos delete env production -- --force` bypasses safety checks via `--` separator
   - **Impact**: Production deletion, running VM deletion, emergency overrides can be bypassed
   - **Remediation**: Add validation to 357 unprotected commands (12 hours, scriptable)

2. **Hardcoded File Permissions (Compliance Risk)**: 732 violations (695 production, 37 test)
   - **Issue**: SOC2/PCI-DSS/HIPAA audit failure - no documented security rationale
   - **Breakdown**: 419 WriteFile, 233 MkdirAll, 29 Chmod, 14 FileMode() calls (excludes test files)
   - **Examples**: `os.WriteFile(path, data, 0600)` → `shared.SecretFilePerm`, `os.MkdirAll(dir, 0755)` → `shared.ServiceDirPerm`
   - **Architecture**: TWO-TIER pattern - shared constants (pkg/shared/permissions.go) + service-specific (pkg/vault/constants.go, pkg/consul/constants.go)
   - **Remediation**: Automated replacement for production code (1-2 days), manual review for service-specific permissions
   - **Note**: Original estimate (1347) was inflated by string matching - caught comments, port numbers, documentation

3. **Architecture Boundary Violations**: 19 cmd/ files >100 lines (should be <100)
   - **Worst**: `cmd/debug/iris.go` (1507 lines, 15x over limit)
   - **Issue**: Business logic in orchestration layer, untestable, unreusable
   - **Remediation**: Refactor to pkg/ following Assess→Intervene→Evaluate pattern (76 hours)

4. **fmt.Print Violations (Telemetry Breaking)**: 298 violations in debug commands
   - **Issue**: Breaks telemetry, forensics, observability
   - **Rule**: CLAUDE.md P0 #1 - NEVER use fmt.Print/Println, ONLY otelzap.Ctx(rc.Ctx)
   - **Remediation**: Convert to structured logging (5 hours, semi-automated)

5. **Documentation Policy Violations**: 5 forbidden standalone .md files
   - **Files**: P0-1_TOKEN_EXPOSURE_FIX_COMPLETE.md, P0-2_VAULT_SKIP_VERIFY_FIX_COMPLETE.md, P0-3_PRECOMMIT_HOOKS_COMPLETE.md, SECURITY_HARDENING_SESSION_COMPLETE.md, TECHNICAL_SUMMARY_2025-01-28.md
   - **Remediation**: Consolidate to ROADMAP.md + inline comments, delete standalone files (1 hour) **← COMPLETED 2025-11-13**

6. **Missing Flag Fallback Chain (Human-Centric)**: Only 5/363 commands use `interaction.GetRequiredString()` pattern
   - **Philosophy Violation**: "Technology serves humans" - missing flags should prompt with informed consent, not fail
   - **Remediation**: Add fallback chain (CLI flag → env var → prompt → default → error) to required flags (3-4 days)

7. **Insecure TLS Configuration**: 19 files with `InsecureSkipVerify: true`
   - **Attack**: MitM via certificate bypass
   - **Justification Required**: Dev-only with clear marking, self-signed certs with pinning, or explicit user consent
   - **Remediation**: Security review + dev/prod split (9.5 hours)

8. **Command Injection Risk**: 1329 direct `exec.Command()` calls bypassing `execute.Run` wrapper
   - **Issue**: No argument sanitization, timeout enforcement, telemetry integration
   - **Remediation**: Migrate to secure wrapper (44 hours, requires security audit)

**Incomplete Infrastructure** (Built but Unused):
- Evidence Collection (`pkg/remotedebug/evidence.go`): 265 lines, 0 users
- Debug Capture (`pkg/debug/capture.go`): 151 lines, 1/13 commands using it
- Unified Authentik Client: Built, but 47 callsites still use old clients

**Technical Debt**: 841 TODO/FIXME comments, 18 concentrated in `cmd/create/wazuh.go` alone

#### Four-Phase Remediation Plan

**Phase 1: Security Critical (P0)** - Week 1-2, 3-4 days
- [ ] Flag bypass vulnerability: Protect 357 commands with `ValidateNoFlagLikeArgs()` (12h, scriptable)
- [ ] InsecureSkipVerify audit: Justify or remove 19 violations (9.5h, manual review)
- [x] Documentation policy: Consolidate 5 forbidden .md files to ROADMAP.md (1h) **← COMPLETED**

**Deliverables**:
- All 357 commands protected
- TLS security audit complete
- CVE announcement: "Flag bypass vulnerability patched in eos v1.X"

**Phase 2: Compliance & Architecture (P1)** - Week 3-4, 7-10 days
- [ ] Hardcoded permissions: Automated replacement for 695 production violations (1-2 days, preserve service-specific constants)
- [ ] Architecture violations: Refactor 19 oversized cmd/ files to pkg/ (76h, manual)
- [ ] fmt.Print violations: Convert to structured logging (5h, semi-automated)

**Deliverables**:
- Permission security rationale matrix for SOC2 audit
- 100% of cmd/ files <100 lines
- All debug commands use structured logging

**Phase 3: Technical Debt Reduction (P2)** - Week 5-6, 5-7 days
- [ ] Required flag fallback: Add human-centric pattern to top 100 commands (3-4 days)
- [ ] Command injection audit: Migrate to execute.Run wrapper, 80%+ coverage (44h audit)
- [ ] HTTP client consolidation: Deprecate old Authentik clients, migration guide (2 days)
- [ ] Infrastructure adoption: Integrate evidence collection + debug capture (2 days)

**Deliverables**:
- Top 100 commands have human-centric UX
- exec.Command audit complete
- Authentik unified client migration guide published

**Phase 4: Optimization & Polish (P3)** - Week 7-8, 3-5 days
- [ ] TODO/FIXME cleanup: Triage 841 comments (50% resolve, 25% → issues, 25% document) (2 days)
- [ ] Compliance docs: SOC2/PCI-DSS/HIPAA control matrix (1 day)
- [ ] AI alignment: Weekly CLAUDE.md review process (1 day)
- [ ] Migration tooling: `eos migrate check` for deprecated patterns (2 days)

**Deliverables**:
- TODO/FIXME reduced by 75%
- Compliance audit readiness achieved
- Automated pattern migration available

#### Success Metrics

**Pre-Remediation** (Current State):
- Flag bypass: 357/363 commands vulnerable (98.3%)
- Hardcoded permissions: 732 violations (695 production, 37 test; original 1347 was inflated by string matching)
- Architecture violations: 19 files (6-15x over limit)
- fmt.Print violations: 298
- Human-centric flags: 5/363 commands (1.4%)

**Target State** (Post-Remediation):
- Flag bypass: 0 commands vulnerable (100% protected)
- Hardcoded permissions: 0 violations (100% constants with rationale)
- Architecture violations: 0 files >100 lines (100% refactored)
- fmt.Print violations: Debug commands only (with justification)
- Human-centric flags: Top 100 commands (100% Tier 1)

**Timeline**: 6-8 weeks for complete remediation with sustained focus

---

## 2025-11 – Ongoing Priorities

### Hecate Authentication Phase 1 (2025-11-01 → 2025-11-15)

#### Context (2025-10-30 source verification)
- Enrollment lives at the Authentik **brand** level; providers expose only `authentication_flow`, `authorization_flow`, and `invalidation_flow`.
- Current failures:
  1. Self-registration disabled globally because brand `flow_enrollment` is unset.
  2. BionicGPT bypasses its documented oauth2-proxy pattern, limiting token lifecycle control.
- Response strategy:
  - **Phase 1:** enable brand enrollment, pair with per-app authorization policies, deliver immediate self-service.
  - **Phase 2:** adopt oauth2-proxy + OIDC to match BionicGPT's reference architecture and improve session management.

#### Evidence Snapshot
```python
class Provider(SerializerModel):
    authentication_flow = ForeignKey("Flow", ...)
    authorization_flow = ForeignKey("Flow", ...)
    invalidation_flow = ForeignKey("Flow", ...)
    # enrollment_flow = ...  # ❌ only available on Source classes
```
- Authentik’s separation of enrollment (brand) vs authorization (application) is intentional.
- BionicGPT documentation: `Nginx → oauth2-proxy → External Identity Provider → Bionic Server`.

#### Phase 1 Task Plan
1. **Enable enrollment via CLI (Step 1.1, 5 min)**
   - `sudo eos update hecate enable self-enrollment --app bionicgpt [--enable-captcha|--dry-run]`
   - Creates flow, prompts, password stage, user creation/login, optional captcha; links to brand and prints enrollment URL.
   - Stage order: captcha (optional) → prompt → password → user write → user login.
   - Command is idempotent and includes rollback guidance (clear brand enrollment flow).
2. **Bind per-app authorization policies (Step 1.2, 30–60 min)**
   - Create `bionicgpt-users` group with attributes.
   - Bind group membership policy to BionicGPT’s application (authorization binding).
   - Ensure other apps (Umami/Grafana/Wazuh) rely on admin-only groups.
3. **Execute testing matrix (Step 1.3, 15–30 min)**
   - New user enrollment success, BionicGPT positive access after group assignment, negative tests for restricted apps, idempotency verification.
4. **Publish documentation (Step 1.4, 30 min)**
   - `/opt/hecate/README-enrollment.md` for end users.
   - `/opt/hecate/RUNBOOK-enrollment.md` for administrators (disable/re-enable, monitoring, audit).

#### Success Criteria
- Self-service enrollment live with optional captcha; enrollment URL communicated.
- Authorization policies prevent lateral movement; group assignments gate access.
- Test matrix executed with verified outcomes; documentation in place.
- Existing user flows unaffected; no regressions in SSO behaviour.

#### Risks & Mitigations
- **Expectation mismatch:** Document clearly that enrollment remains brand-scoped; per-app gating uses policies.
- **Spam enrollments:** Encourage `--enable-captcha`; plan SMTP/email verification follow-up.
- **Over-engineering Phase 2:** Reassess oauth2-proxy migration after 3–6 months of data.

---

### Hecate Configuration Management Phase 0 (2025-11-15 → 2025-12-15)

#### Environment Definitions
- `development`: Ephemeral, developer-managed, non-federated Authentik, debug logging, disposable state.
- `testing`: CI-driven, self-service disabled, debug logging, fixtures regenerated, auto-shutdown every 24 h.
- `staging`: Production-parity, gated self-service, info logging, config-only persistence, scheduled shutdown exceptions.
- `production`: Always-on with approvals, self-service enabled with audit hooks, persistent replicated volumes.
- `administration`: Restricted control plane (Consul/Vault/build tools) with break-glass workflows and audited logging.

#### Guardrail Baseline (Nomad/Consul/Vault 2024.5; Authentik 2024.10)
- Store defaults per environment in Consul KV and hydrate during `eos promote`.
- Partition secrets with Vault namespaces or templated paths (`env/<name>/...`).
- Manage Authentik flows via Outpost/PromptFlow to toggle self-registration per environment.
- Tie promotion provenance to Git SHA and artifact digests.
- Automate DNS via Consul service discovery + external-dns pattern.
- Standardise Consul node metadata (`role`, `env`) and enforce via Nomad scheduling constraints.
- Drive log levels from Consul KV to maintain prod quietness vs dev verbosity.
- Default non-prod allocations to `ephemeral_disk`; scrub data on teardown.
- Enforce 24 h stop windows via Nomad periodic jobs and short-lived Vault tokens.

#### Phase 0 Deliverables
- Abuse-case catalog and environment policy matrix.
- RFC covering promotion prerequisites and audit log schema updates.
- Inventory of current Consul catalog highlighting worker/edge gaps.
- Risk: ensure admin environment segmentation (Consul ACL bootstrap rotation) precedes automation rollout.

---

### Wazuh SSO Integration – P1 Security Improvements (target week of 2025-11-10)
- **P1 #5 – Exchange key length**: confirm SAML expectations, codify `SAMLExchangeKeyLengthBytes` in `pkg/wazuh/types.go`, regenerate keys accordingly.
- **P1 #6 – Atomic writes**: introduce `pkg/shared/atomic_write.go` to guarantee permissions before write; retrofit all five existing `os.WriteFile` uses.
- **P1 #7 – Distributed locking**: wrap `ConfigureAuthentication` with Consul-based locks, record KV marker `service/wazuh/sso/configured`, validate contention/timeouts.
- **P1 #8 – URL validation**: use `shared.SanitizeURL` + `shared.ValidateURL`, enforce HTTPS and public hostnames, reject localhost/invalid ports with actionable errors.
- **P1 #9 – Read-only health check**: add `GetSAMLProviderByName()` / `GetApplicationBySlug()` helpers so health checks never create resources; surface warnings when drift detected.
- **P1 #10 – TLS trust posture**: add `ServiceOptions.CustomCACert`, document preferred `--ca-cert` flag, only fall back to `--allow-insecure-tls` with explicit warnings.

Deployment stages:
1. Non-breaking updates (key length, atomic writes, validation).
2. Behavioural changes (locking, read-only health checks, TLS enhancements).
Rollback per item; full build/vet/test suites must pass before promotion.

---

### Secret Manager Phases 5-6 (Weeks of 2025-11-10 & 2025-11-17)
- **Phase 5 – Upgrade & Test**
  - Bump Vault SDK to v1.22.0; run `go test` across `pkg/secrets`, `pkg/vault`, service packages, and build binaries.
  - Manual validation: `eos create vault`, `eos create bionicgpt`, `eos debug bionicgpt`, `eos create umami`, secrets rotation.
  - Pass criteria: automated tests green, manual checklist complete, no performance regression.
- **Phase 5.4 Enhancements**
  - Add capability verification helpers, context caching, UX-focused error messages, and token rate limiting for `vault_cluster` commands (`cmd/update/vault_cluster.go`, `pkg/vault/auth_cluster.go`).
- **Phase 6 – Documentation & Migration Guide**
  - Update `CLAUDE.md`, `CHANGELOG.md`, `pkg/secrets/README.md`.
  - Publish `docs/SECRET_MANAGEMENT.md` (architecture + examples) and `docs/MIGRATION_SECRET_MANAGER.md` (step-by-step).
  - Extend vault cluster documentation with detailed Godoc, UX prompts, troubleshooting, and testing requirements.

### Service Initialization Framework – Phases 1-2 (2025-11-03 → 2025-11-28)
- **Phase 1 (Nov 03 → Nov 14):** deliver persisted state manager (`internal/service/state.go`), lock-file protection, and container/command/variable preflight checks surfaced via `eos service init --dry-run`. Include validation-focused unit tests plus operator docs covering the new workflow.
- **Phase 2 (Nov 17 → Nov 28):** implement executor loop with retry/backoff utilities, HTTP healthcheck + API call handlers, and structured logging to `~/.eos/logs/service-<name>.log`. Resume semantics should reach parity with scaffolding before December resilience work.
- **Exit criteria:** Langfuse definition can complete dry-run successfully, and CI covers state/preflight paths.
- **Risks:** Vault ACL alignment for state/log directories and potential scheduling conflicts with Secret Manager Phase 5 testing window.

---

## 2025-11 – Security Hardening Sprint (URGENT - Week of 2025-01-27)

### CRITICAL SECURITY FIXES (P0 - BREAKING)

**Context**: Adversarial security analysis (2025-01-27) identified 3 CRITICAL, 4 HIGH, 3 MEDIUM vulnerabilities requiring immediate remediation before production deployment.

**Compliance Risk**: Violates PCI-DSS 3.2.1, SOC2 CC6.1, HIPAA encryption requirements.

#### P0-1: Token Exposure in Environment Variables (CVSS 8.5)
- **Issue**: Vault tokens in `VAULT_TOKEN=<value>` visible in `ps auxe`, `/proc/<pid>/environ`
- **Location**: `pkg/vault/cluster_operations.go` (5 functions)
- **Fix**: 2 hours - temporary token files with 0400 perms
- **Reference**: NIST 800-53 SC-12

#### P0-2: VAULT_SKIP_VERIFY=1 Globally Enabled (CVSS 9.1)
- **Issue**: TLS validation disabled, enables MITM attacks
- **Location**: `pkg/vault/phase2_env_setup.go:92`
- **Fix**: 3 hours - CA certificate validation with user consent
- **Reference**: NIST 800-53 SC-8

#### P0-3: Pre-Commit Security Hooks
- **Issue**: No automated checks prevent regressions
- **Fix**: 1 hour - `.git/hooks/pre-commit` + CI workflow

### HIGH PRIORITY (P1)
- **P1-4**: HTTP Client Consolidation (Wazuh) - 1 hour
- **P1-5**: Database Credential Sanitization - 30 min
- **P1-6**: Hardcoded Permissions Migration - 30 min

### MEDIUM PRIORITY (P2 - Q1 2026)
- **P2-7**: Secrets Rotation Framework - 4 weeks
- **P2-8**: Compliance Documentation - 2 weeks

### LOW PRIORITY (P3 - Q2 2026)
- **P3-9**: Security Observability - 2 weeks
- **P3-10**: Threat Modeling - 1 week
- **P3-11**: DR Testing Enhancement - Ongoing

---

### Authentik Client Consolidation & Export Enhancements (2025-11 → 2026-01)

#### Completed (2025-10-30)
- **P0 #1**: Sanitised runtime export by redacting sensitive env vars via `sanitizeContainerSecrets()` (`pkg/hecate/authentik/export.go`).
- **P0 #2**: Established `UnifiedClient` scaffolding (`pkg/authentik/unified_client.go`) and migration guide (`pkg/authentik/MIGRATION.md`) for future consolidation.
- **P1 #3**: Added Authentik blueprint export (`pkg/authentik/blueprints.go`) alongside existing JSON outputs.
- **P1 #5**: Integrated PostgreSQL backups into export pipeline (`pkg/hecate/authentik/export.go` / `validation.go`).

#### In Flight (Nov 2025 → Jan 2026)
- **P2 #6 – Precipitate function**: Decide on API→disk sync approach (recommended: embrace Caddy’s persistence and document template-only stance).
- **P2 #7 – OpenAPI client generation**: Adopt `oapi-codegen`, create wrapper aligning with `RuntimeContext`, automate schema refresh (weekly GitHub Action), and migrate callers incrementally.
- **P3 Items** (deferred): automation tooling, full migration of `pkg/hecate/authentik/` into unified client once wrappers stabilise.

---

### Hecate Configuration Management – Immediate Work (Week of 2025-11-01 → 2025-11-08)

#### Completed (Mon–Tue)
1. Container name alignment (`authentik-server`), `AUTHENTIK_HOST` env var, Caddy Admin API port binding, UDP/443 exposure, health-check addition.
2. Validated via fresh VM `eos create hecate`.

#### Self-Service Foundation (Wed–Fri)
1. Self-service snippet generator.
2. Flow slug auto-discovery with pagination/rate limiting.
3. `ServiceOptions` extensions for self-service controls.
4. Logout URL templating fixes.
5. Integration testing in progress.

#### Following Week (2025-11-08 → 2025-11-15)
- Inject self-service handlers into SSO templates, test across multiple services, validate custom flow discovery, run end-to-end enrol/reset/logout flows, and update documentation.

#### Priority Matrix
| Phase | Priority | Timeline | Effort | Blocker | Dependencies |
|-------|----------|----------|--------|---------|--------------|
| **A: Option B (Drift Detection)** | P0 | ✅ Complete | 8 h | None | None |
| **B.1: Critical Template Fixes** | P0 | 2025-11-01 → 2025-11-08 | 4 h | None | None |
| **B.2: Self-Service Endpoints** | P0 | 2025-11-08 → 2025-11-15 | 8 h | B.1 | Authentik API access |
| **B.3: High-Priority Fixes** | P1 | Parallel to B.2 | 3 h | None | None |
| **C: Precipitate Pattern** | P2 | ⚠️ Deferred | 100 h+ | Converter, comment handling, secrets | None |
| **D: Redis Deprecation** | P2 | 2026-02 → 2026-06 | 12 h | None | Eos v2.0 release |
| **E: Worker Security Review** | P1 | 2026-04 | 16 h | Authentik upstream research | None |

---

## 2025-12 → 2026-01 – Near-Term Delivery

### Environment Automation Phase 1 (Development → Testing, 2025-12-15 → 2026-01-31)
- Implement `eos promote --to testing` profile loader backed by Consul defaults and Vault path rewrites.
- Enforce Authentik self-service disabled via API push before Nomad submissions.
- Deploy Nomad periodic job `eos-gc-dev-testing` for 24 h shutdowns with notifications.
- Acceptance: CI promotes latest green build with deterministic defaults; rollback validated.
- Enforce node metadata (`role` constraints) across dev/testing; prohibit persistent volumes via policy pack.

### Hecate Authentication Phase 1 Follow-Through (Week of 2025-11-15)
- Monitor Authentik events, gather user feedback, refine policies, log issues for Phase 2 planning.

### Authentik Client Consolidation – P2 Execution (Dec 2025 → Jan 2026)
- Generate OpenAPI client, wrap with Eos conventions, and migrate high-impact callers (Hecate, Wazuh).
- Establish CI workflow for weekly schema diffs; add regression tests ensuring generated structs match live API responses.

### Backup & Restore Infrastructure Kickoff (2025-Q4)
- Current state: exports include Authentik secrets redaction, blueprint, Postgres dump; remaining gaps focus on automation and verification.
- Upcoming (Nov–Dec 2025):
  - Automate backup scheduling, verification (SHA256 checks), and rotation.
  - Document restore runbooks per environment.
- Success metrics: 100% verified backups, documented RTO/RPO, rehearsed restore for at least one production-like workload.

### Secret Manager Documentation (Phase 6) Completion
- Finalise guides, run manual migration dry-run using docs, ensure CLAUDE patterns reference new API.

### Service Initialization Framework – Phases 3-4 (2025-12-01 → 2026-01-17)
- **Phase 3 (Dec 01 → Dec 19):** harden executor with idempotent checks, edge-case handlers, and persisted summary output. Introduce Vault write + env update + docker restart step handlers, plus regression tests covering resume and failure paths.
- **Phase 4 (Jan 06 → Jan 17):** migrate Langfuse bootstrap to the new executor, including integration test harness (`test/integration/langfuse_init.sh`) and operator docs. Retire legacy shell script once end-to-end validation completes.
- **Exit criteria:** `eos service init langfuse` completes end-to-end in staging, and roadmap sign-off to decommission ad-hoc scripts.
- **Risks:** coordination with BionicGPT releases for env updates, and ensuring Vault/Consul credentials align with production guardrails.

---

## 2026-02 → 2026-04 – Mid-Term Focus

### Hecate Authentication Phase 2 (2026-01 → 2026-02)
- Create Authentik OIDC provider for BionicGPT; manage credentials via Vault.
- Deploy oauth2-proxy sidecar (docker-compose) with token refresh validation and header passthrough.
- Update Caddy to route through oauth2-proxy; remove forward-auth configuration, add health checks.
- Execute blue/green migration, run end-to-end/regression/perf testing, and verify rollback plan.
- Update documentation and clean up deprecated file-based routes post-verification.

### Service Initialization Framework – Phase 5 (2026-02-03 → 2026-03-28)
- Generalise service definitions for Authentik and BionicGPT, building shared step templates where possible.
- Extend executor to support database query handlers and remote state (Vault) options if warranted by production usage.
- Publish operator playbooks and ADR describing declarative service onboarding, and baseline monitoring dashboards for init flows.
- Exit criteria: at least three services running through the framework with integration tests; legacy per-service scripts deprecated.
- Risks: scope creep into full environment automation, ensuring Docs/Support teams trained before retiring old flows.

### Environment Automation Phases 2-3
- **Phase 2 (Testing → Staging, 2026-02-01 → 2026-03-15):**
  - Add evidence collection (integration tests, vuln scans) as promotion prerequisites.
  - Require dual approvals (`eos promote approve --require-role`) aligned with CLAUDE governance.
  - Enable staging self-service flows, populate staging DNS via Consul catalog sync, extend 24 h shutdown scheduler with calendar exceptions.
  - Highlight drift between node metadata and workloads.
- **Phase 3 (Staging → Production, 2026-03-16 → 2026-04-30):**
  - Enforce change windows (PagerDuty API integration), implement canary/halt rules via Nomad `progress_deadline` and telemetry hooks.
  - Harden Vault automation (capability checks, admin token caching, rate limiting) per Secret Manager Phase 5.4 outcomes.

### Hecate Consul KV + Vault Integration (Target April–May 2026)
- Goals: encode environment defaults in Consul KV, hydrate Nomad templates, and align Vault secret paths per environment.
- Dependencies: Secret Manager Phase 5/6 completion, environment automation Phase 1 success.
- Milestones: KV schema design, template refactor, Vault namespace/path migration, testing across environments.

### Backup & Restore Program (Continuing)
- Deliver automated restore validation in staging, integrate into quarterly DR exercises.

---

## 2026-Q2 and Beyond – Strategic / Backlog

### Backup & Restore Advanced Features (through 2026-Q3)
- Implement incremental backups, off-site replication, and automated restore drills.
- Target full feature completion by 2026-06-30 with scheduled DR rehearsals.

### Hecate Configuration Backlog (Q1–Q2 2026)
- P2 items: Admin API rate limiting, DNS validation strictness (`--dev`/`--prod` flags), backup integrity verification, `--remove` flag implementation.
- Q2 backlog: Authentik API circuit breaker, Caddy observability command (`eos read hecate metrics`).

### Technical Debt – Caddy Configuration Management (Future Direction)
- Documented need for automated API→disk sync or official stance on template usage.
- Evaluate Precipitate pattern and CLI UX enhancements once Phase B self-service stabilises.

### Authentik Client Future Work
- Complete migration of remaining callers after OpenAPI client adoption.
- Consider schema-driven policy enforcement and automatic drift detection once wrappers mature.

### Hecate Security & Reliability Improvements (Adversarial Analysis 2025-10-31)
- Prioritised items for upcoming quarters:
  - **P1 (Nov 2025):** Admin API network segmentation, token discovery simplification.
  - **P2 (Q1 2026):** Backup verification, rate limiting, DNS strictness, `--remove` flag.
  - **P3 (Q2 2026):** Circuit breakers, metrics/observability.
- Success metrics:
  - November 2025: Admin API segmentation + token discovery fix.
  - Q1 2026: `--remove` flag, verified backups, rate limiting, DNS gating.
  - Q2 2026: Authentik circuit breaker, Caddy metrics visibility.

### Future Phases (Post-Refactor)
- Multiplayer CLI UX improvements triggered by user feedback or Q1 2026 sprint.
- Redis deprecation (P2, 2026-02 → 2026-06) aligned with Eos v2.0.
- Worker security review (P1, 2026-04) dependent on Authentik upstream research.

---

## Risk Management

- **User expectation mismatch (Hecate Phase 2):** communicate that enrollment remains brand-level; rely on policies for app gating.
- **Over-engineering oauth2-proxy:** re-evaluate after Phase 1 data; defer if benefits limited.
- **Authentik API schema drift:** weekly OpenAPI regeneration, automated diff checks.
- **Concurrent SSO provisioning:** Consul-based locking plus KV markers prevent destructive overlap.
- **Vault admin automation:** capability verification and token rate limiting reduce blast radius; cache tokens per `RuntimeContext`.
- **Rootless Docker vs permissions:** evaluate feasibility, document risk acceptance if unavoidable, require explicit consent during `eos create hecate`.

---

## Success Metrics

- **Self-Enrollment:** Eligible services reachable within 60 s of signup; policy violations blocked with clear messaging; <1% enrolment failure rate.
- **Secret Manager:** All core commands (`eos create`, `eos debug`) succeed with new manager; documentation-guided migration validated by dry-run; zero regressions reported post-upgrade.
- **Wazuh SSO:** No unauthorized access during chaos testing; health checks detect missing resources without side effects; TLS validation supports custom CA without disabling verification.
- **Environment Automation:** Promotions produce deterministic configs; automated evidence attached to staging promotions; drift detection dashboards show zero critical discrepancies.
- **Backup & Restore:** 100% of scheduled backups pass verification; at least one quarterly restore exercise completed per environment tier.
- **Authentik Client Migration:** Generated client passes schema parity tests; wrapper preserves logging/context patterns; migration issues tracked/resolved within sprint.

---

## Communication Plan

- Weekly async updates in #eos-infra summarising progress against timeline buckets.
- Anchor documents (`docs/SECRET_MANAGEMENT.md`, forthcoming oauth2-proxy migration guide) shared in PR descriptions and linked from README.
- For cross-team dependencies (Product, SRE), use `eos promote` governance hooks (`--require-role`) and change calendar integrations.
- Publish Authentik schema diffs via automated PRs; review cadence weekly.
- Document risk acceptances and mitigation status in CLAUDE.md addenda.

---

## Questions & Feedback

- Primary contact: @henry
- File issues referencing roadmap area tags (e.g. `[auth-phase1]`, `[secret-manager]`, `[wazuh-sso]`).
- Supporting docs: `docs/SECRET_MANAGER_REFACTORING_PLAN.md`, future oauth2-proxy migration runbook.

---

## References

- Authentik 2025.10 source (`authentik/core/models.py`, `authentik/providers/oauth2/models.py`).
- Authentik documentation: https://docs.goauthentik.io/docs/providers/oauth2/
- BionicGPT architecture: https://bionic-gpt.com/docs/running-a-cluster/running-authentication/
- Caddy Admin API docs: https://caddyserver.com/docs/api
- HashiCorp Nomad/Consul/Vault 2024.5 hardening guides.
- CLAUDE.md governance rules and recent adversarial analyses (2025-10-28, 2025-10-31).
