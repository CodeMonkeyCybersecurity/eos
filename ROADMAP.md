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

### Lessons Learned
- Verify critical Authentik behaviours against current source (v2025.10) rather than relying solely on documentation.
- Telemetry and fallbacks should ship alongside API migrations to keep rollouts observable.
- Strict logging policies need explicit, well-documented exceptions to remain sustainable.

---

## 2025-11 – Immediate Priorities

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

---

## 2026-02 → 2026-04 – Mid-Term Focus

### Hecate Authentication Phase 2 (2026-01 → 2026-02)
- Create Authentik OIDC provider for BionicGPT; manage credentials via Vault.
- Deploy oauth2-proxy sidecar (docker-compose) with token refresh validation and header passthrough.
- Update Caddy to route through oauth2-proxy; remove forward-auth configuration, add health checks.
- Execute blue/green migration, run end-to-end/regression/perf testing, and verify rollback plan.
- Update documentation and clean up deprecated file-based routes post-verification.

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
