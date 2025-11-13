# EOS Consul Implementation - HashiCorp Compliance Audit Report

Date: 2025-11-04
Auditor: Codex (GPT-5)
EOS Version: commit 3301471c
Audit Scope: Complete Consul implementation across pkg/consul, cmd/*/consul, pkg/sync/connectors/consul_vault.go, pkg/vault, and shared utilities

## Executive Summary
- Security posture is not production ready: gossip encryption and TLS are disabled by default and there is no automation to provision or rotate keys/certificates.
- ACL enablement defaults to deny, but generated policies remain overly permissive and upgrade workflows do not warn operators when flipping existing clusters from allow to deny.
- Vault storage integration relies on Consul without providing the mandatory ACL token, TLS transport, or cluster segregation HashiCorp requires.
- Operational guardrails (backups, upgrade safety, multi-datacenter ACL replication, automation for retry_join) are largely absent, leaving operators to assemble core production practices manually.
- Strengths include automated bootstrap token storage in Vault when available, node-identity based agent tokens, and a full Consul secrets engine integration for dynamic token issuance.

Overall, EOS aligns with roughly 11% of the HashiCorp checklist, is partially aligned with 29%, and misses or leaves unclear the remaining 60%. Immediate remediation is required before any production rollout.

## Compliance Dashboard

### By Priority
- P0 (Critical): 9 compliant, 14 partial, 24 non-compliant, 5 unclear
- P1 (High): 4 compliant, 18 partial, 30 non-compliant, 13 unclear
- P2 (Medium): 4 compliant, 17 partial, 15 non-compliant, 13 unclear
- P3 (Low): 1 compliant, 0 partial, 1 non-compliant, 2 unclear

### By Status
- ✅ Fully Compliant: 18 items
- ⚠️ Partially Compliant: 49 items
- ❌ Non-Compliant: 70 items
- ❓ Unclear / Needs Investigation: 33 items
- N/A Not Applicable: 0 items

## Critical Issues (P0)

### Issue #1: Production configs ship without required encryption
**Section**: 2.1 Gossip Encryption & 2.2 TLS Encryption
**Status**: ❌ NON-COMPLIANT
**HashiCorp Requirement**: *"Gossip is unencrypted by default and should be encrypted on both new and existing Consul clusters."* / *"Enable TLS with verification for all Consul agent communication."*
**Current Implementation**: Generated configuration comments out both `encrypt` and the entire `tls` stanza, leaving plaintext gossip and RPC (`pkg/consul/config/generator.go:193-205`). No code path invokes `consul keygen`, `consul tls ca create`, or cert issuance automation.
**Gap**: Operators receive no key material, no Vault-backed source of truth, and no rotation workflow; enabling encryption requires manual, undocumented edits.
**Risk**: Cluster traffic (membership, KV, ACLs) is exposed to interception and tampering; violates HashiCorp's "defense in depth" baseline.
**Recommendation**:
1. Generate gossip keys via `consul keygen` or `pkg/consul/secrets.GenerateGossipKey()` and store them in Vault, then render `encrypt = "<key>"` into configs.
2. Automate CA and node certificate issuance (HashiCorp `consul tls` tooling or Vault PKI) and ship configs with `verify_incoming`, `verify_outgoing`, `verify_server_hostname` enabled.
3. Provide rotation subcommands (`eos update consul --rotate-gossip`, `--rotate-tls`) with Vault-backed storage.

**Files Affected**:
- pkg/consul/config/generator.go:123-205
- pkg/consul/secrets/gossip.go:34-184 (logic exists but unused)
- pkg/sync/connectors/consul_vault.go:637-645 (only migrates existing keys)

### Issue #2: ACL policies violate least privilege
**Section**: 1.3 Least Privilege Policies & 16 Security Hardening
**Status**: ❌ NON-COMPLIANT
**HashiCorp Requirement**: *"Create specific policies for each role/service following principle of least privilege."*
**Current Implementation**: Default policies grant `service_prefix "" { policy = "write" }`, `node_prefix "" { policy = "read" }`, and `agent_prefix "" { policy = "read" }` (pkg/consul/acl/policies.go:123-240). Node agent tokens hardcode `Datacenter: "dc1"` (pkg/consul/acl/agent_token.go:122-125), breaking multi-datacenter segregation.
**Gap**: Services and operators receive broad authority across the entire catalog; no per-node/session scoping as required.
**Risk**: Single compromised token permits cluster-wide modification, undermining ACL protections.
**Recommendation**:
1. Generate node/service policies using exact-match stanzas (`node "<hostname>"`, `service "vault"`).
2. Parameterize datacenter in `CreateAgentToken` and block wildcard grants.
3. Update Vault role templates to reference narrowly scoped policies per service.

**Files Affected**:
- pkg/consul/acl/policies.go:123-240
- pkg/consul/acl/agent_token.go:122-145
- pkg/vault/consul_secrets_engine.go:246-282

### Issue #3: Vault→Consul storage integration omits mandatory security controls
**Section**: 5.1 Vault Using Consul Storage & 16 Security Hardening
**Status**: ❌ NON-COMPLIANT
**HashiCorp Requirement**: *"Vault storage \"consul\" requires TLS, dedicated ACL token, and isolated cluster."*
**Current Implementation**: `storage "consul"` block renders with `scheme = "http"` and no `token` (pkg/vault/config_builder.go:153-164). There is no automated provisioning of the policy/token pair, nor any check that Vault runs on a dedicated Consul cluster.
**Gap**: Vault would talk to Consul in plaintext without authentication, breaching both Vault and Consul guidance.
**Risk**: Secret leakage, privilege escalation, and circular dependency deadlocks.
**Recommendation**:
1. Generate a dedicated policy (`key_prefix "vault/"`, etc.) and token before writing the config; embed secure token reference (Vault agent template or file with 0600 perms).
2. Enforce TLS by default (`scheme = "https"`, CA/cert paths) and document certificate bootstrap.
3. Validate target Consul cluster is dedicated; refuse to proceed otherwise.

**Files Affected**:
- pkg/vault/config_builder.go:140-188
- pkg/consul/acl/policies.go:163-186
- pkg/consul/vault/integration.go:146-196

### Issue #4: Script-based handlers remain enabled by default
**Section**: 10.1 Script Checks Security & 16 Security Hardening
**Status**: ❌ NON-COMPLIANT
**HashiCorp Requirement**: *"enable_script_checks must be false otherwise ... script checks present a remote code execution threat."*
**Current Implementation**: Config generator leaves `enable_local_script_checks = true` and installs a watcher whose `handler_type = "script"` (pkg/consul/config/generator.go:179-214). There is no gating on ACL/TLS state.
**Gap**: HTTP API exposure plus script handlers re-introduce RCE even with ACLs enabled.
**Risk**: Authenticated or compromised agents can execute arbitrary code on Consul nodes.
**Recommendation**:
1. Default to `enable_script_checks = false` and remove script-based watchers.
2. Offer opt-in CLI flag that verifies ACL+TLS+token hardening before enabling local scripts.
3. Replace script watchers with HTTP/gRPC receivers or out-of-process handlers.

**Files Affected**:
- pkg/consul/config/generator.go:179-214

## High Priority Issues (P1)
1. **Public HTTP exposure without guardrails** – `client_addr = "0.0.0.0"` is hard-coded (pkg/consul/config/generator.go:123-132).
   - Risk: API open to LAN/WAN if firewall misconfigured.
   - Fix: Default to `127.0.0.1` unless operator explicitly opens the interface and ACL/TLS are confirmed.
2. **Agent tokens hard-wire datacenter `dc1`** – `CreateAgentToken` sets `Datacenter: "dc1"` (pkg/consul/acl/agent_token.go:122-125).
   - Risk: Multi-datacenter deployments fail or mis-scope permissions.
   - Fix: Parameterize datacenter from runtime discovery / CLI flags.
3. **No snapshot/restore automation** – no code invokes `consul snapshot save`/`restore`; docs absent.
   - Risk: Unable to recover from data corruption or operator error.
   - Fix: Add `eos backup consul` / `eos restore consul` commands with scheduling integration and encrypted storage.
4. **Upgrade and drift detection missing** – there is no version drift detection or warning when servers diverge (Section 18 items all ❌).
   - Risk: Operators can mix incompatible versions causing outages.
   - Fix: Implement `consul operator raft list-peers` + version checks and block upgrades on mismatch.
5. **Vault Consul token lifecycle incomplete** – management token is created but never stored in Vault or rotated (pkg/consul/acl/tokens.go:28-75).
   - Risk: Long-lived secret leaks degrade security posture.
   - Fix: Persist management token in Vault, add rotation job, delete bootstrap token after replacement.

## Medium Priority Issues (P2)
- SDK consumers connect via hostname rather than `127.0.0.1`, risking cross-host coupling (pkg/consul/config/config.go:27-42).
- Health check and monitoring documentation is minimal; no guidance on querying `/v1/status/*` endpoints.
- Cloud/Kubernetes/Nomad integrations are largely stubs (pkg/hecate/consul/federation.go TODO blocks, lack of Helm guidance).

## Strengths
- Default config enforces `acl.enabled = true` and `default_policy = "deny"` (pkg/consul/config/generator.go:186-189).
- `BootstrapConsulACLs` stores bootstrap tokens in Vault when available without logging secrets (pkg/consul/acl/bootstrap.go:132-166).
- Consul secrets engine integration is fully automated, enabling short-lived tokens (pkg/vault/consul_secrets_engine.go:56-208).
- Agent deployment pipeline validates bootstrap_expect parity and refuses 2/4 server counts (pkg/consul/agent/deploy.go:203-211).

## Architectural Observations
- Configuration generation is centralized but assumes single-node defaults, making production-hardening opt-in and manual.
- Security validation (`pkg/consul/security.go`) exists yet is not wired into CLI flows, missing an opportunity for automated gating.
- Several packages (e.g., `pkg/hecate/consul`) define advanced topologies but are not integrated with EOS CLI commands, suggesting incomplete migration.

## Deployment Scenario Analysis

### Single-Node (Dev)
- **Status**: ⚠️ Partial – Dev mode available via `AgentMode=dev` but docs do not clearly state non-production limitations.
- **Compliant**: UI enabled, ACLs default deny even in dev mode.
- **Non-Compliant**: TLS/Gossip still disabled; warning banners missing.

### Single-Node Production
- **Status**: ❌ Non-Compliant – No warnings or safeguards; operators could run unprotected single node in production.

### Three-Node Production Cluster
- **Status**: ⚠️ Partial – Config supports `bootstrap_expect=3`, but automation for provisioning three servers, key distribution, and retry_join is absent.

### Five-Node High Availability Cluster
- **Status**: ❓ Unclear – No documented workflow to provision 5 servers across AZs; limitations in validation logic.

### Vault Using Consul Storage (Scenario A)
- **Status**: ❌ Non-Compliant – Missing secure token, TLS, and dedicated cluster verification.

### Vault with Integrated Storage + Consul Discovery (Scenario B)
- **Status**: ⚠️ Partial – Raft is the default, but Consul registration/health guidance is incomplete.

### Multi-Datacenter Federation
- **Status**: ❌ Non-Compliant – Federation helpers exist but are not invoked; ACL replication and SAN handling absent.

## Detailed Findings by Section

### Section 1: ACL Security Configuration (P0)
- 1.1 Default policy deny ✅ – generator writes `default_policy = "deny"` (pkg/consul/config/generator.go:186-190).
- 1.1 Upgrade handling ❌ – `EnableACLsInConfig` rewrites ACL block without warnings or migration steps (pkg/consul/config/acl_enablement.go:135-205).
- 1.2 Bootstrap stored in Vault ⚠️ – Vault required; no encrypted file fallback (pkg/consul/acl/bootstrap.go:132-166).
- 1.3 Policies least privilege ❌ – Default policies rely on `*_prefix ""` wildcards (pkg/consul/acl/policies.go:123-240).

### Section 2: Encryption Configuration (P0)
- 2.1 Gossip encryption ❌ – `encrypt` commented out; no key generation pipeline (pkg/consul/config/generator.go:193-195).
- 2.2 TLS ❌ – TLS block commented; no CA automation.

### Section 3: Cluster Topology (P0)
- 3.1 Server count validation ⚠️ – only blocks 2 or 4 (pkg/consul/agent/deploy.go:203-211).
- 3.2 Client deployment ❌ – no enforcement to run clients on every node.
- 3.3 Server/client configs ✅/⚠️ – Agent generator handles modes, but legacy generator always sets `server = true`.

### Section 4: Network Configuration (P1)
- `client_addr = "0.0.0.0"` exposes API (pkg/consul/config/generator.go:123-134).
- `SelectInterface` correctly pins bind address (pkg/consul/config/generator.go:100-119).

### Section 5: Vault Storage Backend (P0)
- Consul storage lacks token/TLS (pkg/vault/config_builder.go:153-164).
- Dedicated cluster checks missing.

### Section 6: Multi-Datacenter Support (P1)
- Federation helper incomplete with multiple TODOs (pkg/hecate/consul/federation.go:200-320).
- No ACL replication logic.

### Section 7: Service Discovery & Registration (P2)
- Service HCL generator supports tags/meta (pkg/consul/agent/config.go:180-223).
- Health checks optional; no enforcement that each service defines one.

### Section 8: Consul SDK Usage (P2)
- All clients use official Go SDK (pkg/consul/config/config.go:16-60).
- Address resolution uses hostnames, not loopback.

### Section 9: High Availability Patterns (P1)
- No operator docs on quorum/failover; rely on Consul defaults.

### Section 10: Operational Patterns (P2)
- Script checks enabled (see critical issue #4).
- Credential rotation not automated (`pkg/consul/constants.go:307-397` only comments).

### Section 11: Deployment Scenarios (P1)
- CLI lacks scenario-specific guardrails for single-node or 3-/5-node rollouts.

### Section 12: Performance Tuning (P3)
- `raft_multiplier = 1` present (pkg/consul/config/generator.go:147-151); no WAN tuning guidance.

### Section 13: Monitoring & Health Checks (P2)
- Minimal telemetry setup; no documentation of REST endpoints.

### Section 14: Backup & DR (P1)
- No snapshot automation or restore helpers; `pkg/consul/rollback` only handles uninstall cleanup.

### Section 15: SDK Integration Patterns (P2)
- No sample code demonstrating blocking queries/watches.

### Section 16: Security Hardening Checklist (P0)
- Multiple failures inherited from Sections 1,2,10; remote exec disablement unverified.

### Section 17: Documentation & Examples (P2)
- README lacks production runbooks; docs/consul-vault-integration.md covers secret engine but not core cluster hardening.

### Section 18: Edge Cases & Error Handling (P1)
- No version drift detection; failure handling delegated to Consul default behavior.

### Section 19: Cloud Provider Integration (P2)
- No auto-join/IAM automation beyond templates.

### Section 20: Container & Orchestrator Integration (P2)
- Docker/Kubernetes/Nomad integration plans exist but not wired into EOS workflows.

## Code Quality Observations
- Logging is verbose and security-sensitive fields (tokens) are usually redacted; continue enforcing structured logging.
- OTel-wrapped loggers are consistent, but lack of unit tests around ACL/tls generation leaves regressions undetected.
- Several packages (e.g., `pkg/consul/secrets`) contain high-quality utilities that are never invoked; align CLI workflows with these helpers.

## Recommendations Summary

### Immediate Actions (P0)
1. Ship encrypted-by-default configs (gossip + TLS) and corresponding automation.
2. Refactor ACL policies to remove wildcard prefixes; parameterize datacenter in agent tokens.
3. Fix Vault Consul storage integration to meet HashiCorp guidance or disable until compliant.
4. Disable script checks and remove script handlers from default config.

### Short-Term (P1)
1. Introduce secure defaults for network exposure and token storage, including warnings when `client_addr` is widened.
2. Automate snapshots/backups and provide documented restore procedures.
3. Implement upgrade compatibility checks and server-count validation beyond 2/4.

### Medium-Term (P2)
1. Expand docs with scenario-based runbooks (dev, 3-node, 5-node, multi-DC, Vault patterns).
2. Provide sample SDK usage for blocking queries, retries, and caching patterns.
3. Wire monitoring/health check guidance into EOS dashboards.

### Long-Term (P3)
1. Offer WAN/latency performance tuning presets and cloud-provider auto-join integrations.

## Appendix A: Checklist Item Status

| Section | Item | Status | Priority | Notes |
|---------|------|--------|----------|-------|
| 1.1 | Default ACL policy deny | ✅ | P0 | Config generator enforces `default_policy = "deny"` (pkg/consul/config/generator.go:186-190). |
| 1.1 | ACLs enabled on new installs | ✅ | P0 | `acl.enabled = true` baked into generated config (pkg/consul/config/generator.go:186-190). |
| 1.1 | Upgrade workflow warns/migrates | ❌ | P0 | `EnableACLsInConfig` overwrites ACL block without warnings or migration steps (pkg/consul/config/acl_enablement.go:135-205). |
| 1.2 | Run bootstrap on first server | ✅ | P0 | `BootstrapConsulACLs` calls `consulClient.ACL().Bootstrap()` (pkg/consul/acl/bootstrap.go:92-124). |
| 1.2 | Bootstrap token stored securely | ⚠️ | P0 | Stored in Vault if available; no encrypted file fallback (pkg/consul/acl/bootstrap.go:132-166). |
| 1.2 | Replacement management token lifecycle | ⚠️ | P0 | Token created but not persisted or rotated (pkg/consul/acl/tokens.go:28-87). |
| 1.3 | Agent-specific policies | ⚠️ | P0 | Node identities created but datacenter hard-coded to `dc1` (pkg/consul/acl/agent_token.go:122-125). |
| 1.3 | Agent policies exact match | ❌ | P0 | Default policies rely on wildcard prefixes (pkg/consul/acl/policies.go:123-240). |
| 1.3 | Vault policy (conditional) | ⚠️ | P0 | Includes required stanzas but leaves `agent_prefix ""` broad (pkg/consul/acl/policies.go:163-186). |
| 1.3 | No global-management tokens to agents | ✅ | P0 | Workflows create dedicated tokens; bootstrap token kept in Vault (pkg/consul/acl/bootstrap.go:132-166). |
| 1.3 | Service-specific tokens | ⚠️ | P0 | Vault roles exist but reference broad policies (pkg/vault/consul_secrets_engine.go:246-282). |
| 2.1 | Generate gossip key | ❌ | P0 | No CLI path populates `encrypt`; only helper functions exist (pkg/consul/secrets/gossip.go:63-178). |
| 2.1 | Store gossip key securely | ⚠️ | P0 | Vault storage attempted after manual config; not generated automatically (pkg/sync/connectors/consul_vault.go:637-645). |
| 2.1 | Distribute key to all nodes | ❌ | P0 | No automation to push key to agents; relies on manual edits. |
| 2.1 | Config sets `encrypt` | ❌ | P0 | `encrypt` line commented out (pkg/consul/config/generator.go:193-195). |
| 2.1 | Key rotation support | ❌ | P0 | No rotation commands; only TODO comments (pkg/consul/secrets/gossip.go:266-312). |
| 2.1 | Logs confirm encryption | ❓ | P0 | No verification or log parsing implemented. |
| 2.2 | Generate CA | ❌ | P0 | No usage of `consul tls ca create`; TLS block commented (pkg/consul/config/generator.go:196-205). |
| 2.2 | Node certificates | ❌ | P0 | No certificate issuance workflow. |
| 2.2 | Multi-DC SAN (conditional) | ❌ | P0 | Not implemented. |
| 2.2 | Client certificate distribution | ❌ | P0 | No auto-encrypt or manual distribution logic. |
| 2.2 | Auto-encrypt config (conditional) | ❌ | P0 | `auto_encrypt` absent from generated configs. |
| 2.2 | TLS verification flags | ❌ | P0 | `verify_*` lines commented (pkg/consul/config/generator.go:196-205). |
| 3.1 | Server count odd validation | ⚠️ | P0 | Blocks 2/4 only; even counts >4 pass (pkg/consul/agent/deploy.go:203-211). |
| 3.1 | Warn on invalid counts | ⚠️ | P0 | Errors only for 2/4; no warnings for 1 or >5 (pkg/consul/agent/deploy.go:203-211). |
| 3.1 | Recommend 3-5 servers | ❌ | P0 | No guidance in CLI/docs. |
| 3.1 | Multi-AZ layout (conditional) | ❓ | P0 | No automation or validation. |
| 3.1 | bootstrap_expect set | ✅ | P0 | Generator writes `bootstrap_expect` when >1 (pkg/consul/config/generator.go:76-106). |
| 3.2 | Client agent everywhere | ❌ | P0 | Deployment tooling lacks enforcement or audit. |
| 3.2 | Clients join local servers | ⚠️ | P0 | `retry_join` required but addresses assumed static hostnames (pkg/consul/agent/config.go:93-116). |
| 3.2 | Max 5000 clients guidance | ❌ | P0 | No checks or warnings. |
| 3.2 | Multi-DC recommendation | ❌ | P0 | Absent from code/docs. |
| 3.3 | Server mode flag | ✅ | P0 | Agent generator sets `server = true` when ModeServer (pkg/consul/agent/config.go:70-88). |
| 3.3 | Client mode config | ⚠️ | P0 | Legacy generator still outputs `server = true`; new agent path handles `server = false` (pkg/consul/config/generator.go:70-118 / pkg/consul/agent/config.go:70-110). |
| 3.3 | retry_join for clients | ✅ | P0 | Client validation enforces `retry_join` non-empty (pkg/consul/agent/deploy.go:223-231). |
| 3.3 | Clients omit bootstrap_expect | ✅ | P0 | Only server mode writes value (pkg/consul/agent/config.go:70-106). |
| 4.1 | bind_addr set | ✅ | P1 | Interface detection ensures explicit `bind_addr` (pkg/consul/config/generator.go:100-127). |
| 4.1 | client_addr hardened | ❌ | P1 | Hard-coded `0.0.0.0` (pkg/consul/config/generator.go:123-135). |
| 4.1 | advertise_addr set | ✅ | P1 | Uses detected IP (pkg/consul/config/generator.go:127-129). |
| 4.2 | Ports documented | ⚠️ | P1 | Config comments list ports; no operator docs (pkg/consul/config/generator.go:109-120). |
| 4.2 | Cloud firewall guidance | ❓ | P1 | Not present. |
| 4.2 | Service mesh ports | ❓ | P1 | Not documented. |
| 4.3 | DNS recursors | ❓ | P1 | No automated configuration. |
| 4.3 | Custom domain | ❓ | P1 | Not supported. |
| 4.3 | DNS forwarding | ❓ | P1 | Absent. |
| 5.1 | Vault storage config | ❌ | P0 | Missing token/TLS (pkg/vault/config_builder.go:153-164). |
| 5.1 | Consul policy for Vault | ⚠️ | P0 | Policy exists but broad (pkg/consul/acl/policies.go:163-186). |
| 5.1 | Vault token not bootstrap | ⚠️ | P0 | Management token created but not persisted or rotated (pkg/consul/acl/tokens.go:28-87). |
| 5.1 | HA Vault agent deployment (conditional) | ❓ | P0 | Not validated. |
| 5.2 | Advise integrated storage | ⚠️ | P0 | Docs hint at Raft preference, but CLI lacks warnings. |
| 5.2 | Document reasons for Consul storage | ❓ | P0 | No prompts. |
| 5.2 | Dedicated cluster mapping | ❌ | P0 | No validation. |
| 5.3 | Consul cluster dedicated | ❌ | P0 | Not enforced. |
| 5.3 | Separate discovery cluster | ❌ | P0 | Not enforced. |
| 5.3 | Separate mesh cluster | ❌ | P0 | Not enforced. |
| 6.1 | Unique DC name | ⚠️ | P1 | Defaults to `dc1`; no validation for uniqueness (cmd/create/consul.go:37-45). |
| 6.1 | Consistent DC naming | ⚠️ | P1 | Relies on manual input. |
| 6.1 | Multi-DC config management | ⚠️ | P1 | Helper exists but not integrated (pkg/hecate/consul/federation.go:200-320). |
| 6.2 | WAN federation configuration | ⚠️ | P1 | Partial logic; many TODOs (pkg/hecate/consul/federation.go:200-320). |
| 6.2 | Mesh gateway support | ❓ | P1 | Not implemented. |
| 6.3 | Primary DC ACL authority | ❌ | P1 | No configuration for `primary_datacenter` or token replication. |
| 6.3 | Replication token distribution | ❌ | P1 | Missing. |
| 6.3 | Replication token security | ❌ | P1 | Missing. |
| 7.1 | Multiple registration methods | ⚠️ | P2 | SDK & HCL supported; docs lacking. |
| 7.1 | Health checks per service | ⚠️ | P2 | Checks optional in API (pkg/consul/agent/config.go:197-220).
| 7.1 | Metadata/tags support | ✅ | P2 | Provided in service generator (pkg/consul/agent/config.go:189-209). |
| 7.2 | Tags/metadata usage | ✅ | P2 | Supported fields (pkg/consul/agent/config.go:182-209).
| 8.1 | Official Consul Go API | ✅ | P2 | All clients import `github.com/hashicorp/consul/api` (e.g., pkg/consul/config/config.go:16-70). |
| 8.1 | Client config completeness | ⚠️ | P2 | Tokens set when provided; TLS ignored (pkg/consul/config/config.go:23-44). |
| 8.1 | Error handling | ⚠️ | P2 | Basic errors returned; no retries/backoff. |
| 8.2 | Connect to local agent | ⚠️ | P2 | Uses hostnames resolved from `GetInternalHostname()` rather than loopback (pkg/shared/service_addresses.go:123-130). |
| 8.2 | Avoid direct server IPs | ⚠️ | P2 | Some code may resolve to server hostnames; no enforcement. |
| 8.2 | Retry logic | ⚠️ | P2 | Circuit breaker exists but not widely used (pkg/consul/enhanced_integration.go:32-142). |
| 9.1 | Leader election documentation | ❓ | P1 | No operator docs. |
| 9.1 | No leader assumption in code | ✅ | P1 | API calls rely on client routing. |
| 9.1 | Apps use local agent | ⚠️ | P1 | Recommended but not enforced. |
| 9.2 | Agent failure handling | ⚠️ | P1 | Circuit breaker optional; fallback missing. |
| 9.2 | Local caching | ❌ | P1 | Not implemented. |
| 9.2 | Exponential backoff | ❌ | P1 | Not implemented. |
| 10.1 | Script checks disabled | ❌ | P2 | `enable_local_script_checks = true` by default (pkg/consul/config/generator.go:179-182). |
| 10.1 | Local script checks conditional | ⚠️ | P2 | Enabled regardless of security posture. |
| 10.2 | Remote execution disabled | ❓ | P2 | Not explicitly configured. |
| 10.2 | ACL hardening for exec | ❓ | P2 | Not applicable / undocumented. |
| 10.3 | Credential rotation support | ⚠️ | P2 | Consul secrets engine enables dynamic tokens; other credentials static. |
| 10.3 | Rotation documentation | ❌ | P2 | Absent. |
| 10.3 | Vault integration for tokens | ✅ | P2 | Secrets engine configured (pkg/vault/consul_secrets_engine.go:70-208). |
| 11.1 | Dev mode support | ⚠️ | P1 | Agent supports ModeDev but CLI docs limited (pkg/consul/agent/types.go:41-141). |
| 11.1 | Dev warnings | ❓ | P1 | No explicit warning banners. |
| 11.1 | Dev characteristics | ⚠️ | P1 | ACLs/TLS remain disabled; not clearly documented. |
| 11.2 | Single-node warnings | ❌ | P1 | No guardrails. |
| 11.2 | Single-node disclaimer | ❌ | P1 | Missing. |
| 11.2 | Single-node security | ❌ | P1 | No enforcement of ACL/TLS. |
| 11.3 | Three-node deployment | ⚠️ | P1 | Manual; no automation beyond templates. |
| 11.3 | Fault tolerance docs | ❌ | P1 | Absent. |
| 11.3 | Quorum documentation | ❌ | P1 | Absent. |
| 11.4 | Five-node support | ❓ | P1 | Not implemented. |
| 11.4 | Multi-AZ distribution | ❌ | P1 | Not automated. |
| 11.4 | Quorum guidance | ❌ | P1 | Absent. |
| 11.5A | Dedicated Consul cluster | ❌ | P1 | No validation. |
| 11.5A | Vault ACL policy | ⚠️ | P1 | Provided but broad. |
| 11.5A | Token management | ⚠️ | P1 | Vault secrets engine handles dynamic tokens; management token static. |
| 11.5A | Session management | ❓ | P1 | Not verified. |
| 11.5B | Vault Raft default | ✅ | P1 | Installer defaults to Raft (pkg/vault/config_builder.go:142-152). |
| 11.5B | Consul for discovery | ⚠️ | P1 | Service registration optional without health guidance. |
| 11.5B | Vault service registration | ⚠️ | P1 | Service registration delegated to Vault config without validation. |
| 11.6 | retry_join configuration | ⚠️ | P1 | Static list required; no automation (pkg/consul/agent/config.go:93-114). |
| 11.6 | Cloud auto-join | ❓ | P1 | Not implemented. |
| 11.6 | Initial bootstrap flow | ⚠️ | P1 | `BootstrapConsulCluster` exists but not tied to CLI workflow. |
| 11.6 | Join existing cluster | ⚠️ | P1 | Manual commands required. |
| 12.1 | Raft multiplier | ✅ | P3 | Set to 1 (pkg/consul/config/generator.go:147-149). |
| 12.1 | WAN tuning guidance | ❓ | P3 | Not documented. |
| 12.1 | High-latency adjustments | ❓ | P3 | Not documented. |
| 12.2 | Connection limits | ❌ | P3 | No config for http_max_conns. |
| 13.1 | Health endpoint docs | ❌ | P2 | Missing. |
| 13.1 | Health checks run | ❌ | P2 | No monitoring integration. |
| 13.2 | Service health checks | ⚠️ | P2 | Optional in templates; not enforced. |
| 14.1 | Snapshot automation | ❌ | P1 | Absent. |
| 14.1 | Snapshot schedule | ❌ | P1 | Absent. |
| 14.1 | Secure snapshot storage | ❌ | P1 | Absent. |
| 14.2 | Restore documentation | ❌ | P1 | Absent. |
| 14.2 | Restore testing | ❌ | P1 | Absent. |
| 14.2 | DR runbooks | ❌ | P1 | Absent. |
| 15.1 | SDK service discovery example | ❌ | P2 | No example code. |
| 15.1 | Applications query Consul | ❓ | P2 | Usage undocumented. |
| 15.1 | Tag filtering | ❌ | P2 | Not demonstrated. |
| 15.2 | KV naming conventions | ⚠️ | P2 | EOS policy allows `config/` prefixes; guidance limited. |
| 15.2 | KV ACL policies | ⚠️ | P2 | Policies broad; lacks least privilege. |
| 15.2 | Secrets avoidance | ❌ | P2 | No enforcement to keep secrets out of KV. |
| 15.3 | Watches support | ❌ | P2 | Not implemented. |
| 15.3 | Blocking query guidance | ❓ | P2 | Not documented. |
| 16 | ACL default deny | ✅ | P0 | See Section 1 findings. |
| 16 | Gossip encryption enabled | ❌ | P0 | See Section 2. |
| 16 | TLS enabled | ❌ | P0 | See Section 2. |
| 16 | Bootstrap token security | ⚠️ | P0 | Stored in Vault when available; no rotation. |
| 16 | Script checks disabled | ❌ | P0 | Enabled locally (pkg/consul/config/generator.go:179-182). |
| 16 | Remote execution disabled | ❓ | P0 | Not confirmed. |
| 16 | Cert expiration reasonable | ❓ | P1 | No certificate automation. |
| 16 | Agent tokens unique | ⚠️ | P1 | Node-identity used but datacenter static. |
| 16 | Service tokens least privilege | ❌ | P1 | Policies broad. |
| 16 | Credential rotation process | ❌ | P2 | Absent. |
| 16 | Audit logging | ❓ | P2 | Not configured. |
| 16 | Monitoring & alerting | ⚠️ | P2 | Telemetry stubbed; no alerting pipeline. |
| 17.1 | Documentation coverage | ⚠️ | P2 | Partial docs (`docs/consul-vault-integration.md`). |
| 17.1 | Scenario examples | ⚠️ | P2 | Limited examples. |
| 17.1 | Troubleshooting guide | ❌ | P2 | Missing. |
| 17.2 | Example deployments | ❌ | P2 | No ready-to-run manifests. |
| 17.2 | Sample configs | ⚠️ | P2 | Some HCL shown in docs. |
| 17.2 | Integration guides | ⚠️ | P2 | Vault integration documented; others missing. |
| 18.1 | Detect version drift | ❌ | P1 | Not implemented. |
| 18.1 | Warn incompatible versions | ❌ | P1 | Not implemented. |
| 18.1 | Preserve security artifacts | ❌ | P1 | No upgrade plan. |
| 18.1 | Rolling upgrades | ❌ | P1 | Missing. |
| 18.2 | Partial failure behavior | ❓ | P1 | Not documented. |
| 18.2 | Health reporting | ❌ | P1 | No aggregated cluster health view. |
| 18.2 | Quorum documentation | ❌ | P1 | Missing. |
| 18.3 | Partition behavior docs | ❌ | P1 | Missing. |
| 18.3 | Quorum partition handling | ❌ | P1 | Missing. |
| 18.3 | App resiliency guidance | ❌ | P1 | Missing. |
| 19.1 | Cloud auto-join | ❓ | P2 | Not delivered. |
| 19.2 | Cloud IAM integration | ❌ | P2 | Missing. |
| 20.1 | Docker persistence | ❓ | P2 | Not covered. |
| 20.1 | Docker networking | ❓ | P2 | Not covered. |
| 20.1 | Container health checks | ❓ | P2 | Not covered. |
| 20.1 | Container logging | ❓ | P2 | Not covered. |
| 20.2 | Kubernetes via Helm | ❌ | P2 | Not implemented. |
| 20.2 | Custom deployment rationale | ❌ | P2 | Missing. |
| 20.2 | Consul dataplane support | ❌ | P2 | Missing. |
| 20.3 | Nomad servers -> Consul | ❓ | P2 | Not documented. |
| 20.3 | Nomad clients register | ❓ | P2 | Not documented. |
| 20.3 | Service discovery via Consul | ❓ | P2 | Not documented. |

## Appendix B: Files Reviewed
- pkg/consul/config/generator.go
- pkg/consul/config/acl_enablement.go
- pkg/consul/acl/bootstrap.go
- pkg/consul/acl/policies.go
- pkg/consul/acl/agent_token.go
- pkg/consul/agent/config.go & deploy.go
- pkg/consul/secrets/gossip.go
- pkg/sync/connectors/consul_vault.go
- pkg/vault/config_builder.go
- pkg/vault/consul_secrets_engine.go
- pkg/shared/service_addresses.go
- pkg/hecate/consul/federation.go
- cmd/create/consul.go

## Appendix C: HashiCorp Documentation References
1. Consul ACL Best Practices — https://developer.hashicorp.com/consul/docs/secure/acl/best-practice
2. Consul Production Security Guidance — https://developer.hashicorp.com/consul/tutorials/production-vms/security
3. Consul Reference Architecture — https://developer.hashicorp.com/consul/tutorials/production-vms/reference-architecture
4. Vault Consul Storage Backend Docs — https://developer.hashicorp.com/vault/docs/configuration/storage/consul
5. Consul Production Checklist — https://developer.hashicorp.com/consul/tutorials/production-vms/production-checklist
