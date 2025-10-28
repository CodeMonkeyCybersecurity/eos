# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **BionicGPT Adversarial Analysis**: Complete codebase review (8,244 lines across 18 files)
  - Identified 15 issues across 4 priority levels (P0-P3)
  - Fixed 3 P0 (Breaking) issues immediately
  - Documented 12 remaining issues with implementation plans
  - See [docs/BIONICGPT_ADVERSARIAL_ANALYSIS_COMPLETE_2025-10-28.md](docs/BIONICGPT_ADVERSARIAL_ANALYSIS_COMPLETE_2025-10-28.md)

- **BionicGPT Concrete Recommendations**: Prioritized improvement roadmap
  - Immediate actions (1 week): 5 tasks, 7-9 hours
  - Short-term (2 weeks): 5 tasks, 14-17 hours
  - Long-term (1 month): 5 tasks, 10-12 hours
  - See [docs/BIONICGPT_RECOMMENDATIONS_2025-10-28.md](docs/BIONICGPT_RECOMMENDATIONS_2025-10-28.md)

- **Vault Integration Roadmap**: Documented BionicGPT Vault integration as deferred task
  - Current state: `.env` files working, Vault diagnostics show 403 (permission issue)
  - Required fix: Update Vault Agent AppRole policy for `services/production/bionicgpt/*`
  - Priority: P2 (Nice-to-have), deferred until Vault-backed delivery needed
  - See [ROADMAP.md](ROADMAP.md#bionicgpt-vault-integration)

- **Consul ACL Auto-Enablement**: `eos sync --vault --consul` now automatically enables Consul ACLs if disabled, with user consent
  - Preflight check detects ACL status before attempting integration
  - Offers to enable ACLs automatically with backup and rollback support
  - Use `--force` flag to enable ACLs without prompting
  - See [docs/consul-vault-integration.md](docs/consul-vault-integration.md#acl-configuration) for details

- **New Helper Package**: `pkg/consul/config/acl_enablement.go`
  - `EnableACLsInConfig()`: Modify Consul configuration to enable ACLs
  - `BackupConfig()`: Create timestamped backups before modification
  - `ValidateConfigSyntax()`: Verify HCL syntax after changes
  - `RestartConsulService()`: Restart Consul and wait for readiness
  - Automatic rollback if Consul fails to start after configuration change

### Changed

- **BREAKING**: Consul ACLs now enabled by default for new installations (changed from `enabled = false` to `enabled = true`)
  - **Impact**: New `eos create consul` installations will have ACLs enabled
  - **Migration**: Existing Consul installations are NOT affected
  - **Rationale**: Required for Vault-Consul integration, improves security posture
  - **Default Policy**: Changed from `allow` to `deny` (zero-trust model)
  - **Rollback**: Original configuration backed up automatically, restore with `cp /etc/consul.d/consul.hcl.backup.TIMESTAMP /etc/consul.d/consul.hcl`

### Fixed

- **BionicGPT LiteLLM Health Check Failure** (P0 - Breaking) - Fixed 2025-10-28
  - **Root Cause**: `curl` executable not found in `ghcr.io/berriai/litellm:main-latest` container
  - **Impact**: Health checks always failed, bionicgpt-app never started (stuck in "created" state), port 8513 inaccessible
  - **Solution**: Changed health check from `curl` to Python `urllib` (Python guaranteed in LiteLLM container)
  - **Files**: [pkg/bionicgpt/install.go:913](pkg/bionicgpt/install.go#L913)
  - **Verification**: Tested on vhost2 production - all containers healthy, port 8513 accessible

- **BionicGPT App Dependency Too Strict** (P0 - Breaking) - Fixed 2025-10-28
  - **Problem**: App depended on `litellm-proxy: service_healthy`, any health check issue blocked startup completely
  - **Solution**: Relaxed to `service_started` - app will retry LiteLLM connections internally (more resilient)
  - **Rationale**: Separation of concerns - health checks for monitoring, not blocking
  - **Files**: [pkg/bionicgpt/install.go:952](pkg/bionicgpt/install.go#L952)

- **BionicGPT Diagnostics Use curl Inside Container** (P0 - Breaking) - Fixed 2025-10-28
  - **Problem**: Diagnostic health checks used `curl` inside LiteLLM container (not available)
  - **Impact**: Diagnostics always showed "failed" even when service was healthy
  - **Solution**: Changed all curl usages to Python urllib
  - **Files**:
    - [pkg/debug/bionicgpt/diagnostics.go:1449](pkg/debug/bionicgpt/diagnostics.go#L1449) (health endpoint)
    - [pkg/debug/bionicgpt/diagnostics.go:1487](pkg/debug/bionicgpt/diagnostics.go#L1487) (liveliness endpoint)
    - [pkg/debug/bionicgpt/diagnostics.go:881](pkg/debug/bionicgpt/diagnostics.go#L881) (remediation message)
  - **Verification**: `go build` and `go vet` both pass

- **Issue**: `eos sync --vault --consul` failed with "ACL support disabled" error
  - **Root Cause**: Vault-Consul integration requires ACLs, but default Consul config had `acl.enabled = false`
  - **Solution**: Preflight check now detects this and offers automatic remediation
  - **User Experience**: Clear error messages with actionable remediation steps

## [v1.x.x] - Previous Releases

(Historical changelog entries go here)

---

## Breaking Change Migration Guide

### Consul ACL Default Change (v2.0)

**Who is affected**: Users who install Consul with Eos v2.0+

**What changed**: ACLs are now enabled by default

**Before (v1.x)**:
```bash
eos create consul
# Config: acl { enabled = false, default_policy = "allow" }

eos sync --vault --consul
# Error: ACL support disabled
```

**After (v2.0)**:
```bash
eos create consul
# Config: acl { enabled = true, default_policy = "deny" }

eos sync --vault --consul
# Success: ACLs already enabled, bootstrap proceeds
```

**Migration for existing installations**:

If you have Consul installed with ACLs disabled:

```bash
# Option 1: Automatic (recommended)
sudo eos sync --vault --consul
# Answer 'y' when prompted to enable ACLs

# Option 2: Automatic without prompting
sudo eos sync --vault --consul --force

# Option 3: Manual
sudo nano /etc/consul.d/consul.hcl
# Change: acl { enabled = true, default_policy = "deny" }
sudo systemctl restart consul
sudo eos sync --vault --consul
```

**Rollback**:

If you need to revert to ACLs disabled:

```bash
# 1. Restore backup
sudo cp /etc/consul.d/consul.hcl.backup.TIMESTAMP /etc/consul.d/consul.hcl

# 2. Restart Consul
sudo systemctl restart consul

# 3. Verify
consul members
```

**Why this change**:

1. Security: ACLs provide access control and audit trails
2. Compliance: Required for SOC2, PCI-DSS, HIPAA
3. Vault Integration: Vault Consul secrets engine requires ACLs
4. Best Practice: HashiCorp recommends ACLs for production

**Support**:

- Documentation: [docs/consul-vault-integration.md#acl-configuration](docs/consul-vault-integration.md#acl-configuration)
- Issues: https://github.com/CodeMonkeyCybersecurity/eos/issues
- Community: https://wiki.cybermonkey.net.au
