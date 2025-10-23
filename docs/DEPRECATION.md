# Deprecation Notice

*Last Updated: 2025-10-22*

This document tracks deprecated features in Eos and their removal timelines.

## Active Deprecations

### 1. `eos fix` Command Family

**Status**: DEPRECATED as of 2025-10-22
**Removal Target**: 2026-04-22 (6 months)
**Removal Version**: v2.0.0
**Replacement**: `eos update <service> --fix`

#### Affected Commands
- `eos fix vault` → `eos update vault --fix`
- `eos fix consul` → `eos update consul --fix`
- `eos fix mattermost` → `eos update mattermost --fix`
- `eos fix iris` → **EXCEPTION**: Kept as-is (development tooling)

#### Rationale
The `eos fix` command family was reactive ("something broke, fix it"). The new `eos update <service> --fix` pattern is proactive ("update service by correcting configuration drift from canonical state"). This aligns with the "configuration as code" philosophy where drift is automatically detected and corrected.

#### Migration Guide

**For Interactive Use:**
```bash
# Old way (deprecated)
sudo eos fix vault --all
sudo eos fix consul --dry-run

# New way
sudo eos update vault --fix
sudo eos update consul --fix --dry-run
```

**For Scripts/Automation:**
```bash
# Update your cron jobs, CI/CD pipelines, and automation scripts
# Old:
*/5 * * * * /usr/local/bin/eos fix vault --all >> /var/log/eos.log 2>&1

# New:
*/5 * * * * /usr/local/bin/eos update vault --fix >> /var/log/eos.log 2>&1
```

**For Ansible/Terraform:**
```yaml
# Old (deprecated)
- name: Fix Vault configuration drift
  command: eos fix vault --all

# New
- name: Fix Vault configuration drift
  command: eos update vault --fix
```

#### Suppressing Deprecation Warnings

If you cannot migrate immediately, suppress warnings in automation:

**Option 1: Environment Variable**
```bash
export EOS_LOG_LEVEL=error  # Only show errors, suppress warnings
eos fix vault --all
```

**Option 2: Redirect stderr**
```bash
eos fix vault --all 2>/dev/null  # Not recommended - hides real errors
```

**Option 3: Filter stderr**
```bash
eos fix vault --all 2>&1 | grep -v "DEPRECATION WARNING"
```

#### Timeline

| Date | Milestone |
|------|-----------|
| 2025-10-22 | Deprecation announced, warnings added |
| 2025-11-22 | **1 month** - Migration grace period |
| 2025-12-22 | **2 months** - Louder warnings added |
| 2026-01-22 | **3 months** - Last chance notices |
| 2026-02-22 | **4 months** - Pre-removal warnings |
| 2026-03-22 | **5 months** - Final month notices |
| 2026-04-22 | **6 months** - Commands removed in v2.0.0 |

#### Breaking Changes in v2.0.0

When v2.0.0 is released (~2026-04-22), the following commands will **no longer work**:
- `eos fix vault`
- `eos fix consul`
- `eos fix mattermost`

Users will receive:
```
Error: unknown command "fix" for "eos"
Did you mean "eos update <service> --fix"?
See 'eos update --help' for available commands.
```

#### Automated Migration Script

We provide a migration script to update your codebase:

```bash
# Download migration script
curl -o /tmp/migrate-fix-to-update.sh https://github.com/CodeMonkeyCybersecurity/eos/scripts/migrate-fix-to-update.sh
chmod +x /tmp/migrate-fix-to-update.sh

# Dry-run (shows what would change)
/tmp/migrate-fix-to-update.sh --dry-run /path/to/your/scripts

# Apply migrations
/tmp/migrate-fix-to-update.sh /path/to/your/scripts
```

#### Support

If you have questions or concerns about this deprecation:
- Open an issue: https://github.com/CodeMonkeyCybersecurity/eos/issues
- Email: support@cybermonkey.net.au
- Documentation: https://docs.cybermonkey.net.au/eos/migrations/fix-to-update

---

## Deprecation Policy

Eos follows semantic versioning and provides clear deprecation timelines:

1. **Minor Releases** (v0.x, v1.x): Features deprecated with 6-month notice
2. **Major Releases** (v2.0, v3.0): Breaking changes allowed, deprecated features removed
3. **Patch Releases** (v1.2.3): No deprecations, only bug fixes

### Deprecation Stages

1. **Soft Deprecation** (Month 1-2): Warnings in help text, old command still works
2. **Hard Deprecation** (Month 3-4): Runtime warnings every time command runs
3. **Pre-Removal** (Month 5-6): Loud warnings, migration script available
4. **Removal** (Month 6+): Command removed in next major version

### User Communication

When a feature is deprecated, we communicate through:
- In-app warnings (logger.Warn messages)
- Help text updates (`--help` shows [DEPRECATED])
- This DEPRECATION.md file
- Release notes
- GitHub issues/discussions
- Blog posts (for major deprecations)
- Email to known enterprise users

---

## Historical Deprecations

_None yet - this is the first deprecation in Eos._

---

**Code Monkey Cybersecurity** - "Cybersecurity. With humans."

ABN 77 177 673 061
https://cybermonkey.net.au
