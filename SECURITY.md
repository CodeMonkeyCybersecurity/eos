# Security Policy

## Supported Versions

Use this section to tell people about which versions of your project are
currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 5.1.x   | :white_check_mark: |
| 5.0.x   | :x:                |
| 4.0.x   | :white_check_mark: |
| < 4.0   | :x:                |

## Reporting a Vulnerability

Use this section to tell people how to report a vulnerability.

Tell them where to go, how often they can expect to get an update on a
reported vulnerability, what to expect if the vulnerability is accepted or
declined, etc.

## AI automation hardening

- Every AI action is validated against a canonical workspace allowlist, command deny-list, and size/argument limits before execution. All actions (success or failure) are recorded with timestamps in `.eos-ai-audit/actions.log` for post-incident forensics.
- Environment analysis now skips `.env`, `*.pem`, kubeconfig and other high-risk files unless the operator explicitly opts in. Sanitized summaries replace raw contents and the CLI displays a consent banner before sharing any context with Anthropic/OpenAI.
- Auto-remediation requires an HMAC-signed policy (`--auto-fix-policy`) to bypass per-action confirmation even when `--auto-fix` is provided.

## Supply-chain verification

- `pkg/remotecode/install.go` downloads installers to a temporary file, enforces a pinned SHA-256 (override via `ClaudeInstallerSHA256`/`CLAUDE_INSTALLER_SHA256`), and provides offline/manual fallback instructions when HTTPS fails.
- `install.sh` now maintains explicit checksum tables for every artifact (Go toolchains, GitHub CLI GPG key, etc.) and refuses to proceed if a checksum mismatches or is missing.
- `test/install_checksum_table_test.go` keeps the checksum map honest by ensuring every entry is a 64-character hex digest.
