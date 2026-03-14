# Eos

Go CLI for Ubuntu server administration — Vault, Consul, Nomad, Caddy/Hecate, and containerised services.
Code Monkey Cybersecurity (ABN 77 177 673 061). Dual-licensed: AGPL-3.0-or-later + Do No Harm License.

## Commands

```bash
go build -o /tmp/eos-build ./cmd/  # ALWAYS run before committing — zero compile-error tolerance
go test ./pkg/...                  # Unit tests
go test -race ./pkg/...            # Race-detection (CI-blocking)
go test -tags=integration ./...    # Integration tests
golangci-lint run                  # Lint
make all                           # Lint + test + build
```

## Governing contracts

**IMPORTANT:** Read the relevant contract before starting any work.

Compact ruleset (60 rules, always loaded): @prompts/GOVERNANCE-SUMMARY.md
Anti-patterns catalogue (always loaded): @prompts/ANTI-PATTERNS.md

All governance contracts vendored from `cybermonkey/prompts` at `prompts/`:

| Contract | File | Governs |
|----------|------|---------|
| Session workflow | @prompts/SOAPIER.md | 14-step SOAPIER process |
| Documentation | @prompts/DOCUMENTATION.md | Diataxis, frontmatter, naming |
| Testing | @prompts/TESTING.md | 70/20/10, coverage, evidence |
| Testing (Go) | @prompts/TESTING-GO.md | Race detection, testify, table-driven tests |
| Workflow | @prompts/WORKFLOW.md | CI, PRs, branch lifecycle |
| Git Rules | @prompts/GIT-RULES.md | Signing, linear history |
| Security | @prompts/SECURITY.md | Secrets, OWASP, SLSA |
| Coordination | @prompts/COORDINATION.md | Multi-agent isolation |

Submodule update runbook: @prompts/docs/runbooks/RUNBOOK-update-submodule.md

## Eos-specific patterns

Domain rules are in `.claude/rules/` with path scoping — they load automatically when you touch those files:

| Rule file | Loads when touching | Key patterns |
|-----------|-------------------|--------------|
| `go-patterns.md` | `**/*.go` | Architecture, constants, logging, idempotency, retry |
| `cli-patterns.md` | `cmd/**/*.go` | cmd/ vs pkg/ enforcement, flag validation, human-centric input |
| `secrets-vault.md` | `pkg/vault/**`, `pkg/consul/**` | Vault/Consul storage, Vault Agent, token auth |
| `debugging.md` | `cmd/debug/**` | Diagnostic logging, evidence collection, report rendering |

## Architecture (quick reference)

- **cmd/**: Orchestration ONLY — cobra + flags + call pkg/. If >100 lines → move to pkg/.
- **pkg/**: ALL business logic — ASSESS → INTERVENE → EVALUATE. Always use `*eos_io.RuntimeContext`.
- **Logging:** ONLY `otelzap.Ctx(rc.Ctx)` — never `fmt.Print*` (exception: `fmt.Print(report.Render())` at end of cmd/debug/ handlers)
- **Constants:** NEVER hardcode — use `pkg/shared/ports.go`, `pkg/shared/paths.go`, `pkg/[service]/constants.go`
- **Human-centric:** Missing flags → `interaction.GetRequiredString()` fallback chain, never hard-fail

## Documentation

- Patterns and detailed examples: @prompts/docs/CANONICAL.md
- Roadmap and technical debt: [ROADMAP.md](ROADMAP.md)
- Per-directory docs: `README.md` in each directory

**FORBIDDEN**: standalone `*.md` files other than ROADMAP.md and per-directory README.md. Put patterns in `.claude/rules/`, implementation rationale in inline comments.

## Cross-repo work

If a fix belongs in a different repo, create the issue in the **target repo** first, then use the ISoBAR cross-repo template from `prompts/COORDINATION.md`.

Repo inventory: hecate (gateway, vhost7), moni (backend, vhost11), contracts (data contracts), aphrodite (UI), prompts (governance).

## Testing

@prompts/TESTING.md
@prompts/TESTING-GO.md
