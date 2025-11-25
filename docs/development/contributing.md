# Contributing

Welcome to Eos. Contributions should reinforce the "solve once, systematize" philosophy and keep the experience human-centric, evidence-based, and sustainable.

## Before you start
- Read [CLAUDE.md](../../CLAUDE.md) and the root [README.md](../../README.md) for architecture and philosophy.
- Review [ADR index](../adr/README.md) to avoid duplicating decisions; add a new ADR for material behavior changes.
- Map work to a verb and service (e.g., `update vault`, `debug consul`).

## Workflow
1. Create a topic branch; keep changes scoped and incremental.
2. Write or update ADRs and docs alongside code.
3. Run formatting and checks:
   ```bash
   gofmt -w ./pkg ./cmd
   go vet ./...
   go test ./...
   go build -o /tmp/eos-build ./cmd/...
   ```
4. Add command docs under [reference/commands](../reference/commands/) when behavior changes.
5. Submit for review with a summary of risks, tests run, and any follow-up tasks.

## Contribution principles
- Orchestration in `cmd/`; business logic in `pkg/`.
- Use `otelzap.Ctx(rc.Ctx)` for logging; avoid `fmt.Print*` for operational output.
- Keep constants centralized; no hardcoded ports/paths/permissions.
- Default to safe operations with user consent and clear rollback guidance.
