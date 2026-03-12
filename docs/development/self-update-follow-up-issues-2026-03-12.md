# Self-Update Follow-Up Issues

Date: 2026-03-12
Scope: `eos self update`

1. Issue: Persist self-update transaction records outside ephemeral logs
Description: Write a compact JSON transaction record to disk so operators can inspect the last successful, skipped, failed, and rolled-back update without parsing journal output.
Why follow up: The current refactor improves structured logs, but there is still no durable per-run transaction artifact for incident review.

2. Issue: Add explicit dry-run mode for `eos self update`
Description: Provide `eos self update --dry-run` to report trusted remote status, credential readiness, source/binary commit drift, disk space, and planned actions without mutating git or the installed binary.
Why follow up: This would further improve operator trust and reduce risky trial runs on production hosts.

3. Issue: Support authenticated non-interactive pulls with documented credential sources
Description: Add first-class support for non-interactive token or SSH-agent based update flows and document the precedence order for repo-local, root, and invoking-user git credential configuration.
Why follow up: The current behavior is safer and clearer, but HTTPS auth under `sudo` remains operationally fragile.

4. Issue: Add an end-to-end rollback smoke test with a synthetic install failure
Description: Exercise `pull -> build -> backup -> failed install -> rollback` in one controlled scenario and assert binary restoration plus git/stash restoration semantics.
Why follow up: Current coverage is strong around units and focused lanes, but rollback orchestration still depends mostly on lower-level tests.

5. Issue: Expose self-update counters and outcomes as process metrics
Description: Export metrics for `started`, `skipped`, `succeeded`, `failed`, and `rolled_back` self-update outcomes, plus phase durations.
Why follow up: CI emits artifacts and alerts, but runtime observability is still log-centric rather than metric-driven.

6. Issue: Document the installed-binary-versus-source-commit model
Description: Add operator-facing docs describing when `eos self update` skips, rebuilds, or backs up the binary and how embedded build metadata affects those decisions.
Why follow up: The new no-op path is simpler, but the rationale should be explicit for maintainers and operators.
