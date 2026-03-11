# Self-Update Follow-Up Issues

## 1. Add explicit `--force-insecure` plumbing for Vault TLS fallback

Problem: `pkg/vault/phase2_env_setup.go` still relies on environment-variable overrides for non-interactive insecure fallback rather than a first-class CLI flag.

Why it matters: the current audit trail is stronger than before, but the consent model is still uneven across commands that call `EnsureVaultEnv`.

Next step: introduce a shared `--force-insecure` flag at the command layer, thread it through `RuntimeContext.Attributes`, and require a matching audit record before setting `VAULT_SKIP_VERIFY=1`.

## 2. Replace fetch-then-pull with fetch-plus-fast-forward/merge strategy

Problem: `pkg/git/PullRepository` now fetches before deciding whether to stash, but it still performs a subsequent `git pull`, which duplicates the network step.

Why it matters: the behavior is safer and simpler than before, but not yet optimal for latency or traceability.

Next step: add a `mergeFetchedHead` path that applies `FETCH_HEAD` directly when the preflight shows a clean fast-forward, and fall back to retryable pull only when needed.

## 3. Promote self-update quality lane into the default CI debug lane for touched files

Problem: `npm run ci` passes through `ci:debug`, while the self-update-specific 90% focused gate runs separately today.

Why it matters: local and CI success can still diverge if contributors forget to run the focused lane after touching `pkg/git`, `pkg/self`, or Vault TLS consent code.

Next step: either invoke `ci:self-update-quality` from `ci:debug` when relevant files change, or make `npm run ci` compose both lanes.

## 4. Add alert routing for self-update regressions

Problem: the self-update lane emits structured metrics and reports, but there is no dedicated alert policy for repeated failures or coverage regression over time.

Why it matters: the current observability is good for manual inspection, not proactive detection.

Next step: publish the focused coverage metric to the existing monitoring pipeline and add an alert on consecutive failures or coverage dropping below 90%.

## 5. Add mutation/property coverage for pull decision logic

Problem: the new tests cover the major branches in `PullRepository`, but they do not yet prove resilience against subtle control-flow regressions in the decision matrix.

Why it matters: this path coordinates trust validation, credential policy, stash safety, fetch-first logic, and rollback semantics.

Next step: add table-driven property tests for option combinations and mutation-oriented checks around stash restoration and fetch-first early exits.
