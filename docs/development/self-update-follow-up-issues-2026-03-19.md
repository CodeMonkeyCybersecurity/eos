# Self-Update Follow-Up Issues

Date: 2026-03-19
Scope: `eos self update`

1. Issue: Preserve and replay conflicted local changes without leaving the working tree dirty
Description: Add an explicit recovery workflow for the case where a fast-forward update succeeds but re-applying stashed local edits conflicts with the new upstream files.
Why follow up: This iteration now prevents unsafe cross-branch and diverged updates, but overlapping local edits after a legitimate upstream change can still require manual conflict resolution.

2. Issue: Normalize working-tree ownership for sudo-driven self-update runs
Description: Extend sudo ownership normalization beyond `.git/` so root-owned tracked or generated files in `/opt/eos` do not accumulate and block later developer or CI writes.
Why follow up: The current hardening preserves `.git` ownership, but the broader source tree can still contain root-owned files from prior privileged operations.

3. Issue: Persist a durable self-update transaction report on disk
Description: Write the structured transaction summary to a stable JSON artifact under `/var/log/eos/` so operators can inspect the last outcome without reconstructing it from terminal scrollback.
Why follow up: Structured logs are stronger now, but postmortem review is still log-centric rather than artifact-centric.

4. Issue: Add a dry-run mode for branch/remote/stash assessment
Description: Implement `eos self update --dry-run` to report the checked-out branch, remote relation, credential readiness, stash necessity, and planned actions without mutating the repo or installed binary.
Why follow up: The new pull assessment is human-centric, and a dry-run mode would expose it proactively instead of only during execution.

5. Issue: Export self-update outcome counters and branch-relation metrics
Description: Publish metrics for `up_to_date`, `local_ahead`, `remote_ahead`, `diverged`, `failed`, and `rolled_back` outcomes so alerting can distinguish operator action from genuine updater failure.
Why follow up: CI already emits artifacts and alerts, but runtime observability still relies mostly on logs rather than metrics.
