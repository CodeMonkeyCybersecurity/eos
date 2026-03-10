# Governance Propagation Follow-up Issues

## Issue 1: Add branch/outcome coverage reporting for Bash governance wrappers

Problem: The current shell test pyramid exercises the outcome matrix well, but it does not produce line/branch coverage percentages for `scripts/lib/prompts-submodule.sh`, `scripts/prompts-submodule-freshness.sh`, or `scripts/check-governance.sh`.

Why it matters: We can defend high behavioural coverage, but not claim a measured line coverage percentage from the current toolchain.

Next step: Evaluate `kcov` or a lightweight shell coverage harness that can run in CI without making local development heavier.

## Issue 2: Extend governance wrapper testing to a dedicated unit/integration/e2e pyramid

Problem: Freshness now has a clear 70/20/10 split, but governance wrapper coverage is still concentrated in one script even though it now exercises direct path, symlink path, and blocked path cases.

Why it matters: The coverage is good, but the test shape is less explicit than the freshness workflow and harder to reason about at a glance.

Next step: Split governance wrapper tests into dedicated `unit`, `integration`, and `e2e` entrypoints and wire them into a standalone governance workflow if the wrapper gains more behaviour.

## Issue 3: Replace temporary symlink compatibility with upstream checker path abstraction

Problem: The local wrapper still creates a temporary `third_party/prompts` symlink when the submodule lives at `prompts/` because the upstream checker hard-codes `third_party/prompts/` references.

Why it matters: The wrapper is idempotent now, but the symlink is still compatibility glue rather than a first-class contract.

Next step: Update the upstream checker in `prompts/scripts/check-governance.sh` to accept a prompts directory override and consume that from the wrapper.
