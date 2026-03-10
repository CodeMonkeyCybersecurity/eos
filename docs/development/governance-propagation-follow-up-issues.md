# Governance Propagation Follow-up Issues

## Issue 1: Replace temporary symlink compatibility with upstream checker path abstraction

Problem: The local wrapper still creates a temporary `third_party/prompts` symlink when the submodule lives at `prompts/` because the upstream checker hard-codes `third_party/prompts/` references.

Why it matters: The wrapper is now idempotent and covered, but the symlink is still compatibility glue rather than a first-class contract.

Next step: Update the upstream checker in `prompts/scripts/check-governance.sh` to accept a prompts directory override and consume that from the wrapper.

## Issue 2: Promote shell coverage reporting to a first-class published artifact

Problem: The repo now computes shell coverage during `ci:debug`, but the result is only printed in logs and kept in the local `outputs/` tree.

Why it matters: Historical coverage drift is harder to track when the value is not uploaded or summarized in a dedicated report artifact.

Next step: Publish `outputs/ci/governance-propagation-coverage/coverage.json` as a workflow artifact and add trend reporting if the team wants longer-lived observability.
