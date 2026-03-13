# Prompts Submodule Report Schema Migration Guide

## Change

The prompts-submodule governance and freshness wrappers now emit report artifacts with `schema_version: "2"` and `run_id`.

Affected report paths:

- `outputs/ci/submodule-freshness/report.json`
- `outputs/ci/governance/report.json`
- `outputs/ci/pre-commit/report.json`

## Why

Versioned reports let CI alerts and downstream tooling evolve without guessing field shape from ad hoc JSON. Version 2 adds:

- `schema_version`
- `run_id`
- `action`

## Compatibility

Version 1 consumers that only read `status`, `outcome`, `message`, or `exit_code` continue to work because those fields are unchanged.

## Migration

1. Prefer checking `schema_version` before using optional fields.
2. Treat missing `schema_version` as version 1.
3. Use `action` when the same report family can emit multiple modes.
4. Use `run_id` to correlate shell logs with the matching artifact.

## Example

```json
{
  "schema_version": "2",
  "run_id": "20260312Z-12345",
  "kind": "governance",
  "action": "governance",
  "status": "pass",
  "outcome": "pass_checked_via_override"
}
```
