# Backup Observability Runbook

## Metrics Endpoint

Backup telemetry is exported via Go `expvar` at `/debug/vars`.

Key maps:

- `backup_repository_resolution_total`
- `backup_repository_resolution_by_source_total`
- `backup_repository_resolution_by_outcome_total`
- `backup_config_load_total`
- `backup_config_load_by_source_total`
- `backup_config_load_by_outcome_total`
- `backup_config_source_total`
- `backup_config_source_by_source_total`
- `backup_config_source_by_outcome_total`
- `backup_password_source_total`
- `backup_password_source_by_source_total`
- `backup_password_source_by_outcome_total`
- `backup_hook_decision_total`
- `backup_hook_decision_by_source_total`
- `backup_hook_decision_by_outcome_total`

## High-Signal Keys

Config and path drift:

- `backup_config_load_total.permission_denied_failure`
- `backup_config_source_total.canonical_success`
- `backup_config_source_total.legacy_success`
- `backup_config_source_total.defaults_success`

Credential source health:

- `backup_password_source_total.vault_success`
- `backup_password_source_total.vault_failure`
- `backup_password_source_total.repo_env_success`
- `backup_password_source_total.secrets_env_success`
- `backup_password_source_by_source_total.vault`
- `backup_password_source_by_outcome_total.failure`
- `backup_password_source_by_outcome_total.success`

Hook policy enforcement:

- `backup_hook_decision_total.allowlist_execute_success`
- `backup_hook_decision_total.deny_not_allowlisted_failure`
- `backup_hook_decision_total.deny_bad_arguments_failure`
- `backup_hook_decision_total.disabled_failure`
- `backup_hook_decision_by_source_total.deny_not_allowlisted`
- `backup_hook_decision_by_outcome_total.failure`

## Recommended Alerts

- Config access regression:
  Trigger if `permission_denied_failure` increases over a 5-minute window.
- Secret hygiene regression:
  Trigger if `backup_password_source_by_outcome_total.failure` rises above 5% of total outcomes.
- Hook policy pressure:
  Trigger if `backup_hook_decision_by_outcome_total.failure` spikes while execution volume is stable.
