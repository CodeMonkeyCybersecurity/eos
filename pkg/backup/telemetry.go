package backup

import "expvar"

var (
	backupRepositoryResolutionTotal = expvar.NewMap("backup_repository_resolution_total")
	backupConfigLoadTotal           = expvar.NewMap("backup_config_load_total")
	backupConfigSourceTotal         = expvar.NewMap("backup_config_source_total")
	backupPasswordSourceTotal       = expvar.NewMap("backup_password_source_total")
	backupHookDecisionTotal         = expvar.NewMap("backup_hook_decision_total")

	backupRepositoryResolutionBySourceTotal  = expvar.NewMap("backup_repository_resolution_by_source_total")
	backupRepositoryResolutionByOutcomeTotal = expvar.NewMap("backup_repository_resolution_by_outcome_total")
	backupConfigLoadBySourceTotal            = expvar.NewMap("backup_config_load_by_source_total")
	backupConfigLoadByOutcomeTotal           = expvar.NewMap("backup_config_load_by_outcome_total")
	backupConfigSourceBySourceTotal          = expvar.NewMap("backup_config_source_by_source_total")
	backupConfigSourceByOutcomeTotal         = expvar.NewMap("backup_config_source_by_outcome_total")
	backupPasswordSourceBySourceTotal        = expvar.NewMap("backup_password_source_by_source_total")
	backupPasswordSourceByOutcomeTotal       = expvar.NewMap("backup_password_source_by_outcome_total")
	backupHookDecisionBySourceTotal          = expvar.NewMap("backup_hook_decision_by_source_total")
	backupHookDecisionByOutcomeTotal         = expvar.NewMap("backup_hook_decision_by_outcome_total")
)

func recordLegacyAndStructured(legacy, bySource, byOutcome *expvar.Map, source string, success bool) {
	outcome := "failure"
	if success {
		outcome = "success"
	}

	// Keep legacy keys for compatibility with existing dashboards and tests.
	legacy.Add(source+"_total", 1)
	legacy.Add(source+"_"+outcome, 1)

	// Structured counters keep source and outcome dimensions separate.
	bySource.Add(source, 1)
	byOutcome.Add(outcome, 1)
}

func recordRepositoryResolution(source string, success bool) {
	recordLegacyAndStructured(
		backupRepositoryResolutionTotal,
		backupRepositoryResolutionBySourceTotal,
		backupRepositoryResolutionByOutcomeTotal,
		source,
		success,
	)
}

// RecordRepositoryResolution allows external packages (for example cmd/backup)
// to emit repository resolution telemetry using the same series.
func RecordRepositoryResolution(source string, success bool) {
	recordRepositoryResolution(source, success)
}

func recordConfigLoad(source string, success bool) {
	recordLegacyAndStructured(
		backupConfigLoadTotal,
		backupConfigLoadBySourceTotal,
		backupConfigLoadByOutcomeTotal,
		source,
		success,
	)
}

func recordConfigSource(source string, success bool) {
	recordLegacyAndStructured(
		backupConfigSourceTotal,
		backupConfigSourceBySourceTotal,
		backupConfigSourceByOutcomeTotal,
		source,
		success,
	)
}

func recordPasswordSource(source string, success bool) {
	recordLegacyAndStructured(
		backupPasswordSourceTotal,
		backupPasswordSourceBySourceTotal,
		backupPasswordSourceByOutcomeTotal,
		source,
		success,
	)
}

func recordHookDecision(decision string, success bool) {
	recordLegacyAndStructured(
		backupHookDecisionTotal,
		backupHookDecisionBySourceTotal,
		backupHookDecisionByOutcomeTotal,
		decision,
		success,
	)
}
