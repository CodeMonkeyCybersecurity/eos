package backup

import "expvar"

var (
	backupRepositoryResolutionTotal = expvar.NewMap("backup_repository_resolution_total")
	backupConfigLoadTotal           = expvar.NewMap("backup_config_load_total")
	backupConfigSourceTotal         = expvar.NewMap("backup_config_source_total")
	backupPasswordSourceTotal       = expvar.NewMap("backup_password_source_total")
	backupHookDecisionTotal         = expvar.NewMap("backup_hook_decision_total")
)

func recordRepositoryResolution(source string, success bool) {
	backupRepositoryResolutionTotal.Add(source+"_total", 1)
	if success {
		backupRepositoryResolutionTotal.Add(source+"_success", 1)
		return
	}
	backupRepositoryResolutionTotal.Add(source+"_failure", 1)
}

// RecordRepositoryResolution allows external packages (for example cmd/backup)
// to emit repository resolution telemetry using the same series.
func RecordRepositoryResolution(source string, success bool) {
	recordRepositoryResolution(source, success)
}

func recordConfigLoad(source string, success bool) {
	backupConfigLoadTotal.Add(source+"_total", 1)
	if success {
		backupConfigLoadTotal.Add(source+"_success", 1)
		return
	}
	backupConfigLoadTotal.Add(source+"_failure", 1)
}

func recordConfigSource(source string, success bool) {
	backupConfigSourceTotal.Add(source+"_total", 1)
	if success {
		backupConfigSourceTotal.Add(source+"_success", 1)
		return
	}
	backupConfigSourceTotal.Add(source+"_failure", 1)
}

func recordPasswordSource(source string, success bool) {
	backupPasswordSourceTotal.Add(source+"_total", 1)
	if success {
		backupPasswordSourceTotal.Add(source+"_success", 1)
		return
	}
	backupPasswordSourceTotal.Add(source+"_failure", 1)
}

func recordHookDecision(decision string, success bool) {
	backupHookDecisionTotal.Add(decision+"_total", 1)
	if success {
		backupHookDecisionTotal.Add(decision+"_success", 1)
		return
	}
	backupHookDecisionTotal.Add(decision+"_failure", 1)
}
