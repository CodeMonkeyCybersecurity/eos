package backup

import "expvar"

var (
	backupRepositoryResolutionTotal = expvar.NewMap("backup_repository_resolution_total")
	backupConfigLoadTotal           = expvar.NewMap("backup_config_load_total")
)

func recordRepositoryResolution(source string, success bool) {
	backupRepositoryResolutionTotal.Add(source+"_total", 1)
	if success {
		backupRepositoryResolutionTotal.Add(source+"_success", 1)
		return
	}
	backupRepositoryResolutionTotal.Add(source+"_failure", 1)
}

func recordConfigLoad(source string, success bool) {
	backupConfigLoadTotal.Add(source+"_total", 1)
	if success {
		backupConfigLoadTotal.Add(source+"_success", 1)
		return
	}
	backupConfigLoadTotal.Add(source+"_failure", 1)
}
