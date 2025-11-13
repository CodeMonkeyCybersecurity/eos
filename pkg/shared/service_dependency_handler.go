// pkg/shared/service_dependency_handler.go

package shared

import "time"

// getDependencyWorkers returns additional workers for dependencies that need file updates
func (sm *ServiceManager) getDependencyWorkers(service WazuhServiceDefinition, timestamp string) []ServiceWorkerInfo {
	var dependencyWorkers []ServiceWorkerInfo

	for _, dep := range service.Dependencies {
		switch dep {
		case "alert-to-db":
			// alert-to-db.py is a script dependency of wazuh-listener, not a service
			dependencyWorkers = append(dependencyWorkers, ServiceWorkerInfo{
				ServiceName:  "alert-to-db",
				SourcePath:   "/opt/eos/assets/python_workers/alert-to-db.py",
				TargetPath:   "/usr/local/bin/alert-to-db.py", // wazuh-listener expects it here
				ServiceFile:  "",                              // No systemd service file
				Dependencies: []string{},
				BackupPath:   "/usr/local/bin/alert-to-db.py." + timestamp + ".bak",
			})
		case "ab-test-analyzer":
			// ab-test-analyzer.py is also deployed for manual analysis
			dependencyWorkers = append(dependencyWorkers, ServiceWorkerInfo{
				ServiceName:  "ab-test-analyzer",
				SourcePath:   "/opt/eos/assets/python_workers/ab-test-analyzer.py",
				TargetPath:   "/usr/local/bin/ab-test-analyzer.py",
				ServiceFile:  "", // No systemd service file
				Dependencies: []string{},
				BackupPath:   "/usr/local/bin/ab-test-analyzer.py." + timestamp + ".bak",
			})
		}
	}

	return dependencyWorkers
}

// UpdateGetServiceWorkersForUpdate modifies the original function to include dependencies
func (sm *ServiceManager) UpdateGetServiceWorkersForUpdate() []ServiceWorkerInfo {
	var workers []ServiceWorkerInfo
	timestamp := time.Now().Format("20060102_150405")

	for _, service := range sm.registry.GetActiveServices() {
		backupPath := service.WorkerScript + "." + timestamp + ".bak"

		workers = append(workers, ServiceWorkerInfo{
			ServiceName:  service.Name,
			SourcePath:   service.SourceWorker,
			TargetPath:   service.WorkerScript,
			ServiceFile:  service.ServiceFile,
			Dependencies: service.Dependencies,
			BackupPath:   backupPath,
		})

		// Add dependency workers that need to be updated together
		workers = append(workers, sm.getDependencyWorkers(service, timestamp)...)
	}

	return workers
}
