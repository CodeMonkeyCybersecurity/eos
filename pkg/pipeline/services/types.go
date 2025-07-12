package services

// ServiceStatus represents systemd service status information
// Migrated from cmd/read/pipeline_services.go ServiceStatus
type ServiceStatus struct {
	Status  string
	Active  string
	Enabled string
	Uptime  string
}

// FileInfo represents file information
// Migrated from cmd/read/pipeline_services.go FileInfo
type FileInfo struct {
	Permissions string
	Size        string
	Modified    string
}
