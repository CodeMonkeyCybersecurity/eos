package shared

// ServiceRegistryInterface defines the interface for service registry operations
type ServiceRegistryInterface interface {
	GetService(name string) (WazuhServiceDefinition, bool)
	GetActiveServices() map[string]WazuhServiceDefinition
	GetActiveServiceNames() []string
	CheckServiceInstallationStatus(serviceName string) (ServiceInstallationStatus, error)
}
