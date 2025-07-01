package shared

// ServiceRegistryInterface defines the interface for service registry operations
type ServiceRegistryInterface interface {
	GetService(name string) (DelphiServiceDefinition, bool)
	GetActiveServices() map[string]DelphiServiceDefinition
	GetActiveServiceNames() []string
	CheckServiceInstallationStatus(serviceName string) (ServiceInstallationStatus, error)
}