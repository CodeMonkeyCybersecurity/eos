package nuke

// ServiceProvider defines the interface for components that provide services
type ServiceProvider interface {
	GetServices() []ServiceConfig
}

// DirectoryProvider defines the interface for components that provide directories
type DirectoryProvider interface {
	GetDirectories() []DirectoryConfig
}

// ComponentProvider combines both interfaces for full component lifecycle
type ComponentProvider interface {
	ServiceProvider
	DirectoryProvider
	GetComponentName() string
}

// AssessmentEngine handles infrastructure assessment with pluggable providers
type AssessmentEngine struct {
	providers []ComponentProvider
}

// NewAssessmentEngine creates a new assessment engine
func NewAssessmentEngine() *AssessmentEngine {
	return &AssessmentEngine{
		providers: make([]ComponentProvider, 0),
	}
}

// RegisterProvider adds a component provider to the engine
func (ae *AssessmentEngine) RegisterProvider(provider ComponentProvider) {
	ae.providers = append(ae.providers, provider)
}

// GetAllServices collects services from all registered providers
func (ae *AssessmentEngine) GetAllServices(excluded map[string]bool) []ServiceConfig {
	serviceMap := make(map[string]ServiceConfig)
	
	for _, provider := range ae.providers {
		for _, svc := range provider.GetServices() {
			if !excluded[svc.Component] && !excluded[svc.Name] {
				serviceMap[svc.Name] = svc
			}
		}
	}
	
	// Convert map to slice
	services := make([]ServiceConfig, 0, len(serviceMap))
	for _, svc := range serviceMap {
		services = append(services, svc)
	}
	
	return services
}

// GetAllDirectories collects directories from all registered providers
func (ae *AssessmentEngine) GetAllDirectories(excluded map[string]bool, keepData bool) []DirectoryConfig {
	var directories []DirectoryConfig
	
	for _, provider := range ae.providers {
		for _, dir := range provider.GetDirectories() {
			// Skip if component is excluded
			if excluded[dir.Component] {
				continue
			}
			
			// Skip data directories if keepData is true
			if dir.IsData && keepData {
				continue
			}
			
			directories = append(directories, dir)
		}
	}
	
	return directories
}
