package lifecycle

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// Manager defines the interface for component lifecycle management
// All components should implement this interface to provide consistent
// installation, configuration, removal, and discovery capabilities
type Manager interface {
	// Installation and configuration
	Install(rc *eos_io.RuntimeContext, config interface{}) error
	Configure(rc *eos_io.RuntimeContext, config interface{}) error
	Verify(rc *eos_io.RuntimeContext) error
	
	// Removal and cleanup
	Remove(rc *eos_io.RuntimeContext, keepData bool) error
	
	// Discovery methods
	IsInstalled(rc *eos_io.RuntimeContext) bool
	GetName() string
	GetServices() []ServiceInfo
	GetDirectories() []DirectoryInfo
	GetBinaries() []string
	GetAPTSources() []string
	GetSystemdFiles() []string
}

// ServiceInfo represents a service managed by a component
type ServiceInfo struct {
	Name        string
	Component   string
	Required    bool
	Description string
}

// DirectoryInfo represents a directory managed by a component
type DirectoryInfo struct {
	Path        string
	Component   string
	IsData      bool
	Description string
}

// Registry manages all registered lifecycle managers
type Registry struct {
	managers map[string]Manager
}

// NewRegistry creates a new lifecycle manager registry
func NewRegistry() *Registry {
	return &Registry{
		managers: make(map[string]Manager),
	}
}

// Register adds a lifecycle manager to the registry
func (r *Registry) Register(name string, manager Manager) {
	r.managers[name] = manager
}

// Get retrieves a lifecycle manager by name
func (r *Registry) Get(name string) (Manager, bool) {
	manager, exists := r.managers[name]
	return manager, exists
}

// GetAll returns all registered lifecycle managers
func (r *Registry) GetAll() map[string]Manager {
	// Return a copy to prevent external modification
	result := make(map[string]Manager)
	for k, v := range r.managers {
		result[k] = v
	}
	return result
}

// GetAllServices aggregates services from all registered managers
func (r *Registry) GetAllServices(excluded map[string]bool) []ServiceInfo {
	var services []ServiceInfo
	
	for name, manager := range r.managers {
		if excluded[name] {
			continue
		}
		
		for _, svc := range manager.GetServices() {
			if !excluded[svc.Name] {
				services = append(services, svc)
			}
		}
	}
	
	return services
}

// GetAllDirectories aggregates directories from all registered managers
func (r *Registry) GetAllDirectories(excluded map[string]bool, keepData bool) []DirectoryInfo {
	var directories []DirectoryInfo
	
	for name, manager := range r.managers {
		if excluded[name] {
			continue
		}
		
		for _, dir := range manager.GetDirectories() {
			// Skip data directories if keepData is true
			if dir.IsData && keepData {
				continue
			}
			
			directories = append(directories, dir)
		}
	}
	
	return directories
}

// GetAllBinaries aggregates binaries from all registered managers
func (r *Registry) GetAllBinaries(excluded map[string]bool) []string {
	var binaries []string
	
	for name, manager := range r.managers {
		if excluded[name] {
			continue
		}
		
		binaries = append(binaries, manager.GetBinaries()...)
	}
	
	return binaries
}

// GetAllAPTSources aggregates APT sources from all registered managers
func (r *Registry) GetAllAPTSources(excluded map[string]bool) []string {
	var sources []string
	
	for name, manager := range r.managers {
		if excluded[name] {
			continue
		}
		
		sources = append(sources, manager.GetAPTSources()...)
	}
	
	return sources
}

// GetAllSystemdFiles aggregates systemd files from all registered managers
func (r *Registry) GetAllSystemdFiles(excluded map[string]bool) []string {
	var files []string
	
	for name, manager := range r.managers {
		if excluded[name] {
			continue
		}
		
		files = append(files, manager.GetSystemdFiles()...)
	}
	
	return files
}