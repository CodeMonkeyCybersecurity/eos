package lifecycle

import (
	"sync"
)

var (
	globalRegistry *Registry
	registryOnce   sync.Once
)

// GetGlobalRegistry returns the global lifecycle manager registry
// This ensures a single registry instance throughout the application
func GetGlobalRegistry() *Registry {
	registryOnce.Do(func() {
		globalRegistry = NewRegistry()
	})
	return globalRegistry
}

// RegisterGlobal registers a lifecycle manager in the global registry
func RegisterGlobal(name string, manager Manager) {
	GetGlobalRegistry().Register(name, manager)
}