/* pkg/delphi/dashboard/module.go */

package dashboard

import (
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
)

// ModuleType represents different dashboard module types
type ModuleType int

const (
	ModulePipeline ModuleType = iota
	ModuleServices
	ModuleParsers
	ModuleAlerts
	ModulePerformance
	ModuleOverview
)

// String returns the human-readable name for module types
func (m ModuleType) String() string {
	switch m {
	case ModulePipeline:
		return "Pipeline"
	case ModuleServices:
		return "Services"
	case ModuleParsers:
		return "Parsers"
	case ModuleAlerts:
		return "Alerts"
	case ModulePerformance:
		return "Performance"
	case ModuleOverview:
		return "Overview"
	default:
		return "Unknown"
	}
}

// DashboardModule interface defines the contract all dashboard modules must implement
type DashboardModule interface {
	// Module identity
	Name() string
	Type() ModuleType
	Description() string
	
	// Bubble Tea lifecycle
	Init() tea.Cmd
	Update(tea.Msg) (DashboardModule, tea.Cmd)
	View() string
	
	// Navigation and keyboard controls
	KeyMap() []key.Binding
	ShortHelp() []key.Binding
	FullHelp() [][]key.Binding
	
	// Module lifecycle
	OnEnter() tea.Cmd   // Called when module becomes active
	OnExit() tea.Cmd    // Called when leaving module
	OnResize(width, height int)
	
	// Status and health
	IsHealthy() bool
	GetStatus() string
	GetLastError() error
	
	// Data refresh
	Refresh() tea.Cmd
	CanRefresh() bool
}

// BaseModule provides common functionality for all dashboard modules
type BaseModule struct {
	name        string
	moduleType  ModuleType
	description string
	width       int
	height      int
	active      bool
	lastError   error
}

// NewBaseModule creates a new base module
func NewBaseModule(name string, moduleType ModuleType, description string) BaseModule {
	return BaseModule{
		name:        name,
		moduleType:  moduleType,
		description: description,
		active:      false,
	}
}

// Name returns the module name
func (m BaseModule) Name() string {
	return m.name
}

// Type returns the module type
func (m BaseModule) Type() ModuleType {
	return m.moduleType
}

// Description returns the module description
func (m BaseModule) Description() string {
	return m.description
}

// OnResize handles terminal resize events
func (m *BaseModule) OnResize(width, height int) {
	m.width = width
	m.height = height
}

// SetActive marks the module as active/inactive
func (m *BaseModule) SetActive(active bool) {
	m.active = active
}

// IsActive returns whether the module is currently active
func (m BaseModule) IsActive() bool {
	return m.active
}

// SetLastError sets the last error encountered
func (m *BaseModule) SetLastError(err error) {
	m.lastError = err
}

// GetLastError returns the last error encountered
func (m BaseModule) GetLastError() error {
	return m.lastError
}

// IsHealthy returns whether the module is healthy (no recent errors)
func (m BaseModule) IsHealthy() bool {
	return m.lastError == nil
}

// GetStatus returns a string representation of module status
func (m BaseModule) GetStatus() string {
	if m.lastError != nil {
		return "Error"
	}
	if m.active {
		return "Active"
	}
	return "Inactive"
}

// Dimensions returns current width and height
func (m BaseModule) Dimensions() (int, int) {
	return m.width, m.height
}

// ModuleRegistry manages available dashboard modules
type ModuleRegistry struct {
	modules map[ModuleType]DashboardModule
	order   []ModuleType
}

// NewModuleRegistry creates a new module registry
func NewModuleRegistry() *ModuleRegistry {
	return &ModuleRegistry{
		modules: make(map[ModuleType]DashboardModule),
		order:   []ModuleType{},
	}
}

// Register adds a module to the registry
func (r *ModuleRegistry) Register(module DashboardModule) {
	moduleType := module.Type()
	r.modules[moduleType] = module
	
	// Add to order if not already present
	for _, existing := range r.order {
		if existing == moduleType {
			return
		}
	}
	r.order = append(r.order, moduleType)
}

// Get retrieves a module by type
func (r *ModuleRegistry) Get(moduleType ModuleType) (DashboardModule, bool) {
	module, exists := r.modules[moduleType]
	return module, exists
}

// GetByName retrieves a module by name
func (r *ModuleRegistry) GetByName(name string) (DashboardModule, bool) {
	for _, module := range r.modules {
		if module.Name() == name {
			return module, true
		}
	}
	return nil, false
}

// List returns all registered modules in order
func (r *ModuleRegistry) List() []DashboardModule {
	modules := make([]DashboardModule, 0, len(r.order))
	for _, moduleType := range r.order {
		if module, exists := r.modules[moduleType]; exists {
			modules = append(modules, module)
		}
	}
	return modules
}

// GetOrder returns the module types in registration order
func (r *ModuleRegistry) GetOrder() []ModuleType {
	return append([]ModuleType{}, r.order...)
}

// Count returns the number of registered modules
func (r *ModuleRegistry) Count() int {
	return len(r.modules)
}

// NextModule returns the next module in order after the given type
func (r *ModuleRegistry) NextModule(current ModuleType) ModuleType {
	for i, moduleType := range r.order {
		if moduleType == current {
			if i+1 < len(r.order) {
				return r.order[i+1]
			}
			return r.order[0] // Wrap to first
		}
	}
	return current
}

// PrevModule returns the previous module in order before the given type
func (r *ModuleRegistry) PrevModule(current ModuleType) ModuleType {
	for i, moduleType := range r.order {
		if moduleType == current {
			if i > 0 {
				return r.order[i-1]
			}
			return r.order[len(r.order)-1] // Wrap to last
		}
	}
	return current
}