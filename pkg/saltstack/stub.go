// Package saltstack provides backward compatibility stubs for SaltStack functionality
// This package is deprecated in favor of the HashiCorp stack (Nomad, Consul, Vault)
package saltstack

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// RemoveSaltCompletely is a stub for backward compatibility
func RemoveSaltCompletely(rc *eos_io.RuntimeContext, keepData bool) error {
	return fmt.Errorf("SaltStack functionality has been migrated to HashiCorp stack - this is a compatibility stub")
}

// Manager is a deprecated stub for SaltStack manager
type Manager struct{}

// NewManager creates a deprecated stub manager
func NewManager() *Manager {
	return &Manager{}
}

// Apply is a deprecated stub method
func (m *Manager) Apply(rc *eos_io.RuntimeContext, target string, states []string) error {
	return fmt.Errorf("SaltStack functionality has been migrated to HashiCorp stack")
}

// Config is a deprecated stub for SaltStack configuration
type Config struct {
	MasterAddr string
	MinionID   string
}

// DefaultConfig returns a deprecated stub configuration
func DefaultConfig() *Config {
	return &Config{
		MasterAddr: "deprecated",
		MinionID:   "deprecated",
	}
}
