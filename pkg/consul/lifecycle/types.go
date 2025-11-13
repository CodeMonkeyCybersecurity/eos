// pkg/consul/lifecycle/types.go
// Type definitions for Consul installation lifecycle

package lifecycle

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// NOTE: ConsulConfig and PortConfig types moved to pkg/consul/types.go
// This eliminates duplication identified in P0 fixes.
// Use consul.ConsulConfig and consul.PortConfig instead.

// PreflightCheck represents a pre-installation validation check
type PreflightCheck struct {
	Name        string
	Description string
	Critical    bool
	CheckFunc   func(*eos_io.RuntimeContext) error
}
