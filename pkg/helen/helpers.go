// pkg/helen/helpers.go
// Helper functions for Helen deployments

package helen

import (
	"fmt"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// CheckPrerequisites verifies all requirements for static Helen deployment
func CheckPrerequisites(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Checking prerequisites for Helen deployment")
	
	// Check if Vault is available
	if _, err := exec.LookPath("vault"); err != nil {
		return fmt.Errorf("vault CLI not found. Deploy with: eos create vault")
	}
	
	// Check if Nomad is available
	if _, err := exec.LookPath("nomad"); err != nil {
		return fmt.Errorf("nomad CLI not found. Deploy with: eos create nomad")
	}
	
	// Check if Consul is available (optional but recommended)
	if _, err := exec.LookPath("consul"); err != nil {
		logger.Warn("Consul not found. Service discovery will be limited")
	}
	
	// TODO: Check if services are actually running, not just installed
	// This would involve checking service health via their APIs
	
	logger.Info("All prerequisites satisfied")
	return nil
}