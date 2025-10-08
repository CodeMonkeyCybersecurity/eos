// pkg/consul/validation/prerequisites.go
// System prerequisites validation for Consul installation

package validation

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PrerequisitesValidator validates system prerequisites for Consul installation
type PrerequisitesValidator struct {
	rc            *eos_io.RuntimeContext
	logger        otelzap.LoggerWithCtx
	resourceCheck *ResourceValidator
	portCheck     *PortValidator
	securityCheck *SecurityValidator
}

// NewPrerequisitesValidator creates a new prerequisites validator
func NewPrerequisitesValidator(rc *eos_io.RuntimeContext) *PrerequisitesValidator {
	return &PrerequisitesValidator{
		rc:            rc,
		logger:        otelzap.Ctx(rc.Ctx),
		resourceCheck: NewResourceValidator(rc),
		portCheck:     NewPortValidator(rc),
		securityCheck: NewSecurityValidator(rc),
	}
}

// ValidateAll performs all prerequisite checks
func (pv *PrerequisitesValidator) ValidateAll(requiredPorts []int) error {
	pv.logger.Info("Validating system prerequisites")

	// Create context with timeout for all checks
	ctx, cancel := context.WithTimeout(pv.rc.Ctx, 30*time.Second)
	defer cancel()

	// Check if running as root
	if err := pv.checkRoot(); err != nil {
		return err
	}

	// Check memory requirements
	if err := pv.resourceCheck.CheckMemory(ctx, 256); err != nil {
		return fmt.Errorf("memory check failed: %w", err)
	}

	// Check disk space
	if err := pv.resourceCheck.CheckDiskSpace(ctx, "/var/lib", 100); err != nil {
		return fmt.Errorf("disk space check failed: %w", err)
	}

	// Check port availability
	if err := pv.portCheck.CheckPorts(requiredPorts); err != nil {
		return fmt.Errorf("port availability check failed: %w", err)
	}

	// Check security modules (non-fatal, just warnings)
	pv.securityCheck.CheckSecurityModules()

	pv.logger.Info("All prerequisite checks passed")
	return nil
}

// checkRoot verifies the process is running as root
func (pv *PrerequisitesValidator) checkRoot() error {
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("this command must be run as root")
	}
	return nil
}

// ValidateConfig validates Consul configuration parameters
func (pv *PrerequisitesValidator) ValidateConfig(version, datacenter, bindAddr string) error {
	pv.logger.Info("Validating configuration parameters")

	if version == "" {
		return eos_err.NewUserError("consul version must be specified")
	}

	if datacenter == "" {
		return eos_err.NewUserError("datacenter name must be specified")
	}

	if bindAddr == "" {
		return eos_err.NewUserError("bind address must be specified")
	}

	// Validate bind address is not loopback
	if strings.HasPrefix(bindAddr, "127.") {
		pv.logger.Warn("Bind address is loopback - Consul will not be accessible from other nodes",
			zap.String("bind_addr", bindAddr))
	}

	pv.logger.Info("Configuration validation passed")
	return nil
}
