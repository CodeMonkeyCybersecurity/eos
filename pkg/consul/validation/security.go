// pkg/consul/validation/security.go
// Security module validation (SELinux, AppArmor)

package validation

import (
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SecurityValidator validates security modules that might interfere with Consul
type SecurityValidator struct {
	rc     *eos_io.RuntimeContext
	logger otelzap.LoggerWithCtx
}

// NewSecurityValidator creates a new security validator
func NewSecurityValidator(rc *eos_io.RuntimeContext) *SecurityValidator {
	return &SecurityValidator{
		rc:     rc,
		logger: otelzap.Ctx(rc.Ctx),
	}
}

// CheckSecurityModules detects SELinux/AppArmor and warns if they might interfere
func (sv *SecurityValidator) CheckSecurityModules() {
	sv.logger.Info("Checking security modules")

	sv.checkSELinux()
	sv.checkAppArmor()
}

// checkSELinux checks SELinux status and warns if it might block Consul
func (sv *SecurityValidator) checkSELinux() {
	cmd := exec.Command("getenforce")
	output, err := cmd.Output()
	if err != nil {
		// SELinux not installed or not available
		return
	}

	mode := strings.ToLower(strings.TrimSpace(string(output)))
	if mode == "enforcing" {
		sv.logger.Warn("SELinux is in enforcing mode - may block Consul operations",
			zap.String("selinux_mode", mode),
			zap.String("remediation", "If Consul fails, check: ausearch -m AVC -ts recent | grep consul"))

		// Check for consul-related denials in audit log
		denialsCmd := exec.Command("sh", "-c", "ausearch -m AVC -ts recent 2>/dev/null | grep -i consul | tail -5")
		denials, err := denialsCmd.Output()
		if err == nil && len(denials) > 0 {
			sv.logger.Error("SELinux has denied Consul operations recently",
				zap.String("recent_denials", string(denials)),
				zap.String("fix", "Run: setenforce 0 (temporarily) or create SELinux policy"))
		}
	} else if mode == "permissive" {
		sv.logger.Info("SELinux is in permissive mode (will log but not block)")
	}
}

// checkAppArmor checks AppArmor status and warns if profiles exist for Consul
func (sv *SecurityValidator) checkAppArmor() {
	cmd := exec.Command("sh", "-c", "aa-status 2>/dev/null | grep -i consul")
	output, err := cmd.Output()
	if err != nil || len(output) == 0 {
		// No AppArmor profiles for Consul
		return
	}

	sv.logger.Warn("AppArmor profile detected for Consul",
		zap.String("profile", string(output)),
		zap.String("remediation", "If Consul fails, check: dmesg | grep -i apparmor | grep consul"))
}
