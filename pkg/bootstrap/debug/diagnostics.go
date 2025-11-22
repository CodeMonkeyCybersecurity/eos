// pkg/bootstrap/debug/diagnostics.go
package debug

import (
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// RunDiagnostics performs comprehensive bootstrap diagnostics
// Follows Assess → Intervene → Evaluate pattern
func RunDiagnostics(rc *eos_io.RuntimeContext, config *DiagnosticConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting comprehensive bootstrap diagnostics")

	// ASSESS: Gather all diagnostic information
	result := BootstrapDebugResult{
		Timestamp: time.Now(),
	}

	result.SystemCheck = CheckSystemInfo(rc)
	result.PrerequisitesCheck = CheckBootstrapPrerequisites(rc)
	result.StateCheck = CheckBootstrapState(rc)
	result.LockCheck = CheckBootstrapLocks(rc)
	result.ServicesCheck = CheckInfraServices(rc)
	result.PortsCheck = CheckInfraPorts(rc)
	result.NetworkCheck = CheckNetworkConfig(rc)
	result.ResourcesCheck = CheckSystemResources(rc)
	result.PhaseCheck = CheckBootstrapPhases(rc)
	result.PreviousAttemptsCheck = CheckPreviousAttempts(rc)

	// INTERVENE: Not applicable for diagnostics - this is read-only
	// (We don't modify system state, only report on it)

	// EVALUATE: Display results and generate recommendations
	PrintBootstrapDebugResults(rc, result)

	// Generate summary and recommendations
	result.Summary = GenerateBootstrapSummary(result)
	logger.Info("terminal prompt: " + strings.Repeat("=", 80))
	logger.Info("terminal prompt: SUMMARY AND RECOMMENDATIONS")
	logger.Info("terminal prompt: " + strings.Repeat("=", 80))
	for _, line := range strings.Split(result.Summary, "\n") {
		if line != "" {
			logger.Info("terminal prompt: " + line)
		}
	}

	return nil
}
