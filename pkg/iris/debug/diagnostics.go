// pkg/iris/debug/diagnostics.go
package debug

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// RunDiagnostics executes all Iris diagnostic checks and displays the results
// Follows Assess → Intervene → Evaluate pattern
func RunDiagnostics(rc *eos_io.RuntimeContext, config *DiagnosticConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Starting Iris diagnostic checks")

	// ASSESS: Run all diagnostic checks
	results := assessIrisHealth(rc, config)

	// INTERVENE: Test alert if requested (optional intervention)
	if config.TestAlert {
		performTestAlert(rc, results)
	}

	// EVALUATE: Display results to user
	DisplayDiagnosticResults(results, config.Verbose)

	// Diagnostics are informational, not errors
	// Always return nil (exit 0) - the display shows what passed/failed
	// Only return error for actual system failures (can't connect, etc.)
	return nil
}

// assessIrisHealth runs all diagnostic checks and returns results
// ASSESS phase: Gather information about system state
func assessIrisHealth(rc *eos_io.RuntimeContext, config *DiagnosticConfig) []CheckResult {
	var results []CheckResult

	// Load configuration first (needed by other checks)
	irisConfig, configResult := CheckConfiguration(rc, config.ProjectDir, config.Verbose)

	// Infrastructure checks
	results = append(results, CheckProjectStructure(rc, config.ProjectDir, config.Verbose))
	results = append(results, CheckTemporalCLI(rc))
	results = append(results, CheckBinaryAccessibility(rc))
	results = append(results, CheckPortStatus(rc, irisConfig))
	results = append(results, CheckTemporalServerHealth(rc, irisConfig))

	// Configuration checks
	results = append(results, configResult)
	results = append(results, CheckAzureOpenAI(rc, irisConfig))
	results = append(results, CheckSMTPConfig(rc, irisConfig))

	// Services checks
	results = append(results, CheckSystemdServices(rc))
	results = append(results, CheckWorkerProcessHealth(rc))
	results = append(results, CheckWebhookServerHealth(rc, irisConfig))
	results = append(results, CheckRecentWorkflows(rc, irisConfig))

	// System checks
	results = append(results, CheckGoDependencies(rc, config.ProjectDir))

	return results
}

// performTestAlert sends a test alert through the system
// INTERVENE phase: Optionally trigger test workflow
func performTestAlert(rc *eos_io.RuntimeContext, results []CheckResult) {
	// Find the config from results
	var irisConfig *IrisConfig
	for _, r := range results {
		if r.Name == "Configuration File" && r.Passed {
			// Config was loaded successfully, we can send test alert
			// Re-load config for test alert (not ideal but safe)
			cfg, _ := CheckConfiguration(rc, "/opt/iris", false)
			irisConfig = cfg
			break
		}
	}

	fmt.Println("\n╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                      SENDING TEST ALERT                        ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	if err := SendTestAlert(rc, irisConfig); err != nil {
		fmt.Printf("✗ Test alert failed: %v\n", err)
		fmt.Println("\nRemediation:")
		fmt.Println("  • Ensure webhook server is running")
		fmt.Println("  • Check webhook logs for errors")
		fmt.Println("  • Verify Temporal server is accessible")
		return
	}

	fmt.Println("✓ Test alert sent successfully")
	fmt.Println()
	fmt.Println("Next Steps:")
	fmt.Println("  1. Check Temporal UI at http://localhost:8233")
	fmt.Println("  2. Verify workflow execution completed")
	fmt.Println("  3. Check email inbox for alert notification")
}
