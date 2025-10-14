// Package orchestrator provides Vault orchestration utilities
package orchestrator

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DisplayOrchestrationResult displays the orchestration results for Vault installation
func DisplayOrchestrationResult(rc *eos_io.RuntimeContext, result *OrchestrationResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Vault orchestration completed",
		zap.String("mode", string(result.Mode)),
		zap.Bool("success", result.Success),
		zap.Duration("duration", result.Duration))

	fmt.Printf("\n🏛️  Vault Installation Result\n")
	fmt.Printf("============================\n")
	fmt.Printf("Mode: %s\n", result.Mode)
	fmt.Printf("Status: ")
	if result.Success {
		fmt.Printf(" SUCCESS\n")
	} else {
		fmt.Printf(" FAILED\n")
	}
	fmt.Printf("Duration: %s\n", result.Duration)
	if result.Message != "" {
		fmt.Printf("Message: %s\n", result.Message)
	}

	if result.Mode == ModeNomad && result.Success {
		fmt.Printf("\n Next Steps:\n")
		fmt.Printf("   • Check Vault status: nomad job status vault\n")
		fmt.Printf("   • Initialize Vault: vault operator init\n")
		fmt.Printf("   • Unseal Vault: vault operator unseal\n")
		fmt.Printf("   • View logs: nomad alloc logs <alloc-id>\n")
	}

	return nil
}
