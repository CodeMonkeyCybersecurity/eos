// Package orchestrator provides Vault orchestration utilities
package orchestrator

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack/orchestrator"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DisplayOrchestrationResult displays the orchestration results for Vault installation
func DisplayOrchestrationResult(rc *eos_io.RuntimeContext, result *orchestrator.OrchestrationResult) error {
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
		fmt.Printf("✅ SUCCESS\n")
	} else {
		fmt.Printf("❌ FAILED\n")
	}
	fmt.Printf("Duration: %s\n", result.Duration)
	fmt.Printf("Message: %s\n", result.Message)

	if result.JobID != "" {
		fmt.Printf("Salt Job ID: %s\n", result.JobID)
	}

	if len(result.Minions) > 0 {
		fmt.Printf("\n🎯 Target Minions (%d):\n", len(result.Minions))
		for _, minion := range result.Minions {
			fmt.Printf("   • %s\n", minion)
		}
	}

	if len(result.Failed) > 0 {
		fmt.Printf("\n❌ Failed Minions (%d):\n", len(result.Failed))
		for _, minion := range result.Failed {
			fmt.Printf("   • %s\n", minion)
		}
	}

	if result.Mode == orchestrator.OrchestrationModeSalt && result.Success {
		fmt.Printf("\n💡 Next Steps:\n")
		fmt.Printf("   • Check Vault status: eos salt run '%s' vault.status\n", "vault-*")
		fmt.Printf("   • Initialize Vault: eos salt run '%s' vault.init\n", "vault-*")
		fmt.Printf("   • Unseal Vault: eos salt run '%s' vault.unseal\n", "vault-*")
		fmt.Printf("   • View logs: eos salt run '%s' cmd.run 'journalctl -u vault -f'\n", "vault-*")
	}

	return nil
}
