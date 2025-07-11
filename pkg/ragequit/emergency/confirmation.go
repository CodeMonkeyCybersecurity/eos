package emergency

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConfirmRagequit prompts user for confirmation before ragequit
// Migrated from cmd/ragequit/ragequit.go confirmRagequit
func ConfirmRagequit(rc *eos_io.RuntimeContext, config *ragequit.Config) bool {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Check if we should skip confirmation
	logger.Info("Assessing ragequit confirmation requirements",
		zap.Bool("force", config.Force))
	
	if config.Force {
		logger.Warn("Force flag set, skipping confirmation")
		return true
	}
	
	// INTERVENE - Display warning and get confirmation
	fmt.Print(" EMERGENCY RAGEQUIT \n")
	fmt.Print("This will:\n")
	fmt.Print("1. Collect comprehensive system diagnostics\n")
	fmt.Print("2. Create emergency backup files\n")
	if !config.NoReboot {
		fmt.Print("3. REBOOT THE SYSTEM IMMEDIATELY\n")
	}
	fmt.Print("\nAre you sure you want to continue? (yes/no): ")
	
	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		logger.Error("Failed to read user input", zap.Error(err))
		return false
	}
	
	// EVALUATE - Check response
	response = strings.TrimSpace(strings.ToLower(response))
	confirmed := response == "yes" || response == "y"
	
	logger.Info("Ragequit confirmation result",
		zap.Bool("confirmed", confirmed),
		zap.String("response", response))
	
	return confirmed
}