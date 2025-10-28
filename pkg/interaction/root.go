// pkg/interaction/root.go
package interaction

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RequireRoot checks if running as root and provides helpful message if not.
//
// If the process is not running as root (EUID != 0), this function:
//   - Logs the privilege requirement with structured logging
//   - Shows a user-friendly message with the exact command to re-run with sudo
//   - Returns an error
//
// P0 COMPLIANCE: Uses structured logging (otelzap) instead of fmt.Printf.
// This fixes the P0 violation from pkg/prompt.RequireRoot which used fmt.Printf.
//
// Parameters:
//   - rc: RuntimeContext for structured logging
//   - commandName: Human-readable command name for error messages (e.g., "vault install")
//
// Returns:
//   - nil if running as root
//   - error if not running as root
//
// Example:
//
//	if err := interaction.RequireRoot(rc, "vault install"); err != nil {
//	    return err  // User will see helpful message about using sudo
//	}
func RequireRoot(rc *eos_io.RuntimeContext, commandName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	if os.Geteuid() != 0 {
		logger.Info("Root privileges required",
			zap.String("command", commandName),
			zap.Int("current_uid", os.Geteuid()))

		// User-facing message via structured logging (P0 compliant)
		logger.Info("")
		logger.Info(fmt.Sprintf("The '%s' command requires root privileges.", commandName))
		logger.Info("")
		logger.Info("Please run with sudo:")
		logger.Info(fmt.Sprintf("  sudo %s", strings.Join(os.Args, " ")))
		logger.Info("")

		return fmt.Errorf("this command must be run as root")
	}

	return nil
}
