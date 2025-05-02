// pkg/system/interaction.go
package system

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

func PromptWithFallback(question string) (bool, error) {
	if shared.AutoApprove {
		return true, nil
	} else if !IsInteractive() {
		return false, fmt.Errorf("non-interactive session; use --yes")
	} else {
		fmt.Print(question)
		var input string
		if _, err := fmt.Scanln(&input); err != nil {
			return false, fmt.Errorf("failed to read input: %w", err)
		}
		return input == "y" || input == "Y", nil
	}
}

// IsInteractive returns true if stdin is connected to a terminal.
func IsInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false // fallback to non-interactive
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// CheckBasicSudo runs 'sudo -n true' to check if we have non-interactive sudo.
func CheckNonInteractiveSudo() error {
	cmd := exec.Command("sudo", "-n", "true")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sudo check failed: %w. Please ensure you have sudo access", err)
	}
	return nil
}
