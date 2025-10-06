// Package prompt provides interactive prompt utilities
package prompt

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// YesNo prompts the user with a yes/no question and returns true for yes
func YesNo(rc *eos_io.RuntimeContext, question string, defaultYes bool) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	prompt := question
	if defaultYes {
		prompt += " [Y/n]: "
	} else {
		prompt += " [y/N]: "
	}

	fmt.Print(prompt)

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		logger.Error("Failed to read user input", zap.Error(err))
		return false, fmt.Errorf("failed to read input: %w", err)
	}

	response = strings.TrimSpace(strings.ToLower(response))

	// Handle empty response (use default)
	if response == "" {
		return defaultYes, nil
	}

	// Check for yes responses
	return response == "y" || response == "yes", nil
}

// RequireRoot checks if running as root and provides helpful message if not
func RequireRoot(rc *eos_io.RuntimeContext, commandName string) error {
	if os.Geteuid() != 0 {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Root privileges required",
			zap.String("command", commandName),
			zap.Int("current_uid", os.Geteuid()))

		fmt.Printf("\nThe '%s' command requires root privileges.\n", commandName)
		fmt.Println("\nPlease run with sudo:")
		fmt.Printf("  sudo %s\n\n", strings.Join(os.Args, " "))

		return fmt.Errorf("this command must be run as root")
	}
	return nil
}

// CheckDependency checks if a command exists in PATH
func CheckDependency(command string) bool {
	_, err := exec.LookPath(command)
	return err == nil
}

// PromptInstallDependency prompts user to install a missing dependency
func PromptInstallDependency(rc *eos_io.RuntimeContext, depName, depDescription string, installFunc func() error) error {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Printf("\nRequired dependency '%s' is not installed.\n", depName)
	if depDescription != "" {
		fmt.Printf("   %s\n", depDescription)
	}

	install, err := YesNo(rc, fmt.Sprintf("\nWould you like to install %s now?", depName), true)
	if err != nil {
		return err
	}

	if !install {
		fmt.Printf("\n❌ %s is required for this command. Please install it manually and try again.\n", depName)
		fmt.Printf("   For more information, visit: https://github.com/CodeMonkeyCybersecurity/eos/wiki/dependencies\n\n")
		return fmt.Errorf("%s is required but not installed", depName)
	}

	// User wants to install
	fmt.Printf("\n📦 Installing %s...\n", depName)
	logger.Info("Installing dependency", zap.String("dependency", depName))

	if err := installFunc(); err != nil {
		fmt.Printf("\n❌ Failed to install %s: %v\n", depName, err)
		fmt.Printf("   Please install it manually and try again.\n\n")
		return fmt.Errorf("failed to install %s: %w", depName, err)
	}

	fmt.Printf("\n Successfully installed %s!\n", depName)
	return nil
}
