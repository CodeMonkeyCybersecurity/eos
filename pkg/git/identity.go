// pkg/git/identity.go
//
// Interactive git identity configuration - human-centric fallback pattern
// Implements P0 #13: Required Flag Prompting with informed consent

package git

import (
	"bufio"
	"context"
	"fmt"
	"net/mail"
	"os"
	"os/exec"
	"strings"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConfigureGitIdentityInteractive prompts user to configure git identity if missing
// HUMAN-CENTRIC (P0 #13): Offers interactive fallback instead of hard failure
//
// Philosophy: "Technology serves humans, not the other way around"
// Missing git identity is a barrier to entry that we can help solve.
//
// Returns:
// - true if identity is now configured (either was already set or user configured it)
// - false if user declined or non-interactive mode
// - error only on unexpected failures
func ConfigureGitIdentityInteractive(ctx context.Context, nonInteractive bool) (bool, error) {
	logger := otelzap.Ctx(ctx)

	// Check if identity is already configured
	userName, nameErr := getGitConfig(ctx, "user.name", true)
	userEmail, emailErr := getGitConfig(ctx, "user.email", true)

	userName = strings.TrimSpace(userName)
	userEmail = strings.TrimSpace(userEmail)

	// Validate what we have
	nameOK := nameErr == nil && userName != ""
	emailOK := emailErr == nil && userEmail != ""

	if emailOK {
		// Validate email format
		if _, err := mail.ParseAddress(userEmail); err != nil {
			emailOK = false
		}
	}

	// Already configured correctly
	if nameOK && emailOK {
		logger.Debug("Git identity already configured",
			zap.String("user.name", userName),
			zap.String("user.email", userEmail))
		return true, nil
	}

	// Non-interactive mode - can't prompt
	if nonInteractive {
		logger.Warn("Git identity not configured and non-interactive mode enabled")
		return false, nil
	}

	// Check if we have a TTY to prompt on
	if !isTerminal() {
		logger.Warn("Git identity not configured and no TTY available for prompting")
		return false, nil
	}

	// Interactive fallback - explain WHY and offer to configure
	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("Git Identity Configuration Required")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()
	fmt.Println("Git requires both user.name and user.email to create commits.")
	fmt.Println("This information will be recorded in each commit you make.")
	fmt.Println()

	if !nameOK && !emailOK {
		fmt.Println("Status: Neither user.name nor user.email is configured")
	} else if !nameOK {
		fmt.Printf("Status: user.email is set to '%s', but user.name is missing\n", userEmail)
	} else if !emailOK {
		if userEmail == "" {
			fmt.Printf("Status: user.name is set to '%s', but user.email is missing\n", userName)
		} else {
			fmt.Printf("Status: user.name is set to '%s', but user.email '%s' is invalid\n", userName, userEmail)
		}
	}

	fmt.Println()
	fmt.Println("Would you like to configure your git identity now? [Y/n]: ")

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("failed to read user response: %w", err)
	}

	response = strings.TrimSpace(strings.ToLower(response))
	if response != "" && response != "y" && response != "yes" {
		fmt.Println()
		fmt.Println("Git identity configuration declined.")
		fmt.Println("You can configure it later with:")
		fmt.Println("  git config --global user.name \"Your Name\"")
		fmt.Println("  git config --global user.email \"your.email@example.com\"")
		fmt.Println()
		return false, nil
	}

	// Prompt for user.name if needed
	if !nameOK {
		fmt.Println()
		fmt.Println("Enter your name (this will appear in git commits):")
		fmt.Print("Name: ")
		userName, err = reader.ReadString('\n')
		if err != nil {
			return false, fmt.Errorf("failed to read name: %w", err)
		}
		userName = strings.TrimSpace(userName)

		if userName == "" {
			fmt.Println("Error: Name cannot be empty")
			return false, nil
		}

		// Set user.name globally
		cmd := exec.CommandContext(ctx, "git", "config", "--global", "user.name", userName)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return false, fmt.Errorf("failed to set user.name: %w\nOutput: %s", err, string(output))
		}

		logger.Info("Configured git user.name", zap.String("value", userName))
	}

	// Prompt for user.email if needed
	if !emailOK {
		fmt.Println()
		fmt.Println("Enter your email address (this will appear in git commits):")
		fmt.Print("Email: ")

		maxAttempts := 3
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			userEmail, err = reader.ReadString('\n')
			if err != nil {
				return false, fmt.Errorf("failed to read email: %w", err)
			}
			userEmail = strings.TrimSpace(userEmail)

			if userEmail == "" {
				fmt.Println("Error: Email cannot be empty")
				if attempt < maxAttempts {
					fmt.Print("Email: ")
					continue
				}
				return false, nil
			}

			// Validate email format (RFC 5322)
			if _, err := mail.ParseAddress(userEmail); err != nil {
				fmt.Printf("Error: '%s' is not a valid email address\n", userEmail)
				if attempt < maxAttempts {
					fmt.Print("Email: ")
					continue
				}
				return false, nil
			}

			// Valid email - break out of retry loop
			break
		}

		// Set user.email globally
		cmd := exec.CommandContext(ctx, "git", "config", "--global", "user.email", userEmail)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return false, fmt.Errorf("failed to set user.email: %w\nOutput: %s", err, string(output))
		}

		logger.Info("Configured git user.email", zap.String("value", userEmail))
	}

	// Success!
	fmt.Println()
	fmt.Println("✓ Git identity configured successfully!")
	fmt.Printf("  user.name:  %s\n", userName)
	fmt.Printf("  user.email: %s\n", userEmail)
	fmt.Println()
	fmt.Println("These settings are saved in: ~/.gitconfig")
	fmt.Println()

	logger.Info("Git identity configured interactively",
		zap.String("user.name", userName),
		zap.String("user.email", userEmail))

	return true, nil
}

// isTerminal checks if stdin is connected to a terminal
func isTerminal() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}
