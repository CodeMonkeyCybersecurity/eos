// pkg/interaction/prompt_string.go
package interaction

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"go.uber.org/zap"
)

const (
	// DefaultPromptTimeout is the maximum time to wait for user input
	DefaultPromptTimeout = 5 * time.Minute

	// Validation constants
	MaxDomainLength = 253  // RFC 1035
	MaxURLLength    = 2048 // Practical limit
	MaxInputLength  = 4096 // General input limit (prevent DoS)
)

// Compiled regex patterns
var (
	// Domain: lowercase alphanumeric + hyphens, must have TLD
	domainRegex = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`)

	// Hostname: lowercase alphanumeric + hyphens, no dots required (for Tailscale)
	hostnameRegex = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

	// Dangerous patterns to reject (shell injection, path traversal)
	dangerousPatterns = []*regexp.Regexp{
		regexp.MustCompile(`[;&|<>$\x60\\]`),                 // Shell metacharacters
		regexp.MustCompile(`\.\./`),                          // Path traversal
		regexp.MustCompile(`\x00`),                           // Null bytes
		regexp.MustCompile(`[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]`), // Control characters
	}
)

// PromptConfig configures prompt behavior
type PromptConfig struct {
	Message      string
	HelpText     string
	DefaultValue string
	Validator    func(string) error
	Timeout      time.Duration
	AllowEmpty   bool
}

// PromptResult contains the result of a prompt
type PromptResult struct {
	Value     string
	Cancelled bool
	TimedOut  bool
}

// PromptString prompts for user input with validation, timeout, and signal handling
func PromptString(rc *eos_io.RuntimeContext, config *PromptConfig) (*PromptResult, error) {
	logger := rc.Log

	// Check if TTY
	if !IsTTY() {
		return nil, fmt.Errorf("cannot prompt in non-interactive mode")
	}

	// Set default timeout
	if config.Timeout == 0 {
		config.Timeout = DefaultPromptTimeout
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(rc.Ctx, config.Timeout)
	defer cancel()

	// Setup signal handler
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigChan)

	// Channels for input
	inputChan := make(chan string, 1)
	errorChan := make(chan error, 1)

	// Display prompt
	displayPrompt(config)

	// Read input in goroutine
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			inputChan <- scanner.Text()
		} else if err := scanner.Err(); err != nil {
			errorChan <- err
		} else {
			errorChan <- fmt.Errorf("EOF")
		}
	}()

	// Wait for input, timeout, or signal
	select {
	case input := <-inputChan:
		result, err := processInput(input, config)
		if err != nil {
			logger.Warn("Input validation failed", zap.Error(err))
			return retryPrompt(rc, config, 1)
		}
		return result, nil

	case err := <-errorChan:
		logger.Error("Error reading input", zap.Error(err))
		return &PromptResult{Cancelled: true}, fmt.Errorf("input error: %w", err)

	case <-ctx.Done():
		logger.Warn("Prompt timed out", zap.Duration("timeout", config.Timeout))
		return &PromptResult{TimedOut: true}, fmt.Errorf("prompt timed out after %v", config.Timeout)

	case sig := <-sigChan:
		logger.Info("Received signal, cancelling prompt", zap.String("signal", sig.String()))
		fmt.Println() // New line after ^C
		return &PromptResult{Cancelled: true}, fmt.Errorf("cancelled by signal: %s", sig)
	}
}

// displayPrompt shows the prompt to the user
func displayPrompt(config *PromptConfig) {
	if config.HelpText != "" {
		fmt.Printf("   %s\n", config.HelpText)
	}

	if config.DefaultValue != "" {
		fmt.Printf("? %s [%s]: ", config.Message, config.DefaultValue)
	} else {
		fmt.Printf("? %s: ", config.Message)
	}
}

// processInput validates and returns the input
func processInput(input string, config *PromptConfig) (*PromptResult, error) {
	// Sanitize input
	input = strings.TrimSpace(input)

	// Check length
	if len(input) > MaxInputLength {
		return nil, fmt.Errorf("input too long (max %d characters)", MaxInputLength)
	}

	// Check for dangerous patterns
	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(input) {
			return nil, fmt.Errorf("input contains invalid characters")
		}
	}

	// If empty, use default or reject
	if input == "" {
		if config.DefaultValue != "" {
			input = config.DefaultValue
		} else if !config.AllowEmpty {
			return nil, fmt.Errorf("input cannot be empty")
		}
	}

	// Run custom validator if provided
	if config.Validator != nil {
		if err := config.Validator(input); err != nil {
			return nil, err
		}
	}

	return &PromptResult{
		Value:     input,
		Cancelled: false,
		TimedOut:  false,
	}, nil
}

// retryPrompt retries the prompt up to maxAttempts times
func retryPrompt(rc *eos_io.RuntimeContext, config *PromptConfig, attempt int) (*PromptResult, error) {
	const maxAttempts = 3

	if attempt >= maxAttempts {
		return &PromptResult{Cancelled: true}, fmt.Errorf("exceeded maximum retry attempts (%d)", maxAttempts)
	}

	fmt.Printf("Invalid input. Please try again (%d/%d)\n", attempt+1, maxAttempts)
	return PromptString(rc, config)
}

// ValidateDomainStrict validates a fully-qualified domain name with strict requirements
func ValidateDomainStrict(domain string) error {
	if len(domain) == 0 {
		return fmt.Errorf("domain cannot be empty")
	}
	if len(domain) > MaxDomainLength {
		return fmt.Errorf("domain too long (max %d characters)", MaxDomainLength)
	}

	domain = strings.ToLower(strings.TrimSpace(domain))

	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("invalid domain format (must be lowercase, alphanumeric, hyphens, with TLD)")
	}

	return nil
}

// ValidateHostnameStrict validates a hostname (for Tailscale, can be simple name)
func ValidateHostnameStrict(hostname string) error {
	if len(hostname) == 0 {
		return fmt.Errorf("hostname cannot be empty")
	}
	if len(hostname) > 63 {
		return fmt.Errorf("hostname too long (max 63 characters)")
	}

	hostname = strings.ToLower(strings.TrimSpace(hostname))

	if !hostnameRegex.MatchString(hostname) {
		return fmt.Errorf("invalid hostname format (must be lowercase, alphanumeric, hyphens only)")
	}

	return nil
}
