// Package preflight provides pre-installation checks for services
// following Eos P0 architecture patterns and defensive validation.
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."
package preflight

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"syscall"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Check represents a single preflight check
type Check struct {
	Name        string
	Description string
	Check       func(context.Context) error
	Required    bool
}

// CheckResult contains the result of running preflight checks
type CheckResult struct {
	Name    string
	Passed  bool
	Error   error
	Warning string
}

// RunChecks executes all preflight checks and returns results
// Following Assess → Intervene → Evaluate pattern
func RunChecks(ctx context.Context, checks []Check) ([]CheckResult, error) {
	logger := otelzap.Ctx(ctx)

	logger.Info("=== ASSESS PHASE: Running preflight checks ===",
		zap.Int("total_checks", len(checks)))

	results := make([]CheckResult, 0, len(checks))
	criticalFailures := 0

	for _, check := range checks {
		logger.Debug("Running check", zap.String("check", check.Name))

		result := CheckResult{
			Name:   check.Name,
			Passed: false,
		}

		// Run the check with timeout
		checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := check.Check(checkCtx)
		cancel()

		if err != nil {
			result.Error = err
			if check.Required {
				logger.Error("✗ Check failed (REQUIRED)",
					zap.String("check", check.Name),
					zap.Error(err))
				criticalFailures++
			} else {
				logger.Warn("⚠ Check failed (optional)",
					zap.String("check", check.Name),
					zap.Error(err))
				result.Warning = err.Error()
			}
		} else {
			result.Passed = true
			logger.Info("✓ Check passed", zap.String("check", check.Name))
		}

		results = append(results, result)
	}

	if criticalFailures > 0 {
		return results, fmt.Errorf("%d required check(s) failed", criticalFailures)
	}

	logger.Info("=== EVALUATE: All required checks passed ===")
	return results, nil
}

// CheckDocker verifies Docker daemon is accessible
func CheckDocker(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker", "info")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Docker is not running or not accessible: %w\n"+
			"Output: %s\n"+
			"Fix: Install Docker or start the Docker daemon:\n"+
			"  Ubuntu: sudo systemctl start docker\n"+
			"  Or visit: https://docs.docker.com/engine/install/ubuntu/",
			err, string(output))
	}
	return nil
}

// CheckDockerCompose verifies Docker Compose is available
func CheckDockerCompose(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker", "compose", "version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Docker Compose is not available: %w\n"+
			"Output: %s\n"+
			"Fix: Install Docker Compose V2:\n"+
			"  Ubuntu: sudo apt install docker-compose-plugin",
			err, string(output))
	}
	return nil
}

// CheckPort verifies a port is available for binding
func CheckPort(port int) func(context.Context) error {
	return func(ctx context.Context) error {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			return fmt.Errorf("port %d is already in use\n"+
				"Fix: Stop the service using this port:\n"+
				"  sudo lsof -i :%d\n"+
				"  sudo kill <pid>\n"+
				"Or choose a different port with --port",
				port, port)
		}
		ln.Close()
		return nil
	}
}

// CheckDiskSpace verifies minimum disk space is available
func CheckDiskSpace(minGB int) func(context.Context) error {
	return func(ctx context.Context) error {
		var stat syscall.Statfs_t
		if err := syscall.Statfs("/", &stat); err != nil {
			return fmt.Errorf("failed to check disk space: %w", err)
		}

		// Calculate available space in GB
		availableGB := (stat.Bavail * uint64(stat.Bsize)) / (1024 * 1024 * 1024)

		if availableGB < uint64(minGB) {
			return fmt.Errorf("insufficient disk space: %dGB available, %dGB required\n"+
				"Fix: Free up disk space:\n"+
				"  Check usage: df -h\n"+
				"  Clean Docker: docker system prune -a",
				availableGB, minGB)
		}

		return nil
	}
}

// CheckOllama verifies Ollama is running and accessible
// Note: For human-centric prompting with install offers, use CheckOllamaWithPrompt instead
func CheckOllama(ctx context.Context) error {
	client := &http.Client{Timeout: 5 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost:11434/api/version", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Ollama is not running at localhost:11434\n"+
			"Fix: Install and start Ollama:\n"+
			"  curl -fsSL https://ollama.ai/install.sh | sh\n"+
			"  ollama serve\n"+
			"Error: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			_ = closeErr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Ollama API returned unexpected status: %d\n"+
			"Fix: Restart Ollama:\n"+
			"  sudo systemctl restart ollama",
			resp.StatusCode)
	}

	return nil
}

// CheckOllamaWithPrompt checks Ollama and offers to install if missing
// This is the human-centric version that follows informed consent pattern
// Returns (found, userDeclined, error)
func CheckOllamaWithPrompt(ctx context.Context) (bool, bool, error) {
	// First try the standard check
	if err := CheckOllama(ctx); err == nil {
		return true, false, nil
	}

	// Ollama not found - return detailed info for caller to handle prompting
	// The caller should use interaction.CheckDependencyWithPrompt for full flow
	return false, false, fmt.Errorf("Ollama check failed - use interaction.CheckDependencyWithPrompt for guided installation")
}

// CommonChecks returns the standard set of checks for Docker-based services
func CommonChecks(port int) []Check {
	return []Check{
		{
			Name:        "Docker",
			Description: "Docker daemon is running and accessible",
			Check:       CheckDocker,
			Required:    true,
		},
		{
			Name:        "Docker Compose",
			Description: "Docker Compose V2 is installed",
			Check:       CheckDockerCompose,
			Required:    true,
		},
		{
			Name:        fmt.Sprintf("Port %d", port),
			Description: fmt.Sprintf("Port %d is available for binding", port),
			Check:       CheckPort(port),
			Required:    true,
		},
		{
			Name:        "Disk Space",
			Description: "Minimum 10GB disk space available",
			Check:       CheckDiskSpace(10),
			Required:    true,
		},
	}
}

// WithOllamaCheck adds Ollama check to existing checks
func WithOllamaCheck(checks []Check) []Check {
	return append(checks, Check{
		Name:        "Ollama",
		Description: "Ollama is running and accessible",
		Check:       CheckOllama,
		Required:    true,
	})
}
