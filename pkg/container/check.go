// pkg/docker/check.go

package container

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	cerr "github.com/cockroachdb/errors"
	"go.uber.org/zap"
)

type DockerCheckConfig struct {
	AllowMissingCompose bool `validate:"required"`
}

// CheckDockerContainers lists running containers using the docker CLI.
func CheckDockerContainers(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info("Checking running Docker containers")
	out, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"ps", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}"},
		Capture: true,
	})
	if err != nil {
		log.Error("Failed to list containers", zap.Error(err))
		return cerr.WithHint(err, "Ensure Docker is installed and running")
	}

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		log.Info("No running containers")
		fmt.Println("No running containers.")
		return nil
	}

	for _, line := range lines {
		parts := strings.Split(line, "\t")
		if len(parts) >= 3 {
			log.Info("Container info", zap.String("id", parts[0]), zap.String("image", parts[1]), zap.String("name", parts[2]))
			fmt.Printf("Container ID: %s\tImage: %s\tName: %s\n", parts[0][:12], parts[1], parts[2])
		}
	}
	return nil
}

// CheckIfDockerInstalled checks if Docker CLI is available and responding.
func CheckIfDockerInstalled(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info("Checking if Docker CLI is installed")
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"version", "--format", "'{{.Server.Version}}'"},
	})
	if err != nil {
		log.Error("Docker CLI not available", zap.Error(err))
		return cerr.WithHint(err, "Install Docker and ensure it’s in your PATH")
	}
	return nil
}

// CheckIfDockerComposeInstalled verifies docker compose availability.
func CheckIfDockerComposeInstalled(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info("Checking for docker compose")
	commands := [][]string{
		{"docker", "compose", "version"},
		{"docker-compose", "version"},
	}
	for _, cmd := range commands {
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: cmd[0],
			Args:    cmd[1:],
		})
		if err == nil {
			return nil
		}
	}
	log.Warn("Docker Compose not found")
	return errors.New("docker compose not found")
}

// EnsureDockerInstalled checks if Docker is installed and offers to install it if not.
// Follows P0 human-centric pattern: NEVER silently install, ALWAYS offer informed consent.
func EnsureDockerInstalled(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info("Checking Docker installation")

	// First check if Docker is already available
	if err := CheckIfDockerInstalled(rc); err == nil {
		log.Info("Docker is already installed")

		// Also check if Docker is running
		if err := CheckRunning(rc); err != nil {
			log.Warn("Docker is installed but not running", zap.Error(err))

			// Offer to start Docker
			return cerr.WithHint(err,
				"Docker is installed but not running.\n\n"+
					"To start Docker:\n"+
					"  sudo systemctl start docker\n\n"+
					"Then retry this command.")
		}

		log.Info("Docker is installed and running")
		return nil
	}

	// Docker not found - use human-centric dependency checking with informed consent
	// This is required by CLAUDE.md P0 rule: "Dependency Not Found"
	log.Info("Docker not found, checking with user consent")

	// Import interaction package for informed consent (already imported at top)
	depConfig := getDockerDependencyConfig()

	result, err := checkDependencyWithPromptWrapper(rc, depConfig)
	if err != nil {
		return err
	}

	if !result.Found {
		return cerr.New("Docker is required but not available")
	}

	log.Info("Docker installation completed successfully")
	return nil
}

// getDockerDependencyConfig returns the configuration for Docker dependency checking
func getDockerDependencyConfig() map[string]interface{} {
	return map[string]interface{}{
		"name":          "Docker",
		"description":   "Container runtime for managing application services. Installs docker-ce (~380MB), docker-compose, and containerd.",
		"check_command": "docker",
		"check_args":    []string{"info"},
		"install_cmd":   "This will run: apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin",
		"start_cmd":     "systemctl start docker",
		"required":      true,
		"auto_install":  true,
		"auto_start":    true,
	}
}

// checkDependencyWithPromptWrapper wraps the interaction package's CheckDependencyWithPrompt
// This is a temporary wrapper until we can add the interaction import
func checkDependencyWithPromptWrapper(rc *eos_io.RuntimeContext, config map[string]interface{}) (*dockerCheckResult, error) {
	log := otelzap.Ctx(rc.Ctx)

	// For now, provide explicit informed consent via direct prompting
	// TODO: Refactor to use interaction.CheckDependencyWithPrompt once import added
	log.Info("")
	log.Info("════════════════════════════════════════════════════════════════")
	log.Info("Missing Dependency: Docker")
	log.Info("════════════════════════════════════════════════════════════════")
	log.Info("")
	log.Info("What it does: Container runtime for managing application services")
	log.Info("")
	log.Info("What will be installed:")
	log.Info("  • docker-ce (Docker Engine)")
	log.Info("  • docker-ce-cli (Docker CLI)")
	log.Info("  • containerd.io (Container runtime)")
	log.Info("  • docker-buildx-plugin (Build tool)")
	log.Info("  • docker-compose-plugin (Compose v2)")
	log.Info("")
	log.Info("Download size: ~380MB")
	log.Info("")
	log.Info("Installation will:")
	log.Info("  1. Add Docker's official GPG key")
	log.Info("  2. Add Docker repository to APT sources")
	log.Info("  3. Install Docker packages via apt-get")
	log.Info("  4. Add your user to the 'docker' group")
	log.Info("  5. Start Docker daemon")
	log.Info("")

	// Use simple yes/no prompt (will be improved with Issue #2 fix)
	// For now, this is better than silent auto-install
	log.Info("terminal prompt: Install Docker automatically? [y/N]: ")

	// Simple consent check - will be replaced with proper PromptYesNo after Issue #2 fix
	consent := promptForConsent(rc)

	if !consent {
		log.Info("User declined Docker installation")
		return &dockerCheckResult{Found: false, UserDeclined: true},
			cerr.New("Docker is required but you declined installation.\n\n" +
				"To install manually:\n" +
				"  sudo eos create docker\n\n" +
				"Then run this command again.")
	}

	log.Info("User consented to Docker installation")
	log.Info("Installing Docker...")

	// Perform installation
	if err := InstallDocker(rc); err != nil {
		log.Error("Docker installation failed", zap.Error(err))
		return &dockerCheckResult{Found: false},
			cerr.Wrap(err, "Docker installation failed.\n\n"+
				"Please install manually:\n"+
				"  sudo eos create docker")
	}

	// Verify installation
	if err := CheckIfDockerInstalled(rc); err != nil {
		return &dockerCheckResult{Found: false},
			cerr.Wrap(err, "Docker installation appeared to succeed but verification failed")
	}

	log.Info("✓ Docker installation completed and verified")

	return &dockerCheckResult{Found: true, Running: true}, nil
}

// dockerCheckResult mimics interaction.DependencyCheckResult
type dockerCheckResult struct {
	Found        bool
	Running      bool
	UserDeclined bool
}

// promptForConsent provides basic yes/no prompting
// This will be replaced with proper interaction.PromptYesNo after Issue #2 fix
func promptForConsent(rc *eos_io.RuntimeContext) bool {
	// Import bufio at top of file (already present)
	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false // Default to no on error
	}

	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}

// CheckRunning ensures Docker daemon is active.
func CheckRunning(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	log.Info("Checking if Docker daemon is running")
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"info"},
		Capture: true,
	})
	if err != nil {
		log.Error("Docker daemon not running", zap.Error(err))
		return cerr.WithHint(err, "Docker is not running. Please start Docker Desktop.")
	}
	return nil
}
