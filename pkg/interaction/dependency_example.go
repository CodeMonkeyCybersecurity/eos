// pkg/interaction/dependency_example.go
//
// Example usage patterns for human-centric dependency checking
// DO NOT import this file - it's for documentation only

//go:build example
// +build example

package interaction

import (
	"context"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/preflight"
)

// Example 1: Simple dependency check with auto-install
func exampleOllamaCheck(rc *eos_io.RuntimeContext) error {
	depConfig := DependencyConfig{
		Name:          "Ollama",
		Description:   "Local LLM server for embeddings (document search). Runs models locally for FREE.",
		CheckCommand:  "curl",
		CheckArgs:     []string{"-s", "http://localhost:11434/api/version"},
		InstallCmd:    "curl -fsSL https://ollama.ai/install.sh | sh",
		StartCmd:      "ollama serve &",
		Required:      true,
		AutoInstall:   true,  // Will offer to install automatically
		AutoStart:     false, // Will show start command but not auto-start
		CustomCheckFn: preflight.CheckOllama,
	}

	result, err := CheckDependencyWithPrompt(rc, depConfig)
	if err != nil {
		return err
	}

	if !result.Found {
		// User declined installation
		return nil
	}

	// Dependency is now available, continue with business logic
	return nil
}

// Example 2: System package dependency (no auto-install)
func exampleDockerCheck(rc *eos_io.RuntimeContext) error {
	depConfig := DependencyConfig{
		Name:         "Docker",
		Description:  "Container runtime for running containerized services",
		CheckCommand: "docker",
		CheckArgs:    []string{"info"},
		InstallCmd: "curl -fsSL https://get.docker.com | sh\n" +
			"  sudo usermod -aG docker $USER\n" +
			"  sudo systemctl enable --now docker",
		Required:      true,
		AutoInstall:   false, // System packages require manual install
		CustomCheckFn: preflight.CheckDocker,
	}

	result, err := CheckDependencyWithPrompt(rc, depConfig)
	if err != nil {
		return err
	}

	if !result.Found {
		// User needs to install manually
		return nil
	}

	return nil
}

// Example 3: Optional dependency (not required)
func exampleOptionalToolCheck(rc *eos_io.RuntimeContext) error {
	depConfig := DependencyConfig{
		Name:         "jq",
		Description:  "JSON processor for advanced query features (optional)",
		CheckCommand: "jq",
		CheckArgs:    []string{"--version"},
		InstallCmd:   "sudo apt install jq",
		Required:     false, // Optional dependency
		AutoInstall:  true,
	}

	result, err := CheckDependencyWithPrompt(rc, depConfig)
	if err != nil {
		// Optional dependency failed but that's OK
		return nil
	}

	if result.Found {
		// Use advanced features
		return nil
	}

	// Fall back to basic features
	return nil
}

// Example 4: Simple prompt without full check (manual control)
func exampleSimplePrompt(rc *eos_io.RuntimeContext) error {
	// Just ask if they want to install, don't auto-install
	consent := PromptDependencyInstall(rc,
		"PostgreSQL",
		"Relational database for storing application data",
		"sudo apt install postgresql postgresql-contrib")

	if consent {
		// User said yes, but you handle the install yourself
		// ... custom installation logic ...
	}

	return nil
}

// Example 5: Using custom check function
func customCheckFunction(ctx context.Context) error {
	// Your custom logic to verify the dependency
	// Return nil if found, error if not found
	return nil
}

func exampleCustomCheck(rc *eos_io.RuntimeContext) error {
	depConfig := DependencyConfig{
		Name:          "Custom Tool",
		Description:   "A specialized tool with custom verification",
		InstallCmd:    "./install-tool.sh",
		Required:      true,
		AutoInstall:   true,
		CustomCheckFn: customCheckFunction, // Use your custom check
	}

	_, err := CheckDependencyWithPrompt(rc, depConfig)
	return err
}

// Example 6: What the user sees
//
// When Ollama is not installed, the user sees:
//
// INFO terminal prompt:
// INFO terminal prompt: ========================================
// INFO terminal prompt: Missing Dependency: Ollama
// INFO terminal prompt: ========================================
// INFO terminal prompt:
// INFO terminal prompt: What it does: Local LLM server for embeddings (document search). Runs models locally for FREE.
// INFO terminal prompt:
// INFO terminal prompt: Current status: NOT INSTALLED
// INFO terminal prompt:
// INFO terminal prompt: To install manually, run:
// INFO terminal prompt:   curl -fsSL https://ollama.ai/install.sh | sh
// INFO terminal prompt:
// INFO terminal prompt: To start the service, run:
// INFO terminal prompt:   ollama serve &
// INFO terminal prompt:
// INFO terminal prompt: Would you like Eos to install this for you?
// INFO terminal prompt:
// Install Ollama automatically [y/N]: y
//
// INFO terminal prompt: Installing Ollama...
// [Installation output...]
// INFO terminal prompt: ✓ Ollama is now ready
//
// The user gave INFORMED CONSENT before any action was taken.
// They know WHAT it is, WHY they need it, and HOW to install it manually.
// This is the Eos philosophy: Technology serves humans.
