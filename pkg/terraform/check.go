// pkg/terraform/check.go

package terraform

import (
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hashicorp"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/prompt"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// CheckTerraformInstalledWithPrompt checks if terraform is installed and prompts to install if not
func CheckTerraformInstalledWithPrompt(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if terraform is already installed
	if _, err := exec.LookPath("terraform"); err == nil {
		logger.Info("Terraform is already installed")
		return nil
	}

	// Terraform is not installed, prompt user
	logger.Info("Terraform not found in PATH")

	return prompt.PromptInstallDependency(rc, "terraform",
		"Terraform is required to manage infrastructure as code",
		func() error {
			// Use the hashicorp package to install terraform
			return hashicorp.InstallTool(rc, "terraform")
		})
}
