// pkg/terraform/check.go

package terraform

import (
	"fmt"
	"os/exec"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hashicorp"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// CheckTerraformInstalledWithPrompt checks if terraform is installed and prompts to install if not.
//
// This function follows the human-centric dependency checking pattern with informed consent.
// Uses interaction.PromptYesNoSafe for user consent, then manually calls hashicorp.InstallTool
// for the actual installation.
//
// Pattern: ASSESS → INFORM + CONSENT → INTERVENE → EVALUATE
//
// If Terraform is not found:
//   - Explains what Terraform is and why it's needed
//   - Asks for user consent via PromptYesNoSafe (Y/n default)
//   - Calls hashicorp.InstallTool if user consents
//   - Verifies installation succeeded
func CheckTerraformInstalledWithPrompt(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Check if terraform is already installed
	if _, err := exec.LookPath("terraform"); err == nil {
		logger.Info("Terraform is already installed")
		return nil
	}

	// INFORM + CONSENT: Use human-centric pattern to explain and get consent
	logger.Info("Terraform not found in PATH")
	logger.Info("Terraform is required to manage infrastructure as code (DNS, cloud resources)")
	logger.Info("")

	proceed, err := interaction.PromptYesNoSafe(rc, "Would you like to install Terraform now?", true)
	if err != nil {
		return fmt.Errorf("failed to get user consent: %w", err)
	}

	if !proceed {
		return fmt.Errorf("terraform is required but installation was declined by user.\n\n" +
			"To install manually, run:\n" +
			"  sudo eos install terraform")
	}

	// INTERVENE: Install terraform using HashiCorp package manager
	logger.Info("Installing Terraform via HashiCorp package manager...")
	if err := hashicorp.InstallTool(rc, "terraform"); err != nil {
		return fmt.Errorf("failed to install terraform: %w", err)
	}

	// EVALUATE: Verify installation succeeded
	if _, err := exec.LookPath("terraform"); err != nil {
		return fmt.Errorf("terraform installation completed but terraform not found in PATH: %w", err)
	}

	logger.Info("Terraform installed successfully and ready to use")
	return nil
}

// TerraformVersionInfo represents Terraform version information
type TerraformVersionInfo struct {
	Version      string `json:"terraform_version"`
	Platform     string `json:"platform"`
	ProviderSHA  string `json:"provider_selections"`
	Architecture string `json:"terraform_revision"`
}

// TerraformValidationResult represents comprehensive validation results
type TerraformValidationResult struct {
	VersionCompatible   bool                     `json:"version_compatible"`
	ProvidersValid      bool                     `json:"providers_valid"`
	StateValid          bool                     `json:"state_valid"`
	QuotasValid         bool                     `json:"quotas_valid"`
	VersionInfo         *TerraformVersionInfo    `json:"version_info"`
	ProviderValidations []ProviderValidation     `json:"provider_validations"`
	StateValidation     *StateValidation         `json:"state_validation"`
	QuotaValidation     *QuotaValidation         `json:"quota_validation"`
	Errors              []string                 `json:"errors"`
	Warnings            []string                 `json:"warnings"`
}

// ProviderValidation represents provider-specific validation
type ProviderValidation struct {
	Name           string    `json:"name"`
	Version        string    `json:"version"`
	Authenticated  bool      `json:"authenticated"`
	Permissions    []string  `json:"permissions"`
	LastValidated  time.Time `json:"last_validated"`
	Error          string    `json:"error,omitempty"`
}

// StateValidation represents state file validation
type StateValidation struct {
	Exists          bool      `json:"exists"`
	IntegrityValid  bool      `json:"integrity_valid"`
	VersionValid    bool      `json:"version_valid"`
	BackupExists    bool      `json:"backup_exists"`
	Size            int64     `json:"size"`
	LastModified    time.Time `json:"last_modified"`
	ResourceCount   int       `json:"resource_count"`
	Error           string    `json:"error,omitempty"`
}

// QuotaValidation represents resource quota validation
type QuotaValidation struct {
	DNSRecordsUsed     int    `json:"dns_records_used"`
	DNSRecordsLimit    int    `json:"dns_records_limit"`
	APICallsRemaining  int    `json:"api_calls_remaining"`
	RateLimitStatus    string `json:"rate_limit_status"`
	Error              string `json:"error,omitempty"`
}

// TerraformPrerequisites represents required Terraform configurations
type TerraformPrerequisites struct {
	MinVersion       string   `json:"min_version"`
	MaxVersion       string   `json:"max_version"`
	RequiredProviders []string `json:"required_providers"`
	WorkingDirectory string   `json:"working_directory"`
	StateBackend     string   `json:"state_backend"`
}

// Default Terraform requirements for Hecate
var DefaultHecatePrerequisites = TerraformPrerequisites{
	MinVersion: "1.0.0",
	MaxVersion: "2.0.0",
	RequiredProviders: []string{
		"hetzner/hcloud",
		"hashicorp/consul",
		"hashicorp/vault",
	},
	WorkingDirectory: "/var/lib/hecate/terraform",
	StateBackend:     "consul",
}
