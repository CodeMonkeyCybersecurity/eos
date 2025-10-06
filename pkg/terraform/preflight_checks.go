package terraform

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PreflightCheckResult contains the results of Terraform preflight checks
type PreflightCheckResult struct {
	// System checks
	HasSufficientDiskSpace bool
	AvailableDiskSpaceMB   int64
	HasInternetAccess      bool
	Architecture           string
	OperatingSystem        string

	// Dependency checks
	GitInstalled   bool
	GitVersion     string
	UnzipInstalled bool
	GnupgInstalled bool

	// Cloud provider CLIs (optional)
	AwsCliInstalled   bool
	AzureCliInstalled bool
	GcloudInstalled   bool

	// Configuration checks
	HasCredentials      bool
	CredentialProviders []string

	// Installation checks
	TerraformInstalled bool
	TerraformVersion   string
	TerraformPath      string

	// Issues and warnings
	Issues          []string
	Warnings        []string
	Recommendations []string
	CanProceed      bool
}

// RunPreflightChecks performs comprehensive checks before Terraform installation
func RunPreflightChecks(rc *eos_io.RuntimeContext) (*PreflightCheckResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Running Terraform installation preflight checks")

	result := &PreflightCheckResult{
		CanProceed:          true,
		Issues:              []string{},
		Warnings:            []string{},
		Recommendations:     []string{},
		CredentialProviders: []string{},
	}

	// Check system requirements
	checkSystemRequirements(rc, result)

	// Check required dependencies
	checkRequiredDependencies(rc, result)

	// Check optional cloud provider CLIs
	checkCloudProviderCLIs(rc, result)

	// Check if Terraform is already installed
	checkExistingInstallation(rc, result)

	// Check for cloud credentials
	checkCloudCredentials(rc, result)

	// Add recommendations based on findings
	generateRecommendations(result)

	return result, nil
}

func checkSystemRequirements(rc *eos_io.RuntimeContext, result *PreflightCheckResult) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking system requirements")

	// Check architecture
	result.Architecture = runtime.GOARCH
	result.OperatingSystem = runtime.GOOS

	if result.Architecture != "amd64" && result.Architecture != "arm64" {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Terraform may not be available for architecture: %s", result.Architecture))
	} else {
		logger.Info("✓ Supported architecture", zap.String("arch", result.Architecture))
	}

	// Check disk space (need at least 500MB for Terraform + providers)
	diskSpace, err := getAvailableDiskSpace(rc.Ctx, "/usr/local/bin")
	if err == nil {
		result.AvailableDiskSpaceMB = diskSpace
		if diskSpace < 500 {
			result.HasSufficientDiskSpace = false
			result.Issues = append(result.Issues,
				fmt.Sprintf("Insufficient disk space: %dMB available, need at least 500MB", diskSpace))
			result.CanProceed = false
		} else {
			result.HasSufficientDiskSpace = true
			logger.Info("✓ Sufficient disk space", zap.Int64("available_mb", diskSpace))
		}
	}

	// Check internet connectivity
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "ping",
		Args:    []string{"-c", "1", "-W", "2", "releases.hashicorp.com"},
		Capture: true,
	})

	if err != nil {
		result.HasInternetAccess = false
		result.Issues = append(result.Issues, "No internet access to releases.hashicorp.com")
		result.CanProceed = false
	} else {
		result.HasInternetAccess = true
		logger.Info("✓ Internet access verified")
	}
}

func checkRequiredDependencies(rc *eos_io.RuntimeContext, result *PreflightCheckResult) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking required dependencies")

	// Check git
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"git"},
		Capture: true,
	})

	if err != nil {
		result.GitInstalled = false
		result.Issues = append(result.Issues, "Git is required but not installed")
		result.CanProceed = false
		logger.Info("✗ Git not installed (required)")
	} else {
		result.GitInstalled = true

		// Get git version
		version, err := execute.Run(rc.Ctx, execute.Options{
			Command: "git",
			Args:    []string{"--version"},
			Capture: true,
		})
		if err == nil {
			result.GitVersion = strings.TrimSpace(version)
			logger.Info("✓ Git installed", zap.String("version", result.GitVersion))
		}
	}

	// Check unzip
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"unzip"},
		Capture: true,
	})

	if err != nil {
		result.UnzipInstalled = false
		result.Issues = append(result.Issues, "unzip is required but not installed")
		result.CanProceed = false
		logger.Info("✗ unzip not installed (required)")
	} else {
		result.UnzipInstalled = true
		logger.Info("✓ unzip installed")
	}

	// Check gnupg (for signature verification)
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"gpg"},
		Capture: true,
	})

	if err != nil {
		result.GnupgInstalled = false
		result.Warnings = append(result.Warnings, "gnupg not installed (recommended for signature verification)")
		logger.Info("⚠ gnupg not installed (recommended)")
	} else {
		result.GnupgInstalled = true
		logger.Info("✓ gnupg installed")
	}
}

func checkCloudProviderCLIs(rc *eos_io.RuntimeContext, result *PreflightCheckResult) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking cloud provider CLIs (optional)")

	// Check AWS CLI
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"aws"},
		Capture: true,
	})
	result.AwsCliInstalled = err == nil
	if result.AwsCliInstalled {
		logger.Info("✓ AWS CLI installed")
		result.Recommendations = append(result.Recommendations,
			"AWS CLI detected - Terraform can use AWS credentials")
	}

	// Check Azure CLI
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"az"},
		Capture: true,
	})
	result.AzureCliInstalled = err == nil
	if result.AzureCliInstalled {
		logger.Info("✓ Azure CLI installed")
		result.Recommendations = append(result.Recommendations,
			"Azure CLI detected - Terraform can use Azure credentials")
	}

	// Check Google Cloud SDK
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"gcloud"},
		Capture: true,
	})
	result.GcloudInstalled = err == nil
	if result.GcloudInstalled {
		logger.Info("✓ Google Cloud SDK installed")
		result.Recommendations = append(result.Recommendations,
			"Google Cloud SDK detected - Terraform can use GCP credentials")
	}

	if !result.AwsCliInstalled && !result.AzureCliInstalled && !result.GcloudInstalled {
		result.Warnings = append(result.Warnings,
			"No cloud provider CLIs detected - you may need to configure credentials manually")
	}
}

func checkExistingInstallation(rc *eos_io.RuntimeContext, result *PreflightCheckResult) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if Terraform is already installed
	terraformPath, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"terraform"},
		Capture: true,
	})

	if err == nil && strings.TrimSpace(terraformPath) != "" {
		result.TerraformInstalled = true
		result.TerraformPath = strings.TrimSpace(terraformPath)

		// Get version
		version, err := execute.Run(rc.Ctx, execute.Options{
			Command: "terraform",
			Args:    []string{"version"},
			Capture: true,
		})

		if err == nil {
			lines := strings.Split(version, "\n")
			if len(lines) > 0 {
				result.TerraformVersion = strings.TrimSpace(lines[0])
			}
		}

		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Terraform already installed at %s (%s)", result.TerraformPath, result.TerraformVersion))
		logger.Info("⚠ Terraform already installed",
			zap.String("path", result.TerraformPath),
			zap.String("version", result.TerraformVersion))
	}
}

func checkCloudCredentials(rc *eos_io.RuntimeContext, result *PreflightCheckResult) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking for cloud credentials")

	// Check AWS credentials
	if os.Getenv("AWS_ACCESS_KEY_ID") != "" || fileExists(os.ExpandEnv("$HOME/.aws/credentials")) {
		result.HasCredentials = true
		result.CredentialProviders = append(result.CredentialProviders, "AWS")
		logger.Info("✓ AWS credentials detected")
	}

	// Check Azure credentials
	if os.Getenv("AZURE_CLIENT_ID") != "" || fileExists(os.ExpandEnv("$HOME/.azure")) {
		result.HasCredentials = true
		result.CredentialProviders = append(result.CredentialProviders, "Azure")
		logger.Info("✓ Azure credentials detected")
	}

	// Check GCP credentials
	if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "" || fileExists(os.ExpandEnv("$HOME/.config/gcloud")) {
		result.HasCredentials = true
		result.CredentialProviders = append(result.CredentialProviders, "GCP")
		logger.Info("✓ GCP credentials detected")
	}

	if !result.HasCredentials {
		result.Warnings = append(result.Warnings,
			"No cloud credentials detected - you'll need to configure them before using Terraform")
	}
}

func generateRecommendations(result *PreflightCheckResult) {
	// Add recommendations based on what we found
	if !result.GitInstalled {
		result.Recommendations = append(result.Recommendations,
			"Install git: sudo apt-get install git")
	}

	if !result.UnzipInstalled {
		result.Recommendations = append(result.Recommendations,
			"Install unzip: sudo apt-get install unzip")
	}

	if !result.GnupgInstalled {
		result.Recommendations = append(result.Recommendations,
			"Install gnupg for signature verification: sudo apt-get install gnupg")
	}

	if result.TerraformInstalled {
		result.Recommendations = append(result.Recommendations,
			"Consider using 'eos update terraform' to upgrade existing installation")
	}

	if !result.HasCredentials {
		result.Recommendations = append(result.Recommendations,
			"Configure cloud credentials before using Terraform with cloud providers")
	}
}

// DisplayPreflightSummary shows a summary of preflight check results
func DisplayPreflightSummary(rc *eos_io.RuntimeContext, result *PreflightCheckResult) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ╔════════════════════════════════════════════════════════════════╗")
	logger.Info("terminal prompt: ║            TERRAFORM PREFLIGHT CHECK SUMMARY                   ║")
	logger.Info("terminal prompt: ╚════════════════════════════════════════════════════════════════╝")
	logger.Info("terminal prompt: ")

	logger.Info("terminal prompt: SYSTEM:")
	logger.Info("terminal prompt:", zap.String("info", fmt.Sprintf("  • Architecture: %s", result.Architecture)))
	logger.Info("terminal prompt:", zap.String("info", fmt.Sprintf("  • OS: %s", result.OperatingSystem)))
	logger.Info("terminal prompt:", zap.String("info", fmt.Sprintf("  • Disk Space: %dMB available %s",
		result.AvailableDiskSpaceMB, getStatusIcon(result.HasSufficientDiskSpace))))
	logger.Info("terminal prompt:", zap.String("info", fmt.Sprintf("  • Internet Access: %s",
		getStatusIcon(result.HasInternetAccess))))

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: DEPENDENCIES:")
	logger.Info("terminal prompt:", zap.String("info", fmt.Sprintf("  • Git: %s %s",
		getStatusIcon(result.GitInstalled), result.GitVersion)))
	logger.Info("terminal prompt:", zap.String("info", fmt.Sprintf("  • unzip: %s",
		getStatusIcon(result.UnzipInstalled))))
	logger.Info("terminal prompt:", zap.String("info", fmt.Sprintf("  • gnupg: %s",
		getStatusIcon(result.GnupgInstalled))))

	if result.AwsCliInstalled || result.AzureCliInstalled || result.GcloudInstalled {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: CLOUD PROVIDER CLIs:")
		if result.AwsCliInstalled {
			logger.Info("terminal prompt:", zap.String("info", "  • AWS CLI ✓"))
		}
		if result.AzureCliInstalled {
			logger.Info("terminal prompt:", zap.String("info", "  • Azure CLI ✓"))
		}
		if result.GcloudInstalled {
			logger.Info("terminal prompt:", zap.String("info", "  • Google Cloud SDK ✓"))
		}
	}

	if len(result.CredentialProviders) > 0 {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: CREDENTIALS DETECTED:")
		for _, provider := range result.CredentialProviders {
			logger.Info("terminal prompt:", zap.String("info", fmt.Sprintf("  • %s", provider)))
		}
	}

	if len(result.Issues) > 0 {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: ❌ CRITICAL ISSUES:")
		for _, issue := range result.Issues {
			logger.Info("terminal prompt:", zap.String("issue", fmt.Sprintf("  • %s", issue)))
		}
	}

	if len(result.Warnings) > 0 {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: WARNINGS:")
		for _, warning := range result.Warnings {
			logger.Info("terminal prompt:", zap.String("warning", fmt.Sprintf("  • %s", warning)))
		}
	}

	if len(result.Recommendations) > 0 {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: 💡 RECOMMENDATIONS:")
		for _, rec := range result.Recommendations {
			logger.Info("terminal prompt:", zap.String("recommendation", fmt.Sprintf("  • %s", rec)))
		}
	}

	logger.Info("terminal prompt: ")
	if result.CanProceed {
		logger.Info("terminal prompt:  Preflight checks passed - ready to install Terraform")
	} else {
		logger.Info("terminal prompt: ❌ Preflight checks failed - issues must be resolved")
	}
}

func getStatusIcon(ok bool) string {
	if ok {
		return "✓"
	}
	return "✗"
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// getAvailableDiskSpace returns available disk space in MB for the given path
func getAvailableDiskSpace(ctx context.Context, path string) (int64, error) {
	output, err := execute.Run(ctx, execute.Options{
		Command: "df",
		Args:    []string{"-m", path},
		Capture: true,
	})

	if err != nil {
		return 0, err
	}

	lines := strings.Split(output, "\n")
	if len(lines) < 2 {
		return 0, fmt.Errorf("unexpected df output")
	}

	// Parse the second line which contains the data
	fields := strings.Fields(lines[1])
	if len(fields) < 4 {
		return 0, fmt.Errorf("unexpected df output format")
	}

	// Available space is typically in the 4th field
	var available int64
	fmt.Sscanf(fields[3], "%d", &available)

	return available, nil
}

// HandleMissingDependencies helps install missing dependencies
func HandleMissingDependencies(rc *eos_io.RuntimeContext, result *PreflightCheckResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	if !result.GitInstalled || !result.UnzipInstalled {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Required dependencies are missing.")

		consent, err := eos_io.PromptForConsent(rc, "Install missing dependencies (git, unzip)?", false)
		if err != nil {
			return fmt.Errorf("failed to get user consent: %w", err)
		}

		if consent {
			// Install missing packages
			var packages []string
			if !result.GitInstalled {
				packages = append(packages, "git")
			}
			if !result.UnzipInstalled {
				packages = append(packages, "unzip")
			}

			logger.Info("Installing dependencies:", zap.Strings("packages", packages))

			_, err := execute.Run(rc.Ctx, execute.Options{
				Command: "apt-get",
				Args:    append([]string{"install", "-y"}, packages...),
				Capture: false,
			})

			if err != nil {
				return fmt.Errorf("failed to install dependencies: %w", err)
			}

			logger.Info("✓ Dependencies installed successfully")
		} else {
			return fmt.Errorf("Terraform installation cancelled - required dependencies missing")
		}
	}

	return nil
}
