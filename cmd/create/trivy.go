/* cmd/create/trivy.go
 */

package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"os"
	"os/exec"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreateTrivyCmd represents the Trivy installation command.
var CreateTrivyCmd = &cobra.Command{
	Use:   "trivy",
	Short: "Install Trivy vulnerability scanner",
	Long: `Install Trivy vulnerability scanner for container and filesystem security scanning.

Trivy is a comprehensive vulnerability scanner that detects vulnerabilities in:
• Container images
• Filesystem directories
• Git repositories
• Configuration files
• Kubernetes manifests

FEATURES:
• Comprehensive vulnerability database
• Fast scanning with minimal false positives
• Support for multiple output formats (JSON, XML, SARIF, GitHub)
• Integration with CI/CD pipelines
• Offline scanning capability
• License detection
• Secret detection in code

EXAMPLES:
  # Install Trivy with default configuration
  eos create trivy

  # Scan a container image after installation
  trivy image nginx:latest

  # Scan a filesystem directory
  trivy fs /path/to/directory

  # Generate JSON report
  trivy image --format json --output report.json nginx:latest`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)
		log.Info("Starting Trivy installation")

		log.Info("Installing required packages: wget, gnupg")
		if err := exec.Command("apt-get", "install", "-y", "wget", "gnupg").Run(); err != nil {
			log.Error("Failed to install prerequisites", zap.Error(err))
			return fmt.Errorf("failed to install required packages: %w", err)
		}

		log.Info("Downloading Trivy GPG key")
		// SECURITY: Use separate commands instead of shell pipeline to prevent injection
		wgetCmd := exec.Command("wget", "-qO-", "https://aquasecurity.github.io/trivy-repo/deb/public.key")
		aptKeyCmd := exec.Command("apt-key", "add", "-")

		// Pipe wget output to apt-key
		aptKeyCmd.Stdin, _ = wgetCmd.StdoutPipe()

		if err := aptKeyCmd.Start(); err != nil {
			log.Error("Failed to start apt-key command", zap.Error(err))
			return fmt.Errorf("failed to start apt-key: %w", err)
		}

		if err := wgetCmd.Run(); err != nil {
			log.Error("Failed to download GPG key", zap.Error(err))
			return fmt.Errorf("failed to download Trivy GPG key: %w", err)
		}

		if err := aptKeyCmd.Wait(); err != nil {
			log.Error("Failed to add GPG key", zap.Error(err))
			return fmt.Errorf("failed to add Trivy GPG key: %w", err)
		}

		log.Info("Adding Trivy APT repository")
		repoLine := "deb https://aquasecurity.github.io/trivy-repo/deb stable main\n"
		// SECURITY: Use direct file write instead of shell echo redirection
		if err := os.WriteFile("/etc/apt/sources.list.d/trivy.list", []byte(repoLine), shared.ConfigFilePerm); err != nil {
			log.Error("Failed to write repository file", zap.Error(err))
			return fmt.Errorf("failed to write Trivy repository file: %w", err)
		}

		log.Info("Updating APT package lists")
		if err := exec.Command("apt-get", "update").Run(); err != nil {
			log.Error("Failed to update package lists", zap.Error(err))
			return fmt.Errorf("failed to update package lists: %w", err)
		}

		log.Info("Installing Trivy")
		if err := exec.Command("apt-get", "install", "-y", "trivy").Run(); err != nil {
			log.Error("Failed to install Trivy", zap.Error(err))
			return fmt.Errorf("failed to install Trivy: %w", err)
		}

		log.Info("Trivy installed successfully!")
		return nil
	}),
}
