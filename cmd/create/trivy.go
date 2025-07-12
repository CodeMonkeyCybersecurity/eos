/* cmd/create/trivy.go
 */

package create

import (
	"fmt"
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

		log.Info("Adding Trivy GPG key and APT repository")
		addRepoCmd := `
		wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add - && 
		echo "deb https://aquasecurity.github.io/trivy-repo/deb stable main" > /etc/apt/sources.list.d/trivy.list
		`
		if err := exec.Command("bash", "-c", addRepoCmd).Run(); err != nil {
			log.Error("Failed to add Trivy APT repo", zap.Error(err))
			return fmt.Errorf("failed to add Trivy repository: %w", err)
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
