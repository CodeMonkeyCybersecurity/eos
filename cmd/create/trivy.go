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

// installTrivy installs the Trivy vulnerability scanner.
func installTrivy(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	log := otelzap.Ctx(rc.Ctx)
	log.Info(" Starting Trivy installation")

	log.Info(" Installing required packages: wget, gnupg")
	if err := exec.Command("apt-get", "install", "-y", "wget", "gnupg").Run(); err != nil {
		log.Error(" Failed to install prerequisites", zap.Error(err))
		return fmt.Errorf("failed to install required packages: %w", err)
	}

	log.Info(" Adding Trivy GPG key and APT repository")
	addRepoCmd := `
	wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add - && 
	echo "deb https://aquasecurity.github.io/trivy-repo/deb stable main" > /etc/apt/sources.list.d/trivy.list
	`
	if err := exec.Command("bash", "-c", addRepoCmd).Run(); err != nil {
		log.Error(" Failed to add Trivy APT repo", zap.Error(err))
		return fmt.Errorf("failed to add Trivy repository: %w", err)
	}

	log.Info(" Updating APT package lists")
	if err := exec.Command("apt-get", "update").Run(); err != nil {
		log.Error(" Failed to update package lists", zap.Error(err))
		return fmt.Errorf("failed to update package lists: %w", err)
	}

	log.Info(" Installing Trivy")
	if err := exec.Command("apt-get", "install", "-y", "trivy").Run(); err != nil {
		log.Error(" Failed to install Trivy", zap.Error(err))
		return fmt.Errorf("failed to install Trivy: %w", err)
	}

	log.Info(" Trivy installed successfully!")
	return nil
}

// CreateTrivyCmd represents the Trivy installation command.
var CreateTrivyCmd = &cobra.Command{
	Use:   "trivy",
	Short: "Install Trivy vulnerability scanner",
	Long: `This command installs the Trivy vulnerability scanner on your eos_unix.
 It performs the following steps:
   1. Installs required packages (wget, gnupg)
   2. Imports the Trivy public key and adds the Trivy APT repository
   3. Updates package lists and installs Trivy`,
	RunE: eos.Wrap(installTrivy),
}
