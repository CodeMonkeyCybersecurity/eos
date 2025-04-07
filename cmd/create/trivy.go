/* cmd/create/trivy.go
 */

package create

import (
	"fmt"
	"os/exec"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
)

// installTrivy installs the Trivy vulnerability scanner.
func installTrivy(cmd *cobra.Command, args []string) error {
	// Example: install required packages, add Trivy repo, update package lists, install Trivy.
	fmt.Println("Installing required packages...")
	if err := exec.Command("apt-get", "install", "-y", "wget", "gnupg").Run(); err != nil {
		return fmt.Errorf("failed to install required packages: %w", err)
	}

	fmt.Println("Adding Trivy public key and repository...")
	// For example purposes, this is a placeholder command.
	if err := exec.Command("bash", "-c", `
 wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add - && 
 echo "deb https://aquasecurity.github.io/trivy-repo/deb stable main" > /etc/apt/sources.list.d/trivy.list
 `).Run(); err != nil {
		return fmt.Errorf("failed to add Trivy repository: %w", err)
	}

	fmt.Println("Updating package lists...")
	if err := exec.Command("apt-get", "update").Run(); err != nil {
		return fmt.Errorf("failed to update package lists: %w", err)
	}

	fmt.Println("Installing Trivy...")
	if err := exec.Command("apt-get", "install", "-y", "trivy").Run(); err != nil {
		return fmt.Errorf("failed to install Trivy: %w", err)
	}

	fmt.Println("Trivy installed successfully!")
	return nil
}

// CreateTrivyCmd represents the Trivy installation command.
var CreateTrivyCmd = &cobra.Command{
	Use:   "trivy",
	Short: "Install Trivy vulnerability scanner",
	Long: `This command installs the Trivy vulnerability scanner on your system.
 It performs the following steps:
   1. Installs required packages (wget, gnupg)
   2. Imports the Trivy public key and adds the Trivy APT repository
   3. Updates package lists and installs Trivy`,
	RunE: eos.Wrap(installTrivy),
}
