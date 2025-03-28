// cmd/install/trivy.go
package deploy

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

// trivyCmd represents the trivy installation command.
var trivyCmd = &cobra.Command{
	Use:   "trivy",
	Short: "Install Trivy vulnerability scanner",
	Long: `This command installs the Trivy vulnerability scanner on your system.
It performs the following steps:
  1. Installs required packages (wget, gnupg)
  2. Imports the Trivy public key and adds the Trivy APT repository
  3. Updates package lists and installs Trivy`,
	Run: func(cmd *cobra.Command, args []string) {
		installTrivy()
	},
}

func installTrivy() {
	commands := []string{
		"sudo apt-get install -y wget gnupg",
		"wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null",
		`echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee -a /etc/apt/sources.list.d/trivy.list`,
		"sudo apt-get update",
		"sudo apt-get install -y trivy",
	}

	for _, cmdStr := range commands {
		fmt.Printf("Running: %s\n", cmdStr)
		command := exec.Command("sh", "-c", cmdStr)
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		if err := command.Run(); err != nil {
			fmt.Printf("Error executing '%s': %v\n", cmdStr, err)
			os.Exit(1)
		}
	}
	fmt.Println("Trivy installation completed successfully.")
}
