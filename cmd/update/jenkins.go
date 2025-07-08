/* cmd/update/jenkins.go */
package update

import (
	"fmt"
	"os"
	"os/exec"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
)

var backendIP string

// jenkinsCmd updates the Jenkins backend IP configuration.
var jenkinsCmd = &cobra.Command{
	Use:   "jenkins",
	Short: "Update Jenkins backend IP configuration",
	Long: `Update the Jenkins backend IP in the Hecate configuration.

This command recursively replaces the backend IP token in the assets directory and
redeploys Hecate using "docker compose up -d".

Example configuration:
  Base Domain: domain.com
  Backend IP: 12.34.56.78
  Subdomain: jenkins
  Email: mail@domain.com

Usage:
  hecate update jenkins --backendIP <new-ip>`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		if backendIP == "" {
			fmt.Println("Error: please provide a new backend IP using the --backendIP flag")
			return nil
		}

		// Define the directory and token placeholder
		assetsDir := "assets"
		// #nosec G101 - This is a template placeholder, not a hardcoded credential
		token := "{{BACKEND_IP}}" // Make sure this token matches what you use in your asset files

		fmt.Printf("Updating backend IP to %s in assets directory...\n", backendIP)
		if err := updateFilesInDir(assetsDir, token, backendIP); err != nil {
			fmt.Printf("Error updating files: %v\n", err)
			return nil
		}
		fmt.Println("Assets updated successfully with new backend IP.")

		// Redeploy Hecate via docker compose up -d
		fmt.Println("Redeploying Hecate using docker compose up -d...")
		cmdDocker := exec.Command("docker-compose", "up", "-d")
		cmdDocker.Stdout = os.Stdout
		cmdDocker.Stderr = os.Stderr
		if err := cmdDocker.Run(); err != nil {
			fmt.Printf("Error redeploying Hecate: %v\n", err)
			return err
		}
		fmt.Println("Hecate redeployed successfully with new Jenkins backend IP.")
		shared.SafeHelp(cmd)
		return nil
	}),
}

func init() {
	// Attach the jenkins command as a subcommand of the main update command.
	UpdateCmd.AddCommand(jenkinsCmd)
	jenkinsCmd.Flags().StringVar(&backendIP, "backendIP", "", "New backend IP for Jenkins")
}
