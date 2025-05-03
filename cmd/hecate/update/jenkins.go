/* cmd/update/jenkins.go */
package update

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
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
redeploys Hecate using "docker-compose up -d".

Example configuration:
  Base Domain: domain.com
  Backend IP: 12.34.56.78
  Subdomain: jenkins
  Email: mail@domain.com

Usage:
  hecate update jenkins --backendIP <new-ip>`,
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		if backendIP == "" {
			fmt.Println("Error: please provide a new backend IP using the --backendIP flag")
			return nil
		}

		// Define the directory and token placeholder
		assetsDir := "assets"
		token := "{{BACKEND_IP}}" // Make sure this token matches what you use in your asset files

		fmt.Printf("Updating backend IP to %s in assets directory...\n", backendIP)
		if err := updateFilesInDir(assetsDir, token, backendIP); err != nil {
			fmt.Printf("Error updating files: %v\n", err)
			return nil
		}
		fmt.Println("Assets updated successfully with new backend IP.")

		// Redeploy Hecate via docker-compose up -d
		fmt.Println("Redeploying Hecate using docker-compose up -d...")
		cmdDocker := exec.Command("sudo", "docker compose", "up", "-d")
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

// updateFilesInDir recursively scans the specified directory and replaces any occurrence
// of the provided token with the replacement value. This helper function can be moved to a
// common utils package if desired.
func updateFilesInDir(dir, token, replacement string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Skip directories
		if info.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		contents := string(data)
		if strings.Contains(contents, token) {
			newContents := strings.ReplaceAll(contents, token, replacement)
			if err := os.WriteFile(path, []byte(newContents), info.Mode()); err != nil {
				return err
			}
			fmt.Printf("Updated file: %s\n", path)
		}
		return nil
	})
}

func init() {
	// Attach the jenkins command as a subcommand of the main update command.
	UpdateCmd.AddCommand(jenkinsCmd)
	jenkinsCmd.Flags().StringVar(&backendIP, "backendIP", "", "New backend IP for Jenkins")
}
