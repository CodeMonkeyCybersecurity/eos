// cmd/create/jenkins.go

package create

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/templates"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// jenkinsCmd represents the Jenkins installation command.
var CreateJenkinsCmd = &cobra.Command{
	Use:   "jenkins",
	Short: "Install and deploy Jenkins",
	Long: `Install and deploy Jenkins to /opt/jenkins by:
- Rendering the Jenkins Docker Compose template to /opt/jenkins
- Running "docker compose up -d" to deploy
- Waiting 5 seconds and listing running containers via "docker ps"
- Informing the user to navigate to :8059 and log in`,
	RunE: eos.Wrap(func(ctx *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		zap.L().Info("Starting Jenkins installation using Eos")

		// Step 1: Ensure the installation directory exists
		if err := os.MkdirAll(shared.JenkinsDir, shared.DirPermStandard); err != nil {
			zap.L().Fatal("Failed to create installation directory", zap.Error(err))
		}

		// Step 2: Prepare output path
		destPath := filepath.Join(shared.JenkinsDir, "docker-compose.yml")

		// Remove: password generation — not used or needed

		data := map[string]string{
			"JenkinsImage":      "jenkins/jenkins:lts",
			"JenkinsContainer":  "jenkins",
			"JenkinsUIPort":     "8059",
			"JenkinsAgentPort":  "9059",
			"VolumeName":        "jenkins_home",
			"NetworkName":       "arachne-net",
			"SSHAgentContainer": "ssh-agent",
			"SSHAgentImage":     "jenkins/ssh-agent",
		}

		// Render template
		f, err := os.Create(destPath)
		if err != nil {
			return fmt.Errorf("create compose file: %w", err)
		}
		defer f.Close()
		if err := templates.JenkinsComposeTemplate.Execute(f, data); err != nil {
			return fmt.Errorf("render template: %w", err)
		}

		// Ensure network
		if err := container.EnsureArachneNetwork(ctx.Ctx); err != nil {
			return fmt.Errorf("ensure network: %w", err)
		}

		// Start Jenkins
		if err := execute.RunSimple(shared.JenkinsDir, "docker", "compose", "up", "-d"); err != nil {
			return fmt.Errorf("docker compose up: %w", err)
		}

		// Wait and fetch admin password
		time.Sleep(5 * time.Second)
		out, pwErr := container.ExecCommandInContainer(ctx.Ctx, container.ExecConfig{
			ContainerName: "jenkins",
			Cmd:           []string{"cat", "/var/jenkins_home/secrets/initialAdminPassword"},
			Tty:           false, // or true if you need a TTY
		})
		if err != nil {
			fmt.Println("⚠️  Could not get admin password. Run manually:")
			fmt.Println("   docker exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword")
		} else {
			fmt.Printf("🔐 Admin password:\n\n%s\n\n", strings.TrimSpace(out))
		}

		// Step 7: Launch Jenkins
		zap.L().Info("Running docker compose up")
		if err := execute.RunSimple(shared.JenkinsDir, "docker", "compose", "-f", destPath, "up", "-d"); err != nil {
			zap.L().Fatal("Failed to start Jenkins via Docker Compose", zap.Error(err))
		}

		time.Sleep(5 * time.Second)

		if err := container.CheckDockerContainers(ctx.Ctx); err != nil {
			zap.L().Fatal("Error checking containers", zap.Error(err))
		}

		// Step 8: Print Jenkins default admin password
		cmdOut := exec.Command("docker", "exec", "jenkins", "cat", "/var/jenkins_home/secrets/initialAdminPassword")
		rawOut, err := cmdOut.CombinedOutput()
		if pwErr != nil {
			zap.L().Warn("Could not retrieve initial admin password", zap.Error(err))
			fmt.Println("⚠️  Could not retrieve admin password automatically. Check with:")
			fmt.Println("   docker exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword")
		} else {
			password := strings.TrimSpace(string(rawOut))
			fmt.Printf("\n🔐 Jenkins is ready!\nVisit: http://localhost:8059\nUnlock with password:\n\n%s\n\n", password)
		}
		vaultClient, err := vaultapi.NewClient(vaultapi.DefaultConfig())
		if err != nil {
			return fmt.Errorf("failed to create Vault client: %w", err)
		}
		if pwErr == nil {
			// stash in Vault under "secret/jenkins"
			if err := container.StoreJenkinsAdminPassword(ctx.Ctx, vaultClient, strings.TrimSpace(out)); err != nil {
				zap.L().Warn("failed to write Jenkins password to Vault", zap.Error(err))
			} else {
				zap.L().Info("Jenkins admin password stored in Vault", zap.String("path", "secret/jenkins"))
			}
		}

		zap.L().Info("Jenkins deployment complete",
			zap.String("url", fmt.Sprintf("http://%s:8059", eos_unix.GetInternalHostname())))
		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateJenkinsCmd)
}
