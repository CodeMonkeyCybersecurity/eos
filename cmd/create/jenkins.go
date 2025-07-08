// cmd/create/jenkins.go

package create

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/templates"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

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
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("Starting Jenkins installation using Eos")

		// Step 1: Ensure Docker is installed and running
		if err := container.EnsureDockerInstalled(rc); err != nil {
			return fmt.Errorf("docker dependency check failed: %w", err)
		}

		// Step 2: Ensure the installation directory exists
		if err := os.MkdirAll(shared.JenkinsDir, shared.DirPermStandard); err != nil {
			otelzap.Ctx(rc.Ctx).Fatal("Failed to create installation directory", zap.Error(err))
		}

		// Step 3: Prepare output path
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
		defer func() {
			if cerr := f.Close(); cerr != nil {
				otelzap.Ctx(rc.Ctx).Error("failed to close compose file", zap.Error(cerr))
			}
		}()
		if err := templates.JenkinsComposeTemplate.Execute(f, data); err != nil {
			return fmt.Errorf("render template: %w", err)
		}

		// Ensure network
		if err := container.EnsureArachneNetwork(rc); err != nil {
			return fmt.Errorf("ensure network: %w", err)
		}

		// Start Jenkins with sudo and increased timeout
		otelzap.Ctx(rc.Ctx).Info(" Starting Jenkins with Docker Compose",
			zap.String("working_directory", shared.JenkinsDir),
			zap.String("compose_file", destPath),
			zap.String("command", "sudo docker compose up -d"))

		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "sudo",
			Args:    []string{"docker", "compose", "up", "-d"},
			Dir:     shared.JenkinsDir,
			Timeout: 5 * time.Minute, // Increase timeout for container pulls
		}); err != nil {
			return fmt.Errorf("docker compose up: %w", err)
		}

		// Wait for Jenkins to start up
		otelzap.Ctx(rc.Ctx).Info(" Waiting for Jenkins to initialize...")
		time.Sleep(10 * time.Second)

		// Check containers are running
		otelzap.Ctx(rc.Ctx).Info(" Verifying Jenkins containers are running...")
		if err := container.CheckDockerContainers(rc); err != nil {
			otelzap.Ctx(rc.Ctx).Warn(" Warning: Container check failed (likely Docker permission issue)", zap.Error(err))
			otelzap.Ctx(rc.Ctx).Info(" Manual container verification command",
				zap.String("command", "sudo docker ps"),
				zap.String("expected_containers", "jenkins, ssh-agent"))
		}

		// Fetch Jenkins admin password with fallback methods
		otelzap.Ctx(rc.Ctx).Info(" Retrieving Jenkins admin password...")

		var password string
		var pwErr error

		// Method 1: Try using the container exec function
		out, pwErr := container.ExecCommandInContainer(rc, container.ExecConfig{
			ContainerName: "jenkins",
			Cmd:           []string{"cat", "/var/jenkins_home/secrets/initialAdminPassword"},
			Tty:           false,
		})

		if pwErr != nil {
			otelzap.Ctx(rc.Ctx).Warn(" Primary password retrieval failed, trying direct docker exec", zap.Error(pwErr))

			// Method 2: Fallback to direct docker exec using execute package
			if execOut, execErr := execute.Run(rc.Ctx, execute.Options{
				Command: "sudo",
				Args:    []string{"docker", "exec", "jenkins", "cat", "/var/jenkins_home/secrets/initialAdminPassword"},
				Capture: true,
			}); execErr != nil {
				otelzap.Ctx(rc.Ctx).Warn(" Could not retrieve initial admin password automatically", zap.Error(execErr))
				otelzap.Ctx(rc.Ctx).Info(" Manual password retrieval commands",
					zap.String("command", "sudo docker exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword"),
					zap.String("alternative", "cd /opt/jenkins && sudo docker compose logs jenkins | grep -A5 'Please use the following password'"))
				pwErr = execErr // Keep the error for later use
			} else {
				password = strings.TrimSpace(execOut)
				pwErr = nil // Clear the error since we succeeded
				otelzap.Ctx(rc.Ctx).Info(" Password retrieved successfully using fallback method")
			}
		} else {
			password = strings.TrimSpace(out)
			otelzap.Ctx(rc.Ctx).Info(" Password retrieved successfully using primary method")
		}

		if pwErr == nil && password != "" {
			otelzap.Ctx(rc.Ctx).Info(" Jenkins is ready!",
				zap.String("url", "http://localhost:8059"),
				zap.String("password", password))
		}

		// Store password in Vault if successfully retrieved
		if pwErr == nil && password != "" {
			vaultClient, err := vaultapi.NewClient(vaultapi.DefaultConfig())
			if err != nil {
				otelzap.Ctx(rc.Ctx).Warn(" Failed to create Vault client", zap.Error(err))
			} else {
				if err := container.StoreJenkinsAdminPassword(rc, vaultClient, password); err != nil {
					otelzap.Ctx(rc.Ctx).Warn(" Failed to store Jenkins password in Vault", zap.Error(err))
				} else {
					otelzap.Ctx(rc.Ctx).Info(" Jenkins admin password stored in Vault",
						zap.String("vault_path", "secret/jenkins"))
				}
			}
		}

		otelzap.Ctx(rc.Ctx).Info(" Jenkins deployment complete",
			zap.String("web_url", fmt.Sprintf("http://%s:8059", eos_unix.GetInternalHostname())),
			zap.String("status", "ready"))

		otelzap.Ctx(rc.Ctx).Info(" Manual verification commands",
			zap.String("check_containers", "sudo docker ps"),
			zap.String("view_logs", "cd /opt/jenkins && sudo docker compose logs"),
			zap.String("restart_if_needed", "cd /opt/jenkins && sudo docker compose restart"))

		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateJenkinsCmd)
}

func NewDeployJenkinsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jenkins",
		Short: "Deploy reverse proxy for Jenkins",
		Long: `Deploy the reverse proxy configuration for Jenkins using Hecate.

This command stops the Hecate container (if running) and then organizes assets by moving files 
that are not relevant to Jenkins into the "other" directory at the project root.`,
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			otelzap.Ctx(rc.Ctx).Info("Starting Jenkins deployment")

			// Stop the container if it's running.
			if err := container.StopContainersBySubstring(rc, "hecate"); err != nil {
				otelzap.Ctx(rc.Ctx).Error("Error stopping container", zap.String("substring", "hecate"), zap.Error(err))
				fmt.Printf("Error stopping container: %v\n", err)
				return err
			}
			otelzap.Ctx(rc.Ctx).Info("Containers with 'hecate' in the name stopped successfully")

			// Organize assets for Jenkins.
			if err := utils.OrganizeAssetsForDeployment("jenkins"); err != nil {
				otelzap.Ctx(rc.Ctx).Error("Failed to organize assets", zap.Error(err))
				fmt.Printf("Failed to organize assets: %v\n", err)
				return err
			}
			otelzap.Ctx(rc.Ctx).Info("Assets organized successfully for Jenkins")

			// Load configuration from .hecate.conf.
			cfg, err := hecate.LoadConfig(rc, "jenkins")
			if err != nil {
				otelzap.Ctx(rc.Ctx).Error("Configuration error", zap.Error(err))
				fmt.Printf("Configuration error: %v\n", err)
				return err
			}
			otelzap.Ctx(rc.Ctx).Info("Configuration loaded", zap.Any("config", cfg))
			fmt.Printf("Configuration loaded:\n  Base Domain: %s\n  Backend IP: %s\n  Subdomain: %s\n  Email: %s\n",
				cfg.BaseDomain, cfg.BackendIP, cfg.Subdomain, cfg.Email)

			assetsDir := "./assets" // or the appropriate directory
			if err := utils.ReplaceTokensInAllFiles(assetsDir, cfg.BaseDomain, cfg.BackendIP); err != nil {
				otelzap.Ctx(rc.Ctx).Error("Failed to replace tokens in assets", zap.Error(err))
				fmt.Printf("Error replacing tokens: %v\n", err)
				return err
			}
			otelzap.Ctx(rc.Ctx).Info("Tokens replaced successfully in all files under assets")

			// Define fullDomain using subdomain and base domain.
			fullDomain := fmt.Sprintf("%s.%s", cfg.Subdomain, cfg.BaseDomain)

			if err := crypto.EnsureCertificates(cfg.Subdomain, cfg.BaseDomain, cfg.Email); err != nil {
				otelzap.Ctx(rc.Ctx).Error("Certificate generation failed", zap.Error(err))
				fmt.Printf("Certificate generation failed: %v\n", err)
				return err
			}
			otelzap.Ctx(rc.Ctx).Info("Certificate retrieved successfully", zap.String("domain", fullDomain))

			// Uncomment lines in docker-compose.yml relevant to Jenkins.
			if err := container.UncommentSegment("uncomment if using Jenkins behind Hecate"); err != nil {
				otelzap.Ctx(rc.Ctx).Error("Failed to uncomment Jenkins section", zap.Error(err))
				fmt.Printf("Failed to uncomment Jenkins section: %v\n", err)
				return err
			}
			otelzap.Ctx(rc.Ctx).Info("Successfully uncommented Jenkins lines")

			// Now use the compose file for starting the services.
			if err := container.RunDockerComposeAllServices(shared.DefaultComposeYML, "jenkins"); err != nil {
				otelzap.Ctx(rc.Ctx).Error("Failed to start Docker services", zap.Error(err))
				fmt.Printf("Failed to run docker compose up: %v\n", err)
				return err
			}

			fmt.Println(" Jenkins reverse proxy deployed successfully.")
			return nil
		}),
	}
	return cmd
}
