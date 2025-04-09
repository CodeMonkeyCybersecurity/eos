// pkg/deploy/jenkins

package deploy

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consts"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/docker"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func NewDeployJenkinsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jenkins",
		Short: "Deploy reverse proxy for Jenkins",
		Long: `Deploy the reverse proxy configuration for Jenkins using Hecate.

This command stops the Hecate container (if running) and then organizes assets by moving files 
that are not relevant to Jenkins into the "other" directory at the project root.`,
		RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
			log.Info("Starting Jenkins deployment")

			// Stop the container if it's running.
			if err := docker.StopContainersBySubstring("hecate"); err != nil {
				log.Error("Error stopping container", zap.String("substring", "hecate"), zap.Error(err))
				fmt.Printf("Error stopping container: %v\n", err)
				return err
			}
			log.Info("Containers with 'hecate' in the name stopped successfully")

			// Organize assets for Jenkins.
			if err := utils.OrganizeAssetsForDeployment("jenkins"); err != nil {
				log.Error("Failed to organize assets", zap.Error(err))
				fmt.Printf("Failed to organize assets: %v\n", err)
				return err
			}
			log.Info("Assets organized successfully for Jenkins")

			// Load configuration from .hecate.conf.
			cfg, err := hecate.LoadConfig("jenkins")
			if err != nil {
				log.Error("Configuration error", zap.Error(err))
				fmt.Printf("Configuration error: %v\n", err)
				return err
			}
			log.Info("Configuration loaded", zap.Any("config", cfg))
			fmt.Printf("Configuration loaded:\n  Base Domain: %s\n  Backend IP: %s\n  Subdomain: %s\n  Email: %s\n",
				cfg.BaseDomain, cfg.BackendIP, cfg.Subdomain, cfg.Email)

			assetsDir := "./assets" // or the appropriate directory
			if err := utils.ReplaceTokensInAllFiles(assetsDir, cfg.BaseDomain, cfg.BackendIP); err != nil {
				log.Error("Failed to replace tokens in assets", zap.Error(err))
				fmt.Printf("Error replacing tokens: %v\n", err)
				return err
			}
			log.Info("Tokens replaced successfully in all files under assets")

			// Define fullDomain using subdomain and base domain.
			fullDomain := fmt.Sprintf("%s.%s", cfg.Subdomain, cfg.BaseDomain)

			if err := crypto.EnsureCertificates(cfg.Subdomain, cfg.BaseDomain, cfg.Email); err != nil {
				log.Error("Certificate generation failed", zap.Error(err))
				fmt.Printf("Certificate generation failed: %v\n", err)
				return err
			}
			log.Info("Certificate retrieved successfully", zap.String("domain", fullDomain))

			// Uncomment lines in docker-compose.yml relevant to Jenkins.
			if err := docker.UncommentSegment("uncomment if using Jenkins behind Hecate"); err != nil {
				log.Error("Failed to uncomment Jenkins section", zap.Error(err))
				fmt.Printf("Failed to uncomment Jenkins section: %v\n", err)
				return err
			}
			log.Info("Successfully uncommented Jenkins lines")

			// Now use the compose file for starting the services.
			if err := docker.RunDockerComposeAllServices(consts.DefaultComposeYML, "jenkins"); err != nil {
				log.Error("Failed to start Docker services", zap.Error(err))
				fmt.Printf("Failed to run docker-compose up: %v\n", err)
				return err
			}

			fmt.Println("🎉 Jenkins reverse proxy deployed successfully.")
			return nil
		}),
	}
	return cmd
}
