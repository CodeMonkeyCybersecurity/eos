// cmd/create/hecate_terraform.go

package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"os"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/terraform"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var hecateTerraformCmd = &cobra.Command{
	Use:   "hecate-terraform",
	Short: "Generate Terraform configuration for Hecate mail server deployment",
	Long: `Generate Terraform configuration for Hecate mail server with Stalwart, Caddy, and Nginx.
Supports both local Docker deployment and cloud infrastructure provisioning.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		if err := terraform.CheckTerraformInstalled(); err != nil {
			return fmt.Errorf("terraform is required but not installed. Run 'eos create terraform' first: %w", err)
		}

		outputDir, _ := cmd.Flags().GetString("output-dir")
		useCloud, _ := cmd.Flags().GetBool("cloud")
		serverType, _ := cmd.Flags().GetString("server-type")
		location, _ := cmd.Flags().GetString("location")
		domain, _ := cmd.Flags().GetString("domain")

		// Interactive prompts for missing values
		if domain == "" {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info(" Domain name required for mail server configuration")
			logger.Info("terminal prompt: Enter domain name for mail server: ")
			if _, err := fmt.Scanln(&domain); err != nil {
				logger.Error(" Failed to read domain input", zap.Error(err))
				return fmt.Errorf("failed to read domain: %w", err)
			}
			logger.Info(" Domain configured", zap.String("domain", domain))
		}

		serverName := "hecate-mail"
		if useCloud {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Info(" Server name configuration for cloud deployment")
			logger.Info("terminal prompt: Enter server name", zap.String("default", serverName))
			var input string
			if _, err := fmt.Scanln(&input); err != nil {
				// Empty input is acceptable (use default), but actual read errors should be handled
				if err.Error() != "unexpected newline" {
					logger.Error(" Failed to read server name input", zap.Error(err))
					return fmt.Errorf("failed to read server name: %w", err)
				}
			}
			if input != "" {
				serverName = input
			}
			logger.Info(" Server name configured", zap.String("server_name", serverName))
		}

		config := hecate.TerraformConfig{
			UseHetzner: useCloud,
			ServerName: serverName,
			ServerType: serverType,
			Location:   location,
			Domain:     domain,
		}

		logger.Info("Generating Hecate Terraform configuration",
			zap.String("domain", domain),
			zap.Bool("cloud", useCloud),
			zap.String("output_dir", outputDir))

		tfManager := terraform.NewManager(rc, outputDir)

		// Generate main.tf
		if err := tfManager.GenerateFromString(hecate.TerraformTemplate, "main.tf", config); err != nil {
			return fmt.Errorf("failed to generate main.tf: %w", err)
		}

		// Generate cloud-init if using cloud
		if useCloud {
			if err := tfManager.GenerateFromString(hecate.CloudInitTemplate, "hecate-cloud-init.yaml", config); err != nil {
				return fmt.Errorf("failed to generate cloud-init.yaml: %w", err)
			}
		}

		// Generate terraform.tfvars
		tfvarsContent := fmt.Sprintf(`# Terraform variables for Hecate deployment
domain = "%s"`, domain)

		if useCloud {
			tfvarsContent += fmt.Sprintf(`
# hcloud_token = "your-hetzner-cloud-token"
ssh_key_name = "your-ssh-key"
server_type = "%s"
location = "%s"`, serverType, location)
		}

		if err := os.WriteFile(filepath.Join(outputDir, "terraform.tfvars"), []byte(tfvarsContent), shared.ConfigFilePerm); err != nil {
			return fmt.Errorf("failed to generate terraform.tfvars: %w", err)
		}

		// Copy existing files if they exist
		configFiles := []string{"nginx.conf", "Caddyfile"}
		for _, file := range configFiles {
			if _, err := os.Stat(file); err == nil {
				content, err := os.ReadFile(file)
				if err == nil {
					destPath := filepath.Join(outputDir, file)
					if err := os.WriteFile(destPath, content, shared.ConfigFilePerm); err != nil {
						logger.Error("Failed to write configuration file", zap.String("file", file), zap.Error(err))
						return fmt.Errorf("failed to copy %s: %w", file, err)
					}
					logger.Info("Copied configuration file", zap.String("file", file))
				}
			}
		}

		// Initialize and validate
		if err := tfManager.Init(rc); err != nil {
			return fmt.Errorf("failed to initialize terraform: %w", err)
		}

		if err := tfManager.Validate(rc); err != nil {
			return fmt.Errorf("terraform configuration validation failed: %w", err)
		}

		if err := tfManager.Format(rc); err != nil {
			logger.Warn("Failed to format terraform files", zap.Error(err))
		}

		logger.Info("terminal prompt: Hecate Terraform configuration generated in", zap.String("directory", outputDir))
		logger.Info("terminal prompt: \nNext steps:")
		if useCloud {
			logger.Info("terminal prompt: 1. Set your Hetzner Cloud token: export HCLOUD_TOKEN='your-token'")
			logger.Info("terminal prompt: 2. Update terraform.tfvars with your SSH key name")
		}
		logger.Info("terminal prompt: 3. Review the configuration", zap.String("command", "cd "+outputDir))
		logger.Info("terminal prompt: 4. Plan the deployment: terraform plan")
		logger.Info("terminal prompt: 5. Apply the configuration: terraform apply")

		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(hecateTerraformCmd)

	hecateTerraformCmd.Flags().String("output-dir", "./terraform-hecate", "Output directory for Terraform files")
	hecateTerraformCmd.Flags().Bool("cloud", false, "Deploy to cloud infrastructure")
	hecateTerraformCmd.Flags().String("server-type", "cx21", "Server type for cloud instance")
	hecateTerraformCmd.Flags().String("location", "nbg1", "Location for cloud instance")
	hecateTerraformCmd.Flags().String("domain", "", "Domain name for the mail server")
}

// All helper functions have been migrated to pkg/hecate/
