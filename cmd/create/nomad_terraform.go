// cmd/create/nomad_terraform.go
package create

import (
	"fmt"
	"os"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/terraform"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var CreateNomadTerraformCmd = &cobra.Command{
	Use:   "nomad-terraform",
	Short: "Generate Terraform configuration for Nomad+Consul cluster (replaces K3s Terraform)",
	Long: `Generate Terraform configuration for deploying Nomad+Consul clusters.
This replaces the deprecated K3s Terraform templates with modern Nomad orchestration.

The generated Terraform configuration includes:
- Nomad cluster (servers and clients)
- Consul cluster for service discovery
- Caddy ingress for HTTP/HTTPS
- Nginx mail proxy (optional)
- Cloud infrastructure (Hetzner, AWS, etc.)
- Load balancers and networking
- Security groups and firewall rules

This provides the same infrastructure capabilities as K3s but with simpler Nomad orchestration.

Examples:
  # Local cluster
  eos create nomad-terraform --domain=example.com

  # Cloud cluster on Hetzner
  eos create nomad-terraform --domain=example.com --cloud --provider=hetzner

  # Cluster with mail proxy
  eos create nomad-terraform --domain=example.com --enable-mail --mail-backend=stalwart-mail`,
	RunE: eos.Wrap(runCreateNomadTerraform),
}

func runCreateNomadTerraform(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Generating Nomad+Consul Terraform configuration")

	// Parse flags
	domain, _ := cmd.Flags().GetString("domain")
	outputDir, _ := cmd.Flags().GetString("output-dir")
	cloudDeploy, _ := cmd.Flags().GetBool("cloud")
	provider, _ := cmd.Flags().GetString("provider")
	clusterName, _ := cmd.Flags().GetString("cluster-name")
	nodeCount, _ := cmd.Flags().GetInt("node-count")
	serverCount, _ := cmd.Flags().GetInt("server-count")
	enableMail, _ := cmd.Flags().GetBool("enable-mail")
	mailBackend, _ := cmd.Flags().GetString("mail-backend")
	serverType, _ := cmd.Flags().GetString("server-type")
	location, _ := cmd.Flags().GetString("location")

	// Validate required parameters
	if domain == "" {
		return fmt.Errorf("domain is required (use --domain)")
	}

	if cloudDeploy && provider == "" {
		return fmt.Errorf("provider is required for cloud deployment (use --provider)")
	}

	// Setup configuration
	config := terraform.GetDefaultNomadConsulConfig()
	config.CloudDeploy = cloudDeploy
	config.ClusterName = clusterName
	config.NodeCount = nodeCount
	config.ServerCount = serverCount
	config.ServerType = serverType
	config.Location = location
	config.EnableMailProxy = enableMail
	config.MailBackend = mailBackend

	logger.Info("Generating Terraform configuration",
		zap.String("domain", domain),
		zap.String("cluster_name", clusterName),
		zap.Bool("cloud_deploy", cloudDeploy),
		zap.String("provider", provider),
		zap.Bool("enable_mail", enableMail))

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Create terraform manager
	tfManager := terraform.NewManager(rc, outputDir)

	// Generate main.tf
	if err := tfManager.GenerateFromString(terraform.NomadConsulTemplate, "main.tf", config); err != nil {
		return fmt.Errorf("failed to generate main.tf: %w", err)
	}

	// Generate cloud-init if using cloud deployment
	if cloudDeploy {
		if err := tfManager.GenerateFromString(terraform.NomadConsulCloudInit, "nomad-consul-init.yaml", config); err != nil {
			return fmt.Errorf("failed to generate cloud-init.yaml: %w", err)
		}
	}

	// Create jobs directory for Nomad job files
	jobsDir := filepath.Join(outputDir, "jobs")
	if err := os.MkdirAll(jobsDir, 0755); err != nil {
		return fmt.Errorf("failed to create jobs directory: %w", err)
	}

	// Generate Caddy ingress job
	caddyJobPath := filepath.Join(jobsDir, "caddy-ingress.nomad")
	if err := os.WriteFile(caddyJobPath, []byte(terraform.CaddyIngressNomadJob), 0644); err != nil {
		return fmt.Errorf("failed to generate Caddy job file: %w", err)
	}

	// Generate Nginx mail job if enabled
	if enableMail {
		nginxJobPath := filepath.Join(jobsDir, "nginx-mail.nomad")
		if err := os.WriteFile(nginxJobPath, []byte(terraform.NginxMailNomadJob), 0644); err != nil {
			return fmt.Errorf("failed to generate Nginx job file: %w", err)
		}
	}

	// Generate terraform.tfvars
	tfvarsContent := fmt.Sprintf(`# Terraform variables for Nomad+Consul deployment
domain = "%s"

# Cluster configuration
node_count = %d
server_count = %d
`, domain, nodeCount, serverCount)

	if cloudDeploy {
		tfvarsContent += fmt.Sprintf(`
# Cloud deployment settings (%s)
hcloud_token = "your-hetzner-cloud-token"  # Set your token here
ssh_key_name = "your-ssh-key"              # Set your SSH key name
server_type = "%s"
location = "%s"
`, provider, serverType, location)
	}

	if err := os.WriteFile(filepath.Join(outputDir, "terraform.tfvars"), []byte(tfvarsContent), 0644); err != nil {
		return fmt.Errorf("failed to generate terraform.tfvars: %w", err)
	}

	// Generate deployment script
	deployScript := fmt.Sprintf(`#!/bin/bash
# Deployment script for %s Nomad+Consul cluster

set -e

echo "🚀 Deploying Nomad+Consul cluster..."

# Initialize Terraform
terraform init

# Validate configuration
terraform validate

# Plan deployment
terraform plan

# Apply (with confirmation)
echo "Ready to deploy Nomad+Consul cluster. Continue? (y/N)"
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    terraform apply
    
    echo " Deployment complete!"
    echo ""
    echo "🎯 Cluster Details:"
    echo "   - Cluster: %s"
    echo "   - Domain: %s"
    echo "   - Nodes: %d (%d servers, %d clients)"
    echo ""
    echo "🌐 Access URLs:"
    %s
    echo ""
    echo "📋 Next Steps:"
    echo "1. Update DNS to point %s to the load balancer IP"
    echo "2. Deploy applications: nomad job run <job-file>"
    echo "3. Check cluster status: nomad server members"
    echo "4. View Consul services: consul catalog services"
    %s
else
    echo "Deployment cancelled"
fi
`, clusterName, clusterName, domain, nodeCount, serverCount, nodeCount-serverCount,
		func() string {
			if cloudDeploy {
				return `   echo "   - Nomad UI: http://$(terraform output -raw load_balancer_ip):4646"
   echo "   - Consul UI: http://$(terraform output -raw load_balancer_ip):8500"
   echo "   - Ingress: https://$(terraform output -raw load_balancer_ip)"`
			} else {
				return `   echo "   - Nomad UI: http://localhost:4646"
   echo "   - Consul UI: http://localhost:8500"
   echo "   - Ingress: https://localhost"`
			}
		}(),
		domain,
		func() string {
			if enableMail {
				return `echo "5. Configure mail routing and SSL certificates"`
			}
			return ""
		}())

	if err := os.WriteFile(filepath.Join(outputDir, "deploy.sh"), []byte(deployScript), 0755); err != nil {
		return fmt.Errorf("failed to generate deploy script: %w", err)
	}

	// Initialize and validate Terraform
	if err := tfManager.Init(rc); err != nil {
		return fmt.Errorf("failed to initialize terraform: %w", err)
	}

	if err := tfManager.Validate(rc); err != nil {
		return fmt.Errorf("terraform configuration validation failed: %w", err)
	}

	if err := tfManager.Format(rc); err != nil {
		logger.Warn("Failed to format terraform files", zap.Error(err))
	}

	logger.Info("Nomad+Consul Terraform configuration generated successfully")
	logger.Info("terminal prompt:  Nomad+Consul Terraform Generation Complete!")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Configuration Details:")
	logger.Info("terminal prompt:   - Cluster: " + clusterName)
	logger.Info("terminal prompt:   - Domain: " + domain)
	logger.Info("terminal prompt:   - Orchestration: Nomad + Consul (replaces K3s)")
	logger.Info("terminal prompt:   - Ingress: Caddy (replaces Traefik)")
	if enableMail {
		logger.Info("terminal prompt:   - Mail Proxy: Nginx")
	}
	if cloudDeploy {
		logger.Info("terminal prompt:   - Cloud Provider: " + provider)
		logger.Info("terminal prompt:   - Nodes: " + fmt.Sprintf("%d (%d servers)", nodeCount, serverCount))
	}
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Generated Files:")
	logger.Info("terminal prompt:   - " + outputDir + "/main.tf")
	logger.Info("terminal prompt:   - " + outputDir + "/terraform.tfvars")
	logger.Info("terminal prompt:   - " + outputDir + "/jobs/caddy-ingress.nomad")
	if enableMail {
		logger.Info("terminal prompt:   - " + outputDir + "/jobs/nginx-mail.nomad")
	}
	if cloudDeploy {
		logger.Info("terminal prompt:   - " + outputDir + "/nomad-consul-init.yaml")
	}
	logger.Info("terminal prompt:   - " + outputDir + "/deploy.sh")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Quick Start:")
	logger.Info("terminal prompt:   cd " + outputDir)
	if cloudDeploy {
		logger.Info("terminal prompt:   # Update terraform.tfvars with your credentials")
		logger.Info("terminal prompt:   export HCLOUD_TOKEN='your-token'")
	}
	logger.Info("terminal prompt:   ./deploy.sh")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: This configuration replaces K3s with simpler Nomad orchestration.")

	return nil
}

func init() {
	CreateCmd.AddCommand(CreateNomadTerraformCmd)

	// Basic configuration
	CreateNomadTerraformCmd.Flags().String("domain", "", "Primary domain for the cluster")
	CreateNomadTerraformCmd.Flags().String("output-dir", "./nomad-consul-terraform", "Output directory for Terraform files")
	CreateNomadTerraformCmd.Flags().String("cluster-name", "nomad-consul-cluster", "Name for the cluster")
	CreateNomadTerraformCmd.MarkFlagRequired("domain")

	// Cloud deployment
	CreateNomadTerraformCmd.Flags().Bool("cloud", false, "Deploy to cloud infrastructure")
	CreateNomadTerraformCmd.Flags().String("provider", "hetzner", "Cloud provider (hetzner, aws, gcp)")
	CreateNomadTerraformCmd.Flags().String("server-type", "cx21", "Server type for cloud instances")
	CreateNomadTerraformCmd.Flags().String("location", "nbg1", "Location for cloud instances")

	// Cluster sizing
	CreateNomadTerraformCmd.Flags().Int("node-count", 3, "Total number of nodes in the cluster")
	CreateNomadTerraformCmd.Flags().Int("server-count", 3, "Number of server nodes (must be odd)")

	// Optional features
	CreateNomadTerraformCmd.Flags().Bool("enable-mail", false, "Include Nginx mail proxy configuration")
	CreateNomadTerraformCmd.Flags().String("mail-backend", "stalwart-mail", "Backend service for mail proxy")
}
