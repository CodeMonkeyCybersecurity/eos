// cmd/create/hecate_terraform.go

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

var hecateTerraformCmd = &cobra.Command{
	Use:   "hecate-terraform",
	Short: "Generate Terraform configuration for Hecate mail server deployment",
	Long: `Generate Terraform configuration for Hecate mail server with Stalwart, Caddy, and Nginx.
Supports both local Docker deployment and cloud infrastructure provisioning.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return generateHecateTerraform(rc, cmd)
	}),
}

const HecateTerraformTemplate = `
terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
    {{if .UseHetzner}}
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.0"
    }
    {{end}}
  }
}

provider "docker" {
  {{if .DockerHost}}
  host = "{{.DockerHost}}"
  {{end}}
}

{{if .UseHetzner}}
provider "hcloud" {
  token = var.hcloud_token
}

variable "hcloud_token" {
  description = "Hetzner Cloud API Token"
  type        = string
  sensitive   = true
}

resource "hcloud_server" "hecate" {
  name        = "{{.ServerName}}"
  image       = "ubuntu-22.04"
  server_type = "{{.ServerType}}"
  location    = "{{.Location}}"
  ssh_keys    = [data.hcloud_ssh_key.key.id]

  user_data = templatefile("${path.module}/hecate-cloud-init.yaml", {
    domain = var.domain
  })

  labels = {
    type = "hecate"
    role = "mail-server"
  }
}

data "hcloud_ssh_key" "key" {
  name = var.ssh_key_name
}

resource "hcloud_firewall" "hecate" {
  name = "{{.ServerName}}-hecate-firewall"
  
  # SSH
  rule {
    direction = "in"
    port      = "22"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  # HTTP/HTTPS
  rule {
    direction = "in"
    port      = "80"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    port      = "443"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  # Mail ports
  rule {
    direction = "in"
    port      = "25"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    port      = "587"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    port      = "465"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    port      = "110"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    port      = "995"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    port      = "143"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    port      = "993"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    port      = "4190"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }
}

resource "hcloud_firewall_attachment" "hecate" {
  firewall_id = hcloud_firewall.hecate.id
  server_ids  = [hcloud_server.hecate.id]
}

variable "ssh_key_name" {
  description = "SSH key name in Hetzner Cloud"
  type        = string
}

variable "domain" {
  description = "Domain name for the mail server"
  type        = string
}

output "server_ip" {
  value = hcloud_server.hecate.ipv4_address
}
{{end}}

# Docker Networks
resource "docker_network" "hecate_net" {
  name = "hecate-net"
}

# Docker Volumes
resource "docker_volume" "stalwart_data" {
  name = "stalwart_data"
}

# Stalwart Mail Server
resource "docker_image" "stalwart" {
  name = "stalwartlabs/stalwart:latest"
}

resource "docker_container" "stalwart" {
  name  = "hecate-stalwart"
  image = docker_image.stalwart.image_id
  
  restart = "always"
  
  ports {
    internal = 8080
    external = 8080
    protocol = "tcp"
  }
  
  volumes {
    volume_name    = docker_volume.stalwart_data.name
    container_path = "/opt/stalwart"
  }
  
  networks_advanced {
    name = docker_network.hecate_net.name
  }
}

# Caddy
resource "docker_image" "caddy" {
  name = "caddy:latest"
}

resource "docker_container" "caddy" {
  name  = "hecate-caddy"
  image = docker_image.caddy.image_id
  
  restart = "always"
  
  ports {
    internal = 80
    external = 80
    protocol = "tcp"
  }
  
  ports {
    internal = 443
    external = 443
    protocol = "tcp"
  }
  
  volumes {
    host_path      = "./Caddyfile"
    container_path = "/etc/caddy/Caddyfile"
    read_only      = true
  }
  
  volumes {
    host_path      = "./certs"
    container_path = "/data/caddy/certs"
  }
  
  volumes {
    host_path      = "./logs/caddy"
    container_path = "/var/log/caddy"
  }
  
  volumes {
    host_path      = "./assets/error_pages"
    container_path = "/usr/share/nginx/html"
    read_only      = true
  }
  
  networks_advanced {
    name = docker_network.hecate_net.name
  }
}

# Nginx
resource "docker_image" "nginx" {
  name = "nginx:alpine"
}

resource "docker_container" "nginx" {
  name  = "hecate-nginx"
  image = docker_image.nginx.image_id
  
  restart = "always"
  
  # Mail ports
  ports {
    internal = 25
    external = 25
    protocol = "tcp"
  }
  
  ports {
    internal = 587
    external = 587
    protocol = "tcp"
  }
  
  ports {
    internal = 465
    external = 465
    protocol = "tcp"
  }
  
  ports {
    internal = 110
    external = 110
    protocol = "tcp"
  }
  
  ports {
    internal = 995
    external = 995
    protocol = "tcp"
  }
  
  ports {
    internal = 143
    external = 143
    protocol = "tcp"
  }
  
  ports {
    internal = 993
    external = 993
    protocol = "tcp"
  }
  
  ports {
    internal = 4190
    external = 4190
    protocol = "tcp"
  }
  
  volumes {
    host_path      = "./nginx.conf"
    container_path = "/etc/nginx/nginx.conf"
    read_only      = true
  }
  
  volumes {
    host_path      = "./logs"
    container_path = "/var/log/nginx"
  }
  
  volumes {
    host_path      = "./certs"
    container_path = "/opt/hecate/certs"
    read_only      = true
  }
  
  networks_advanced {
    name = docker_network.hecate_net.name
  }
}

output "container_ips" {
  value = {
    stalwart = docker_container.stalwart.network_data[0].ip_address
    caddy    = docker_container.caddy.network_data[0].ip_address
    nginx    = docker_container.nginx.network_data[0].ip_address
  }
}
`

const HecateCloudInitTemplate = `#cloud-config
package_update: true
package_upgrade: true

packages:
  - docker.io
  - docker-compose
  - curl
  - wget

runcmd:
  - systemctl enable docker
  - systemctl start docker
  - usermod -aG docker ubuntu
  - mkdir -p /opt/hecate
  - cd /opt/hecate
  - |
    cat > docker-compose.yml << 'EOF'
    # Your original docker-compose.yml content would go here
    # This is managed by Terraform instead
    EOF
  - docker-compose up -d

write_files:
  - path: /opt/hecate/Caddyfile
    content: |
      # Caddyfile configuration
      {{.domain}} {
        reverse_proxy hecate-stalwart:8080
      }
`

type HecateConfig struct {
	UseHetzner bool
	DockerHost string
	ServerName string
	ServerType string
	Location   string
	Domain     string
}

func generateHecateTerraform(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
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
		fmt.Print("Enter domain name for mail server: ")
		if _, err := fmt.Scanln(&domain); err != nil {
			return err
		}
	}

	serverName := "hecate-mail"
	if useCloud {
		fmt.Printf("Enter server name [%s]: ", serverName)
		var input string
		if _, err := fmt.Scanln(&input); err != nil {
			return err
		}
		if input != "" {
			serverName = input
		}
	}

	config := HecateConfig{
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
	if err := tfManager.GenerateFromString(HecateTerraformTemplate, "main.tf", config); err != nil {
		return fmt.Errorf("failed to generate main.tf: %w", err)
	}

	// Generate cloud-init if using cloud
	if useCloud {
		if err := tfManager.GenerateFromString(HecateCloudInitTemplate, "hecate-cloud-init.yaml", config); err != nil {
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

	if err := os.WriteFile(filepath.Join(outputDir, "terraform.tfvars"), []byte(tfvarsContent), 0644); err != nil {
		return fmt.Errorf("failed to generate terraform.tfvars: %w", err)
	}

	// Copy existing files if they exist
	configFiles := []string{"nginx.conf", "Caddyfile"}
	for _, file := range configFiles {
		if _, err := os.Stat(file); err == nil {
			content, err := os.ReadFile(file)
			if err == nil {
				destPath := filepath.Join(outputDir, file)
				if err := os.WriteFile(destPath, content, 0644); err != nil {
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

	fmt.Printf("\n✅ Hecate Terraform configuration generated in: %s\n", outputDir)
	fmt.Println("\nNext steps:")
	if useCloud {
		fmt.Println("1. Set your Hetzner Cloud token: export HCLOUD_TOKEN='your-token'")
		fmt.Println("2. Update terraform.tfvars with your SSH key name")
	}
	fmt.Printf("3. Review the configuration: cd %s\n", outputDir)
	fmt.Println("4. Plan the deployment: terraform plan")
	fmt.Println("5. Apply the configuration: terraform apply")

	return nil
}

func init() {
	CreateCmd.AddCommand(hecateTerraformCmd)

	hecateTerraformCmd.Flags().String("output-dir", "./terraform-hecate", "Output directory for Terraform files")
	hecateTerraformCmd.Flags().Bool("cloud", false, "Deploy to cloud infrastructure")
	hecateTerraformCmd.Flags().String("server-type", "cx21", "Server type for cloud instance")
	hecateTerraformCmd.Flags().String("location", "nbg1", "Location for cloud instance")
	hecateTerraformCmd.Flags().String("domain", "", "Domain name for the mail server")
}
