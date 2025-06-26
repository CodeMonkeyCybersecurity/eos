// cmd/create/k3s_caddy_nginx.go

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

var k3sCaddyNginxCmd = &cobra.Command{
	Use:   "k3s-caddy-nginx",
	Short: "Deploy K3s with Caddy (HTTP/HTTPS) and Nginx (mail) instead of Traefik",
	Long: `Deploy K3s cluster with Caddy as HTTP/HTTPS ingress controller and Nginx as mail proxy.
This replaces the default Traefik ingress with a familiar Caddy + Nginx setup.

Features:
- K3s without Traefik
- Caddy for HTTP/HTTPS with automatic SSL
- Nginx for mail proxy (SMTP/IMAP/POP3)
- MetalLB for LoadBalancer services
- Cloud deployment support (Hetzner)`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return generateK3sCaddyNginx(rc, cmd)
	}),
}

func generateK3sCaddyNginx(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)

	if err := terraform.CheckTerraformInstalled(); err != nil {
		return fmt.Errorf("terraform is required but not installed. Run 'eos create terraform' first: %w", err)
	}

	// Get flags
	outputDir, _ := cmd.Flags().GetString("output-dir")
	cloudDeploy, _ := cmd.Flags().GetBool("cloud")
	domain, _ := cmd.Flags().GetString("domain")
	clusterName, _ := cmd.Flags().GetString("cluster-name")
	serverType, _ := cmd.Flags().GetString("server-type")
	location, _ := cmd.Flags().GetString("location")
	enableMail, _ := cmd.Flags().GetBool("enable-mail")

	// Interactive prompts for missing values
	if domain == "" {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info(" Primary domain required for cluster configuration")
		fmt.Print("Enter primary domain for the cluster: ")
		if _, err := fmt.Scanln(&domain); err != nil {
			logger.Error(" Failed to read domain input", zap.Error(err))
			return fmt.Errorf("failed to read domain: %w", err)
		}
		logger.Info(" Domain configured", zap.String("domain", domain))
	}

	if clusterName == "" {
		logger := otelzap.Ctx(rc.Ctx)
		clusterName = "k3s-cluster"
		logger.Info(" Cluster name configuration")
		fmt.Printf("Enter cluster name [%s]: ", clusterName)
		var input string
		if _, err := fmt.Scanln(&input); err != nil {
			// Empty input is acceptable (use default), but actual read errors should be handled
			if err.Error() != "unexpected newline" {
				logger.Error(" Failed to read cluster name input", zap.Error(err))
				return fmt.Errorf("failed to read cluster name: %w", err)
			}
		}
		if input != "" {
			clusterName = input
		}
		logger.Info(" Cluster name configured", zap.String("cluster_name", clusterName))
	}

	// Configure mail ports
	mailPorts := []int{}
	if enableMail {
		mailPorts = []int{25, 587, 465, 110, 995, 143, 993, 4190}
	}

	config := terraform.K3sCaddyNginxConfig{
		CloudDeploy:        cloudDeploy,
		ClusterName:        clusterName,
		ServerType:         serverType,
		Location:           location,
		Domain:             domain,
		CaddyVersion:       "2.7-alpine",
		NginxVersion:       "1.24-alpine",
		CaddyReplicas:      2,
		NginxReplicas:      1,
		CaddyAdminEnabled:  true,
		CaddyStorageSize:   "1Gi",
		CaddyMemoryRequest: "128Mi",
		CaddyCPURequest:    "100m",
		CaddyMemoryLimit:   "256Mi",
		CaddyCPULimit:      "200m",
		NginxMemoryRequest: "64Mi",
		NginxCPURequest:    "50m",
		NginxMemoryLimit:   "128Mi",
		NginxCPULimit:      "100m",
		MailPorts:          mailPorts,
		MailBackend:        "stalwart-mail.default.svc.cluster.local",
	}

	logger.Info("Generating K3s + Caddy + Nginx configuration",
		zap.String("domain", domain),
		zap.String("cluster", clusterName),
		zap.Bool("cloud", cloudDeploy),
		zap.Bool("enable_mail", enableMail),
		zap.String("output_dir", outputDir))

	tfManager := terraform.NewManager(rc, outputDir)

	// Generate main.tf
	if err := tfManager.GenerateFromString(terraform.K3sCaddyNginxTemplate, "main.tf", config); err != nil {
		return fmt.Errorf("failed to generate main.tf: %w", err)
	}

	// Generate cloud-init if using cloud
	if cloudDeploy {
		if err := tfManager.GenerateFromString(terraform.K3sCaddyNginxCloudInit, "k3s-cloud-init.yaml", config); err != nil {
			return fmt.Errorf("failed to generate cloud-init.yaml: %w", err)
		}
	}

	// Create config directory and files
	configDir := filepath.Join(outputDir, "config")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Generate Caddyfile template
	caddyfileContent := fmt.Sprintf(`# Caddyfile Template for %s
%s {
    # Health check endpoint
    handle /health {
        respond "OK" 200
    }
    
    # Default backend - update this to point to your services
    reverse_proxy /* {
        to http://backend-service.default.svc.cluster.local:80
        health_uri /health
        health_interval 30s
    }
    
    # Automatic HTTPS
    tls {
        protocols tls1.2 tls1.3
    }
    
    # Security headers
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        X-XSS-Protection "1; mode=block"
        Referrer-Policy "strict-origin-when-cross-origin"
        -Server
    }
    
    # Logging
    log {
        output file /var/log/caddy/access.log
        format console
    }
}

# Admin API (for metrics and management)
:2019 {
    metrics /metrics
    handle /config/* {
        admin
    }
}
`, clusterName, domain)

	if err := os.WriteFile(filepath.Join(configDir, "Caddyfile.tpl"), []byte(caddyfileContent), 0644); err != nil {
		return fmt.Errorf("failed to generate Caddyfile template: %w", err)
	}

	// Generate nginx mail config if mail is enabled
	if enableMail {
		nginxMailContent := fmt.Sprintf(`# Nginx Mail Proxy Configuration
user  nginx;
worker_processes  auto;

error_log  /var/log/nginx/error.log notice;
pid        /var/run/nginx.pid;

events {
    worker_connections  1024;
}

mail {
    server_name %s;
    auth_http http://%s:8080/auth;
    
    proxy_pass_error_message on;
    proxy_timeout 1m;
    proxy_connect_timeout 15s;
    
    # SMTP
    server {
        listen 25;
        protocol smtp;
        smtp_auth login plain;
        xclient off;
    }
    
    # Submission
    server {
        listen 587;
        protocol smtp;
        smtp_auth login plain;
        starttls on;
        xclient off;
    }
    
    # Submission with SSL
    server {
        listen 465 ssl;
        protocol smtp;
        smtp_auth login plain;
        xclient off;
        ssl_certificate /etc/nginx/certs/fullchain.pem;
        ssl_certificate_key /etc/nginx/certs/privkey.pem;
    }
    
    # IMAP
    server {
        listen 143;
        protocol imap;
        starttls on;
    }
    
    # IMAPS
    server {
        listen 993 ssl;
        protocol imap;
        ssl_certificate /etc/nginx/certs/fullchain.pem;
        ssl_certificate_key /etc/nginx/certs/privkey.pem;
    }
    
    # POP3
    server {
        listen 110;
        protocol pop3;
        starttls on;
    }
    
    # POP3S
    server {
        listen 995 ssl;
        protocol pop3;
        ssl_certificate /etc/nginx/certs/fullchain.pem;
        ssl_certificate_key /etc/nginx/certs/privkey.pem;
    }
    
    # Sieve
    server {
        listen 4190;
        protocol smtp;
        smtp_auth login plain;
        starttls on;
    }
}

# HTTP for health checks and auth
http {
    upstream auth_backend {
        server %s:8080;
    }
    
    server {
        listen 8080;
        
        location /auth {
            proxy_pass http://auth_backend;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            proxy_set_header X-Original-URI $request_uri;
        }
        
        location /health {
            return 200 "OK\n";
            add_header Content-Type text/plain;
        }
    }
}
`, domain, config.MailBackend, config.MailBackend)

		if err := os.WriteFile(filepath.Join(configDir, "nginx-mail.conf.tpl"), []byte(nginxMailContent), 0644); err != nil {
			return fmt.Errorf("failed to generate nginx mail config: %w", err)
		}
	}

	// Generate terraform.tfvars
	tfvarsContent := fmt.Sprintf(`# Terraform variables for K3s + Caddy + Nginx deployment
domain = "%s"
caddy_admin_enabled = true
`, domain)

	if cloudDeploy {
		tfvarsContent += fmt.Sprintf(`
# Cloud deployment settings
# hcloud_token = "your-hetzner-cloud-token"
ssh_key_name = "your-ssh-key"
server_type = "%s"
location = "%s"
`, serverType, location)
	}

	if err := os.WriteFile(filepath.Join(outputDir, "terraform.tfvars"), []byte(tfvarsContent), 0644); err != nil {
		return fmt.Errorf("failed to generate terraform.tfvars: %w", err)
	}

	// Generate deployment script
	deployScript := fmt.Sprintf(`#!/bin/bash
# Deployment script for %s

set -e

echo " Deploying K3s cluster with Caddy + Nginx..."

# Initialize Terraform
terraform init

# Validate configuration
terraform validate

# Plan deployment
terraform plan

# Apply (with confirmation)
echo "Ready to deploy. Continue? (y/N)"
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    terraform apply
    
    echo " Deployment complete!"
    echo ""
    echo " Next steps:"
    echo "1. Update your DNS to point %s to the LoadBalancer IP"
    echo "2. Deploy your applications to the cluster"
    echo "3. Configure Caddy routing in config/Caddyfile.tpl"
    %s
    echo ""
    echo " Useful commands:"
    echo "  kubectl get pods -n ingress-system"
    echo "  kubectl logs -n ingress-system deployment/caddy-ingress"
    %s
else
    echo "Deployment cancelled"
fi
`, clusterName, domain,
		func() string {
			if enableMail {
				return "4. Configure mail routing and SSL certificates"
			}
			return ""
		}(),
		func() string {
			if enableMail {
				return "  kubectl logs -n ingress-system deployment/nginx-mail-proxy"
			}
			return ""
		}())

	if err := os.WriteFile(filepath.Join(outputDir, "deploy.sh"), []byte(deployScript), 0755); err != nil {
		return fmt.Errorf("failed to generate deploy script: %w", err)
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

	fmt.Printf("\n K3s + Caddy + Nginx configuration generated in: %s\n", outputDir)
	fmt.Println("\n What you get:")
	fmt.Println("  • K3s cluster without Traefik")
	fmt.Println("  • Caddy for HTTP/HTTPS ingress (familiar reverse proxy)")
	fmt.Println("  • Nginx for mail protocols (SMTP/IMAP/POP3)")
	fmt.Println("  • MetalLB for LoadBalancer services")
	fmt.Println("  • Automatic SSL with Let's Encrypt")

	if enableMail {
		fmt.Println("  • Mail proxy configuration")
	}

	fmt.Println("\n Generated files:")
	fmt.Printf("  %s/main.tf - Main Terraform configuration\n", outputDir)
	fmt.Printf("  %s/config/Caddyfile.tpl - Caddy configuration template\n", outputDir)
	if enableMail {
		fmt.Printf("  %s/config/nginx-mail.conf.tpl - Nginx mail proxy config\n", outputDir)
	}
	fmt.Printf("  %s/deploy.sh - Deployment script\n", outputDir)

	fmt.Println("\n⚡ Quick start:")
	fmt.Printf("  cd %s\n", outputDir)
	if cloudDeploy {
		fmt.Println("  export HCLOUD_TOKEN='your-token'")
		fmt.Println("  # Update terraform.tfvars with your SSH key")
	}
	fmt.Println("  ./deploy.sh")

	return nil
}

func init() {
	CreateCmd.AddCommand(k3sCaddyNginxCmd)

	k3sCaddyNginxCmd.Flags().String("output-dir", "./k3s-caddy-nginx", "Output directory for Terraform files")
	k3sCaddyNginxCmd.Flags().Bool("cloud", false, "Deploy to cloud infrastructure (Hetzner)")
	k3sCaddyNginxCmd.Flags().String("domain", "", "Primary domain for the cluster")
	k3sCaddyNginxCmd.Flags().String("cluster-name", "k3s-cluster", "Name for the K3s cluster")
	k3sCaddyNginxCmd.Flags().String("server-type", "cx21", "Server type for cloud instance")
	k3sCaddyNginxCmd.Flags().String("location", "nbg1", "Location for cloud instance")
	k3sCaddyNginxCmd.Flags().Bool("enable-mail", false, "Include Nginx mail proxy configuration")
}
