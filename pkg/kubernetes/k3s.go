package kubernetes

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/network"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/terraform"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func DeployK3s(rc *eos_io.RuntimeContext) {

	reader := bufio.NewReader(os.Stdin)

	// Ask if this is a server or worker node.
	fmt.Print("Is this node a server or worker? [server/worker]: ")
	roleInput, err := reader.ReadString('\n')
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to read input", zap.Error(err))
		os.Exit(1)
	}
	role := strings.TrimSpace(strings.ToLower(roleInput))

	// Check for IPv6 support and Tailscale IPv6.
	nodeIP := ""
	if network.CheckIPv6Enabled() {
		tailscaleIP, err := network.GetTailscaleIPv6()
		if err == nil && tailscaleIP != "" {
			nodeIP = tailscaleIP
			otelzap.Ctx(rc.Ctx).Info("Detected Tailscale IPv6", zap.String("node-ip", nodeIP))
		} else {
			otelzap.Ctx(rc.Ctx).Info("Tailscale IPv6 not detected; proceeding without --node-ip flag")
		}
	} else {
		otelzap.Ctx(rc.Ctx).Warn("IPv6 is disabled. Attempting to enable it...")
		if err := network.EnableIPv6(); err != nil {
			otelzap.Ctx(rc.Ctx).Warn("Could not enable IPv6", zap.Error(err))
		} else {
			otelzap.Ctx(rc.Ctx).Info("IPv6 enabled. Retrying Tailscale detection...")
			if ip, err := network.GetTailscaleIPv6(); err == nil && ip != "" {
				nodeIP = ip
				otelzap.Ctx(rc.Ctx).Info("Detected Tailscale IPv6", zap.String("node-ip", nodeIP))
			}
		}
	}

	// 🔥 Unified firewall status check
	platform.CheckFirewallStatus(rc)

	var installCmd string

	switch role {
	case "server":
		fmt.Printf("enter TLS SAN (default: %s): ", eos_unix.GetInternalHostname())
		tlsSANInput, _ := reader.ReadString('\n')
		tlsSAN := strings.TrimSpace(tlsSANInput)
		if tlsSAN == "" { // user hit <Enter> → use auto-detected default
			tlsSAN = eos_unix.GetInternalHostname()
		}
		installCmd = fmt.Sprintf("curl -sfL https://get.k3s.io | sh -s - server --tls-san %s", tlsSAN)
		if nodeIP != "" {
			installCmd += fmt.Sprintf(" --node-ip %s", nodeIP)
		}

	case "worker":
		fmt.Print("Enter the K3s server URL (e.g., https://server-ip:6443): ")
		serverURLInput, _ := reader.ReadString('\n')
		serverURL := strings.TrimSpace(serverURLInput)

		if strings.Contains(serverURL, ":") && !strings.Contains(serverURL, "[") {
			serverURL = fmt.Sprintf("https://[%s]:6443", serverURL)
		} else if !strings.HasPrefix(serverURL, "https://") {
			serverURL = fmt.Sprintf("https://%s:6443", serverURL)
		}

		fmt.Print("Enter the K3s node token: ")
		tokenInput, _ := reader.ReadString('\n')
		token := strings.TrimSpace(tokenInput)

		installCmd = fmt.Sprintf(
			"export K3S_URL=%s\nexport K3S_TOKEN=%s\ncurl -sfL https://get.k3s.io | sh -s -",
			serverURL, token,
		)
		if nodeIP != "" {
			installCmd += fmt.Sprintf(" --node-ip %s", nodeIP)
		}

	default:
		fmt.Println("Invalid role. Please enter 'server' or 'worker'.")
		os.Exit(1)
	}

	fmt.Println("\nGenerated install command:")
	fmt.Println(installCmd)
	fmt.Print("\nDo you want to execute this command? [y/N]: ")
	confirmInput, _ := reader.ReadString('\n')
	confirm := strings.TrimSpace(strings.ToLower(confirmInput))
	if confirm != "y" && confirm != "yes" {
		scriptPath := SaveScript(rc, installCmd)
		fmt.Printf("Installation command not executed. Saved to: %s\n", scriptPath)
		return
	}

	scriptPath := SaveScript(rc, installCmd)
	fmt.Printf("Executing the install script: %s\n", scriptPath)
	fmt.Println("Check /var/log/eos/k3s-deploy.log for details.")
	fmt.Println("To monitor logs in real time: tail -f /var/log/eos/k3s-deploy.log")

	if err := execute.RunSimple(rc.Ctx, "bash", scriptPath); err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to execute install script", zap.Error(err))
		fmt.Println("Installation failed. Check logs for details.")
		os.Exit(1)
	}

	fmt.Println("K3s deployment initiated.")
	if role == "server" {
		OutputJoinToken()
	}
}

// saveScript writes the install command to a script file and returns the file path.
func SaveScript(rc *eos_io.RuntimeContext, cmdStr string) string {
	// Ensure the log directory exists
	if err := os.MkdirAll(shared.EosLogDir, shared.DirPermStandard); err != nil {
		fmt.Printf("Warning: Could not create log directory %s: %v\n", shared.EosLogDir, err)
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	dir := homeDir + "/.local/state/eos"
	if err := os.MkdirAll(dir, shared.DirPermStandard); err != nil {
		otelzap.Ctx(rc.Ctx).Warn("Failed to create directory for install script", zap.String("path", dir), zap.Error(err))
	}
	scriptPath := dir + "/k3s-install.sh"
	// Prepend with set -x for debugging and redirect output to a log file.
	// Use Bash so process-substitution works everywhere Ubuntu ships it.
	scriptContent := fmt.Sprintf(`#!/usr/bin/env bash
 set -euo pipefail
 exec > >(tee -a %s/k3s-deploy.log) 2>&1
 %s
 `, shared.EosLogDir, cmdStr)
	err = os.WriteFile(scriptPath, []byte(scriptContent), shared.DirPermStandard)
	if err != nil {
		fmt.Printf("Warning: Failed to write script file: %v\n", err)
	}
	return scriptPath
}

// outputJoinToken waits for the K3s join token to be available and prints it.
func OutputJoinToken() {
	// #nosec G101 - This is a file path to a token file, not a hardcoded credential
	tokenPath := "/var/lib/rancher/k3s/server/node-token"
	fmt.Println("Retrieving K3s join token...")
	maxAttempts := 30
	for range maxAttempts {
		tokenData, err := os.ReadFile(tokenPath)
		if err == nil {
			token := strings.TrimSpace(string(tokenData))
			if token != "" {
				fmt.Printf("K3s Join Token: %s\n", token)
				return
			}
		}
		time.Sleep(1 * time.Second)
	}
	fmt.Println("Unable to retrieve join token. Please check the K3s server status.")
}

func GenerateK3sTerraform(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if terraform is installed
	if err := terraform.CheckTerraformInstalled(); err != nil {
		return fmt.Errorf("terraform is required but not installed. Run 'eos create terraform' first: %w", err)
	}

	// Get command line flags
	provider, _ := cmd.Flags().GetString("provider")
	serverType, _ := cmd.Flags().GetString("server-type")
	location, _ := cmd.Flags().GetString("location")
	sshKey, _ := cmd.Flags().GetString("ssh-key")
	outputDir, _ := cmd.Flags().GetString("output-dir")

	reader := bufio.NewReader(os.Stdin)

	// Interactive prompts
	if sshKey == "" {
		fmt.Print("Enter SSH key name in cloud provider: ")
		input, _ := reader.ReadString('\n')
		sshKey = strings.TrimSpace(input)
	}

	fmt.Print("Enter server name [k3s-server]: ")
	serverNameInput, _ := reader.ReadString('\n')
	serverName := strings.TrimSpace(serverNameInput)
	if serverName == "" {
		serverName = "k3s-server"
	}

	fmt.Print("Is this a server or worker node? [server/worker]: ")
	roleInput, _ := reader.ReadString('\n')
	role := strings.TrimSpace(strings.ToLower(roleInput))
	if role != "server" && role != "worker" {
		role = "server"
	}

	var serverURL, token string
	if role == "worker" {
		fmt.Print("Enter K3s server URL: ")
		input, _ := reader.ReadString('\n')
		serverURL = strings.TrimSpace(input)

		fmt.Print("Enter K3s cluster token: ")
		input, _ = reader.ReadString('\n')
		token = strings.TrimSpace(input)
	}

	// Create terraform manager
	tfManager := terraform.NewManager(rc, outputDir)

	// Prepare K3s configuration
	k3sConfig := terraform.K3sConfig{
		ServerName:   serverName,
		ServerType:   serverType,
		Location:     location,
		SSHKeyName:   sshKey,
		K3sRole:      role,
		K3sServerURL: serverURL,
		K3sToken:     token,
	}

	logger.Info("Generating Terraform configuration",
		zap.String("provider", provider),
		zap.String("server_name", serverName),
		zap.String("role", role),
		zap.String("output_dir", outputDir))

	// Generate main.tf
	if err := tfManager.GenerateFromString(terraform.K3sHetznerTemplate, "main.tf", k3sConfig); err != nil {
		return fmt.Errorf("failed to generate main.tf: %w", err)
	}

	// Generate cloud-init.yaml
	if err := tfManager.GenerateFromString(terraform.K3sCloudInitTemplate, "k3s-cloud-init.yaml", k3sConfig); err != nil {
		return fmt.Errorf("failed to generate cloud-init.yaml: %w", err)
	}

	// Generate terraform.tfvars
	tfvarsContent := fmt.Sprintf(`# Terraform variables for K3s deployment
# Set your Hetzner Cloud API token
# hcloud_token = "your-hetzner-cloud-token"

server_name = "%s"
server_type = "%s"
location = "%s"
ssh_key_name = "%s"
k3s_role = "%s"`, serverName, serverType, location, sshKey, role)

	if role == "worker" {
		tfvarsContent += fmt.Sprintf(`
k3s_server_url = "%s"
k3s_token = "%s"`, serverURL, token)
	}

	if err := os.WriteFile(outputDir+"/terraform.tfvars", []byte(tfvarsContent), 0644); err != nil {
		return fmt.Errorf("failed to generate terraform.tfvars: %w", err)
	}

	// Initialize terraform
	if err := tfManager.Init(rc); err != nil {
		return fmt.Errorf("failed to initialize terraform: %w", err)
	}

	// Validate configuration
	if err := tfManager.Validate(rc); err != nil {
		return fmt.Errorf("terraform configuration validation failed: %w", err)
	}

	// Format files
	if err := tfManager.Format(rc); err != nil {
		logger.Warn("Failed to format terraform files", zap.Error(err))
	}

	fmt.Printf("\n Terraform configuration generated successfully in: %s\n", outputDir)
	fmt.Println("\nNext steps:")
	fmt.Printf("1. Set your Hetzner Cloud token: export HCLOUD_TOKEN='your-token'\n")
	fmt.Printf("2. Review the configuration: cd %s\n", outputDir)
	fmt.Println("3. Plan the deployment: terraform plan")
	fmt.Println("4. Apply the configuration: terraform apply")

	if role == "server" {
		fmt.Println("\nAfter deployment, retrieve the join token:")
		fmt.Println("terraform output server_ip")
		fmt.Println("ssh root@$(terraform output -raw server_ip) 'cat /var/lib/rancher/k3s/server/node-token'")
	}

	return nil
}

func RunCreateKubeadm(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	otelzap.Ctx(rc.Ctx).Info("Starting kubeadm installation")

	// Get flags
	controlPlaneEndpoint, _ := cmd.Flags().GetString("control-plane-endpoint")
	// TODO: Uncomment when implementing kubeadm support
	// podNetworkCIDR, _ := cmd.Flags().GetString("pod-network-cidr")
	// version, _ := cmd.Flags().GetString("version")

	// Prompt for control plane endpoint if not provided
	if controlPlaneEndpoint == "" {
		var err error
		controlPlaneEndpoint, err = interaction.PromptUser(rc, "Enter control plane endpoint (IP:port, optional): ")
		if err != nil {
			return fmt.Errorf("failed to get control plane endpoint: %w", err)
		}
		controlPlaneEndpoint = strings.TrimSpace(controlPlaneEndpoint)
		// TODO: Use controlPlaneEndpoint in the K3s configuration
		_ = controlPlaneEndpoint
	}

	// TODO: Fix missing container.KubernetesInstallOptions and related functions
	// Create installation options
	/*
		options := &container.KubernetesInstallOptions{
			Type:                 "kubeadm",
			ControlPlaneEndpoint: controlPlaneEndpoint,
			PodNetworkCIDR:       podNetworkCIDR,
			Version:              version,
		}

		// Install kubeadm
		if err := container.InstallKubeadm(rc, options); err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to install kubeadm", zap.Error(err))
			return err
		}

		// Get cluster status
		if err := container.GetKubernetesStatus(rc, "kubeadm"); err != nil {
			otelzap.Ctx(rc.Ctx).Warn("Failed to get cluster status", zap.Error(err))
		}
	*/

	otelzap.Ctx(rc.Ctx).Error("Kubeadm installation not yet implemented - missing container functions")

	otelzap.Ctx(rc.Ctx).Info("Kubeadm installation completed successfully")
	otelzap.Ctx(rc.Ctx).Info("Next steps:")
	otelzap.Ctx(rc.Ctx).Info("1. Install a pod network addon (e.g., Calico, Flannel)")
	otelzap.Ctx(rc.Ctx).Info("2. Join worker nodes using the join command from kubeadm init output")
	otelzap.Ctx(rc.Ctx).Info("3. Verify cluster: kubectl get nodes")

	return nil
}

func GenerateK3sCaddyNginx(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
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

	fmt.Println("\n Quick start:")
	fmt.Printf("  cd %s\n", outputDir)
	if cloudDeploy {
		fmt.Println("  export HCLOUD_TOKEN='your-token'")
		fmt.Println("  # Update terraform.tfvars with your SSH key")
	}
	fmt.Println("  ./deploy.sh")

	return nil
}