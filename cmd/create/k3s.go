// cmd/create/k3s.go
package create

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/terraform"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/network"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// k3sCmd is the subcommand for deploying K3s.
var CreateK3sCmd = &cobra.Command{
	Use:   "k3s",
	Short: "Deploy K3s on a server or worker node",
	Long: `Deploy K3s on a node with interactive prompts.
For server nodes, you'll be prompted for the TLS SAN.
For worker nodes, you'll be prompted for the server URL and node token.
Additional checks for IPv6 and Tailscale are performed.
The generated install command is previewed and saved to a script file
for safe, human-approved execution.

Use --terraform flag to generate Terraform configuration instead of direct installation.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		useTerraform, _ := cmd.Flags().GetBool("terraform")
		if useTerraform {
			return generateK3sTerraform(rc, cmd)
		}
		deployK3s(rc)
		return nil
	}),
}

var k3sTerraformCmd = &cobra.Command{
	Use:   "k3s-terraform",
	Short: "Generate Terraform configuration for K3s deployment",
	Long: `Generate Terraform configuration for K3s deployment on cloud infrastructure.
Supports Hetzner Cloud provider with automated server provisioning and K3s installation.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return generateK3sTerraform(rc, cmd)
	}),
}

func init() {
	CreateCmd.AddCommand(CreateK3sCmd)
	CreateCmd.AddCommand(k3sTerraformCmd)

	// Add terraform flag to k3s command
	CreateK3sCmd.Flags().Bool("terraform", false, "Generate Terraform configuration instead of direct installation")

	// Add flags for terraform-specific options
	k3sTerraformCmd.Flags().String("provider", "hetzner", "Cloud provider (hetzner)")
	k3sTerraformCmd.Flags().String("server-type", "cx11", "Server type for cloud instance")
	k3sTerraformCmd.Flags().String("location", "nbg1", "Location for cloud instance")
	k3sTerraformCmd.Flags().String("ssh-key", "", "SSH key name in cloud provider")
	k3sTerraformCmd.Flags().String("output-dir", "./terraform-k3s", "Output directory for Terraform files")
}

func deployK3s(rc *eos_io.RuntimeContext) {

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
		scriptPath := saveScript(rc, installCmd)
		fmt.Printf("Installation command not executed. Saved to: %s\n", scriptPath)
		return
	}

	scriptPath := saveScript(rc, installCmd)
	fmt.Printf("Executing the install script: %s\n", scriptPath)
	fmt.Println("Check /var/log/eos/k3s-deploy.log for details.")
	fmt.Println("To monitor logs in real time: tail -f /var/log/eos/k3s-deploy.log")

	if err := execute.RunSimple(rc.Ctx, "sh", scriptPath); err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to execute install script", zap.Error(err))
		fmt.Println("Installation failed. Check logs for details.")
		os.Exit(1)
	}

	fmt.Println("K3s deployment initiated.")
	if role == "server" {
		outputJoinToken()
	}
}

// saveScript writes the install command to a script file and returns the file path.
func saveScript(rc *eos_io.RuntimeContext, cmdStr string) string {
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
func outputJoinToken() {
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

func generateK3sTerraform(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
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

	fmt.Printf("\n✅ Terraform configuration generated successfully in: %s\n", outputDir)
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
