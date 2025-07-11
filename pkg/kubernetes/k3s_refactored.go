package kubernetes

import (
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
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TODO: This is a refactored version of k3s.go following Eos standards:
// - All fmt.Print* replaced with structured logging or stderr output
// - User prompts use interaction package patterns
// - Proper Assess → Intervene → Evaluate pattern
// - Enhanced error handling and context

// DeployK3sRefactored deploys K3s following the Assess → Intervene → Evaluate pattern
func DeployK3sRefactored(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting K3s deployment")

	// ASSESS - Check system state and prerequisites
	logger.Info("Assessing K3s deployment requirements")
	
	// Check firewall status
	platform.CheckFirewallStatus(rc)
	
	// Check IPv6 support and Tailscale configuration
	nodeIP, err := assessNetworkConfiguration(rc)
	if err != nil {
		logger.Error("Network configuration assessment failed", zap.Error(err))
		return fmt.Errorf("network assessment failed: %w", err)
	}
	
	// Get K3s deployment configuration from user
	config, err := getK3sConfiguration(rc, nodeIP)
	if err != nil {
		return fmt.Errorf("failed to get K3s configuration: %w", err)
	}
	
	// INTERVENE - Execute K3s deployment
	logger.Info("Executing K3s deployment",
		zap.String("role", config.Role),
		zap.String("node_ip", nodeIP))
		
	if err := executeK3sDeployment(rc, config); err != nil {
		return fmt.Errorf("K3s deployment failed: %w", err)
	}
	
	// EVALUATE - Verify deployment success
	logger.Info("Evaluating K3s deployment success")
	
	if err := verifyK3sDeployment(rc, config); err != nil {
		logger.Error("K3s deployment verification failed", zap.Error(err))
		return fmt.Errorf("deployment verification failed: %w", err)
	}
	
	// Display success message to user
	if err := displayK3sDeploymentSummary(rc, config); err != nil {
		logger.Warn("Failed to display deployment summary", zap.Error(err))
	}
	
	logger.Info("K3s deployment completed successfully",
		zap.String("role", config.Role),
		zap.String("node_ip", nodeIP))
	
	return nil
}

// K3sConfig holds the configuration for K3s deployment
type K3sConfig struct {
	Role      string // "server" or "worker"
	TLSSAN    string // TLS Subject Alternative Name for server
	ServerURL string // K3s server URL for workers
	Token     string // K3s node token for workers
	NodeIP    string // Node IP address
	InstallCmd string // Generated install command
}

// assessNetworkConfiguration checks IPv6 support and Tailscale configuration
func assessNetworkConfiguration(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Assessing network configuration")
	
	nodeIP := ""
	if network.CheckIPv6Enabled() {
		tailscaleIP, err := network.GetTailscaleIPv6()
		if err == nil && tailscaleIP != "" {
			nodeIP = tailscaleIP
			logger.Info("Detected Tailscale IPv6",
				zap.String("node_ip", nodeIP))
		} else {
			logger.Info("Tailscale IPv6 not detected; proceeding without --node-ip flag")
		}
	} else {
		logger.Warn("IPv6 is disabled. Attempting to enable it...")
		if err := network.EnableIPv6(); err != nil {
			logger.Warn("Could not enable IPv6", zap.Error(err))
		} else {
			logger.Info("IPv6 enabled. Retrying Tailscale detection...")
			if ip, err := network.GetTailscaleIPv6(); err == nil && ip != "" {
				nodeIP = ip
				logger.Info("Detected Tailscale IPv6 after enabling",
					zap.String("node_ip", nodeIP))
			}
		}
	}
	
	logger.Info("Network configuration assessment complete",
		zap.String("node_ip", nodeIP))
	
	return nodeIP, nil
}

// getK3sConfiguration prompts the user for K3s deployment configuration
func getK3sConfiguration(rc *eos_io.RuntimeContext, nodeIP string) (*K3sConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Getting K3s deployment configuration from user")
	
	config := &K3sConfig{
		NodeIP: nodeIP,
	}
	
	// Get node role
	logger.Info("terminal prompt: Is this node a server or worker?")
	role := interaction.PromptInput(rc.Ctx, "Is this node a server or worker?", "server")
	
	role = strings.TrimSpace(strings.ToLower(role))
	if role != "server" && role != "worker" {
		return nil, fmt.Errorf("invalid role '%s', must be 'server' or 'worker'", role)
	}
	
	config.Role = role
	
	// Get role-specific configuration
	switch role {
	case "server":
		if err := getServerConfiguration(rc, config); err != nil {
			return nil, fmt.Errorf("failed to get server configuration: %w", err)
		}
	case "worker":
		if err := getWorkerConfiguration(rc, config); err != nil {
			return nil, fmt.Errorf("failed to get worker configuration: %w", err)
		}
	}
	
	logger.Info("K3s configuration complete",
		zap.String("role", config.Role),
		zap.String("install_cmd", config.InstallCmd))
	
	return config, nil
}

// getServerConfiguration gets server-specific configuration
func getServerConfiguration(rc *eos_io.RuntimeContext, config *K3sConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("terminal prompt: Enter TLS SAN")
	defaultTLSSAN := eos_unix.GetInternalHostname()
	tlsSAN := interaction.PromptInput(rc.Ctx, "Enter TLS SAN", defaultTLSSAN)
	
	config.TLSSAN = strings.TrimSpace(tlsSAN)
	if config.TLSSAN == "" {
		config.TLSSAN = defaultTLSSAN
	}
	
	// Build server install command
	config.InstallCmd = fmt.Sprintf("curl -sfL https://get.k3s.io | sh -s - server --tls-san %s", config.TLSSAN)
	if config.NodeIP != "" {
		config.InstallCmd += fmt.Sprintf(" --node-ip %s", config.NodeIP)
	}
	
	logger.Info("Server configuration complete",
		zap.String("tls_san", config.TLSSAN))
	
	return nil
}

// getWorkerConfiguration gets worker-specific configuration
func getWorkerConfiguration(rc *eos_io.RuntimeContext, config *K3sConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Get server URL
	logger.Info("terminal prompt: Enter K3s server URL")
	serverURL := interaction.PromptInput(rc.Ctx, "Enter the K3s server URL (e.g., https://server-ip:6443)", "")
	
	serverURL = strings.TrimSpace(serverURL)
	if serverURL == "" {
		return fmt.Errorf("server URL is required for worker nodes")
	}
	
	// Format server URL properly
	if strings.Contains(serverURL, ":") && !strings.Contains(serverURL, "[") {
		serverURL = fmt.Sprintf("https://[%s]:6443", serverURL)
	} else if !strings.HasPrefix(serverURL, "https://") {
		serverURL = fmt.Sprintf("https://%s:6443", serverURL)
	}
	
	config.ServerURL = serverURL
	
	// Get node token
	logger.Info("terminal prompt: Enter K3s node token")
	token, err := interaction.PromptSecret(rc.Ctx, "Enter the K3s node token")
	if err != nil {
		return fmt.Errorf("failed to get node token: %w", err)
	}
	
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("node token is required for worker nodes")
	}
	
	config.Token = token
	
	// Build worker install command
	config.InstallCmd = fmt.Sprintf(
		"export K3S_URL=%s\nexport K3S_TOKEN=%s\ncurl -sfL https://get.k3s.io | sh -s -",
		config.ServerURL, config.Token,
	)
	if config.NodeIP != "" {
		config.InstallCmd += fmt.Sprintf(" --node-ip %s", config.NodeIP)
	}
	
	logger.Info("Worker configuration complete",
		zap.String("server_url", config.ServerURL))
	
	return nil
}

// executeK3sDeployment executes the K3s deployment
func executeK3sDeployment(rc *eos_io.RuntimeContext, config *K3sConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Display the generated install command to user
	logger.Info("terminal prompt: Generated install command")
	summary := fmt.Sprintf("\n📋 Generated K3s Install Command:\n%s\n", config.InstallCmd)
	if _, err := fmt.Fprint(os.Stderr, summary); err != nil {
		return fmt.Errorf("failed to display install command: %w", err)
	}
	
	// Ask user for confirmation
	logger.Info("terminal prompt: Execute install command?")
	confirm := interaction.PromptInput(rc.Ctx, "Do you want to execute this command?", "y")
	
	confirm = strings.TrimSpace(strings.ToLower(confirm))
	if confirm != "y" && confirm != "yes" {
		// Save script but don't execute
		scriptPath := filepath.Join(shared.EosLogDir, "k3s-install.sh")
		if err := saveInstallScript(rc, config.InstallCmd, scriptPath); err != nil {
			logger.Warn("Failed to save install script", zap.Error(err))
		}
		
		logger.Info("terminal prompt: Installation not executed")
		if _, err := fmt.Fprintf(os.Stderr, "Installation command not executed. Saved to: %s\n", scriptPath); err != nil {
			return fmt.Errorf("failed to write message: %w", err)
		}
		return nil
	}
	
	// Execute the installation
	logger.Info("Executing K3s installation")
	scriptPath := filepath.Join(shared.EosLogDir, "k3s-install.sh")
	logPath := filepath.Join(shared.EosLogDir, "k3s-deploy.log")
	
	if err := saveInstallScript(rc, config.InstallCmd, scriptPath); err != nil {
		return fmt.Errorf("failed to save install script: %w", err)
	}
	
	// Make script executable
	if err := os.Chmod(scriptPath, 0755); err != nil {
		return fmt.Errorf("failed to make script executable: %w", err)
	}
	
	// Execute the script
	logger.Info("terminal prompt: Executing install script")
	if _, err := fmt.Fprintf(os.Stderr, "Executing the install script: %s\n", scriptPath); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}
	
	// Run the installation script
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "/bin/bash",
		Args:    []string{scriptPath},
		Capture: false,
		Timeout: 10 * time.Minute, // K3s installation can take several minutes
	}); err != nil {
		logger.Error("K3s installation failed", zap.Error(err))
		return fmt.Errorf("installation failed: %w", err)
	}
	
	// Display log information
	logger.Info("terminal prompt: Installation completed")
	logSummary := fmt.Sprintf("\n✅ K3s installation completed.\n"+
		"Check %s for details.\n"+
		"To monitor logs: tail -f %s\n", logPath, logPath)
	if _, err := fmt.Fprint(os.Stderr, logSummary); err != nil {
		return fmt.Errorf("failed to display log info: %w", err)
	}
	
	return nil
}

// saveInstallScript saves the install command to a script file
func saveInstallScript(rc *eos_io.RuntimeContext, installCmd, scriptPath string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Create log directory if it doesn't exist
	logDir := filepath.Dir(scriptPath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		logger.Warn("Could not create log directory",
			zap.String("path", logDir),
			zap.Error(err))
		return fmt.Errorf("failed to create log directory: %w", err)
	}
	
	// Write script content
	scriptContent := fmt.Sprintf("#!/bin/bash\n\n# K3s Install Script\n# Generated: %s\n\n%s\n",
		time.Now().Format(time.RFC3339), installCmd)
	
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		logger.Warn("Failed to write script file", zap.Error(err))
		return fmt.Errorf("failed to write script: %w", err)
	}
	
	logger.Info("Install script saved", zap.String("path", scriptPath))
	return nil
}

// verifyK3sDeployment verifies that K3s was deployed successfully
func verifyK3sDeployment(rc *eos_io.RuntimeContext, config *K3sConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Verifying K3s deployment")
	
	// Check if K3s service is running
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "k3s"},
		Capture: true,
	}); err != nil {
		logger.Error("K3s service is not active", zap.Error(err))
		return fmt.Errorf("K3s service verification failed: %w", err)
	}
	
	// Check if kubectl is available (for servers)
	if config.Role == "server" {
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "kubectl",
			Args:    []string{"get", "nodes"},
			Capture: true,
		}); err != nil {
			logger.Warn("kubectl verification failed", zap.Error(err))
			// This is a warning, not a hard failure
		}
	}
	
	logger.Info("K3s deployment verification completed successfully")
	return nil
}

// displayK3sDeploymentSummary displays deployment summary to the user
func displayK3sDeploymentSummary(rc *eos_io.RuntimeContext, config *K3sConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("terminal prompt: K3s deployment summary")
	
	var summary strings.Builder
	summary.WriteString("\n")
	summary.WriteString("╔═══════════════════════════════════════════════════════════════════════╗\n")
	summary.WriteString("║              K3S DEPLOYMENT COMPLETED SUCCESSFULLY                   ║\n")
	summary.WriteString("╚═══════════════════════════════════════════════════════════════════════╝\n")
	summary.WriteString("\n")
	
	summary.WriteString(fmt.Sprintf("🎯 Role: %s\n", config.Role))
	if config.NodeIP != "" {
		summary.WriteString(fmt.Sprintf("🌐 Node IP: %s\n", config.NodeIP))
	}
	
	if config.Role == "server" {
		summary.WriteString(fmt.Sprintf("🔐 TLS SAN: %s\n", config.TLSSAN))
		summary.WriteString("\n")
		summary.WriteString("📋 Next Steps:\n")
		summary.WriteString("   • Check cluster status: kubectl get nodes\n")
		summary.WriteString("   • Get join token: sudo cat /var/lib/rancher/k3s/server/node-token\n")
		summary.WriteString("   • Configure kubectl: export KUBECONFIG=/etc/rancher/k3s/k3s.yaml\n")
	} else {
		summary.WriteString(fmt.Sprintf("🔗 Server URL: %s\n", config.ServerURL))
		summary.WriteString("\n")
		summary.WriteString("📋 Next Steps:\n")
		summary.WriteString("   • Check node status: kubectl get nodes (on server)\n")
		summary.WriteString("   • Verify connection: systemctl status k3s-agent\n")
	}
	
	summary.WriteString("\n")
	summary.WriteString("📊 Monitoring:\n")
	summary.WriteString("   • Service status: systemctl status k3s\n")
	summary.WriteString("   • Logs: journalctl -u k3s -f\n")
	summary.WriteString("\n")
	
	// Display to user
	if _, err := fmt.Fprint(os.Stderr, summary.String()); err != nil {
		return fmt.Errorf("failed to display summary: %w", err)
	}
	
	logger.Info("K3s deployment summary displayed to user",
		zap.String("role", config.Role))
	
	return nil
}

// TODO: The following functions would also need to be migrated from the original file:
// - GetK3sJoinToken
// - CreateK3sDeployment
// - GenerateK3sClusterYAML
// - These functions have additional fmt.Print* violations that need addressing