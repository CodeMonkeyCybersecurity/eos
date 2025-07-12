package container

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// K3sInstallOptions represents installation configuration for K3s
type K3sInstallOptions struct {
	Type              string   // "server" or "agent"
	ServerURL         string   // For agent nodes, URL of the K3s server
	Token             string   // For agent nodes, token to join cluster
	DataDir           string   // Data directory for K3s
	DisableComponents []string // Components to disable (e.g., "traefik", "servicelb")
	EnableComponents  []string // Additional components to enable
	Version           string   // K3s version to install
	ExtraArgs         []string // Additional arguments for K3s
}

// InstallK3sServer installs K3s as a server (control plane)
func InstallK3sServer(rc *eos_io.RuntimeContext, options *K3sInstallOptions) error {
	ctx, span := telemetry.Start(rc.Ctx, "container.InstallK3sServer")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Starting K3s server installation")

	// Check if running as root
	if os.Geteuid() != 0 {
		logger.Error("Root privileges required")
		return eos_err.NewExpectedError(ctx, fmt.Errorf("this operation requires root privileges. Try using sudo"))
	}

	// Step 1: Configure firewall for K3s server
	if err := configureK3sServerFirewall(rc); err != nil {
		return err
	}

	// Step 2: Download and install K3s
	if err := downloadAndInstallK3s(rc, options.Version); err != nil {
		return err
	}

	// Step 3: Configure and start K3s server
	if err := startK3sServer(rc, options); err != nil {
		return err
	}

	// Step 4: Configure kubectl access
	if err := configureK3sKubectl(rc); err != nil {
		return err
	}

	// Step 5: Wait for K3s to be ready
	if err := waitForK3sReady(rc); err != nil {
		return err
	}

	logger.Info("K3s server installation completed successfully")
	return nil
}

// InstallK3sAgent installs K3s as an agent (worker node)
func InstallK3sAgent(rc *eos_io.RuntimeContext, options *K3sInstallOptions) error {
	ctx, span := telemetry.Start(rc.Ctx, "container.InstallK3sAgent")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Starting K3s agent installation")

	// Check if running as root
	if os.Geteuid() != 0 {
		logger.Error("Root privileges required")
		return eos_err.NewExpectedError(ctx, fmt.Errorf("this operation requires root privileges. Try using sudo"))
	}

	// Validate required options for agent
	if options.ServerURL == "" {
		return eos_err.NewExpectedError(ctx, fmt.Errorf("server URL is required for K3s agent installation"))
	}
	if options.Token == "" {
		return eos_err.NewExpectedError(ctx, fmt.Errorf("token is required for K3s agent installation"))
	}

	// Step 1: Configure firewall for K3s agent
	if err := configureK3sAgentFirewall(rc); err != nil {
		return err
	}

	// Step 2: Download and install K3s
	if err := downloadAndInstallK3s(rc, options.Version); err != nil {
		return err
	}

	// Step 3: Configure and start K3s agent
	if err := startK3sAgent(rc, options); err != nil {
		return err
	}

	logger.Info("K3s agent installation completed successfully")
	return nil
}

// configureK3sServerFirewall configures firewall for K3s server
func configureK3sServerFirewall(rc *eos_io.RuntimeContext) error {
	ctx, span := telemetry.Start(rc.Ctx, "container.configureK3sServerFirewall")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Configuring firewall for K3s server")

	// K3s server ports
	ports := []string{
		"6443/tcp",  // Kubernetes API server
		"10250/tcp", // kubelet metrics
		"2379/tcp",  // etcd client
		"2380/tcp",  // etcd peer
	}

	for _, port := range ports {
		cmd := exec.CommandContext(ctx, "ufw", "allow", port)
		if err := cmd.Run(); err != nil {
			logger.Error("Failed to allow port", zap.String("port", port), zap.Error(err))
			return fmt.Errorf("failed to allow port %s: %w", port, err)
		}
	}

	// Reload firewall
	cmd := exec.CommandContext(ctx, "ufw", "reload")
	if err := cmd.Run(); err != nil {
		logger.Error("Failed to reload firewall", zap.Error(err))
		return fmt.Errorf("failed to reload firewall: %w", err)
	}

	logger.Info("K3s server firewall configured successfully")
	return nil
}

// configureK3sAgentFirewall configures firewall for K3s agent
func configureK3sAgentFirewall(rc *eos_io.RuntimeContext) error {
	ctx, span := telemetry.Start(rc.Ctx, "container.configureK3sAgentFirewall")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Configuring firewall for K3s agent")

	// K3s agent ports
	ports := []string{
		"10250/tcp", // kubelet metrics
		"10251/tcp", // kube-scheduler (if running on agent)
		"10252/tcp", // kube-controller-manager (if running on agent)
	}

	for _, port := range ports {
		cmd := exec.CommandContext(ctx, "ufw", "allow", port)
		if err := cmd.Run(); err != nil {
			logger.Error("Failed to allow port", zap.String("port", port), zap.Error(err))
			return fmt.Errorf("failed to allow port %s: %w", port, err)
		}
	}

	// Reload firewall
	cmd := exec.CommandContext(ctx, "ufw", "reload")
	if err := cmd.Run(); err != nil {
		logger.Error("Failed to reload firewall", zap.Error(err))
		return fmt.Errorf("failed to reload firewall: %w", err)
	}

	logger.Info("K3s agent firewall configured successfully")
	return nil
}

// downloadAndInstallK3s downloads and installs K3s binary
func downloadAndInstallK3s(rc *eos_io.RuntimeContext, version string) error {
	ctx, span := telemetry.Start(rc.Ctx, "container.downloadAndInstallK3s")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Downloading and installing K3s", zap.String("version", version))

	// Build install command
	installScript := "https://get.k3s.io"
	cmd := exec.CommandContext(ctx, "curl", "-sfL", installScript)

	// Set version if specified
	if version != "" {
		cmd.Env = append(os.Environ(), fmt.Sprintf("INSTALL_K3S_VERSION=%s", version))
	}

	// Pipe to shell for execution
	shellCmd := exec.CommandContext(ctx, "sh", "-")
	shellCmd.Stdin, _ = cmd.StdoutPipe()
	shellCmd.Stdout = os.Stdout
	shellCmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		logger.Error("Failed to start download", zap.Error(err))
		return fmt.Errorf("failed to start K3s download: %w", err)
	}

	if err := shellCmd.Run(); err != nil {
		logger.Error("Failed to install K3s", zap.Error(err))
		return fmt.Errorf("failed to install K3s: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		logger.Error("Failed to complete download", zap.Error(err))
		return fmt.Errorf("failed to complete K3s download: %w", err)
	}

	logger.Info("K3s installed successfully")
	return nil
}

// startK3sServer starts K3s as a server
func startK3sServer(rc *eos_io.RuntimeContext, options *K3sInstallOptions) error {
	ctx, span := telemetry.Start(rc.Ctx, "container.startK3sServer")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Starting K3s server")

	// Build server arguments
	args := []string{"server"}

	// Add data directory if specified
	if options.DataDir != "" {
		args = append(args, "--data-dir", options.DataDir)
	}

	// Add disabled components
	for _, component := range options.DisableComponents {
		args = append(args, "--disable", component)
	}

	// Add extra arguments
	args = append(args, options.ExtraArgs...)

	// Start K3s server
	cmd := exec.CommandContext(ctx, "k3s", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	logger.Info("Starting K3s server", zap.Strings("args", args))
	if err := cmd.Start(); err != nil {
		logger.Error("Failed to start K3s server", zap.Error(err))
		return fmt.Errorf("failed to start K3s server: %w", err)
	}

	// Enable and start K3s service
	serviceCmd := exec.CommandContext(ctx, "systemctl", "enable", "--now", "k3s")
	if err := serviceCmd.Run(); err != nil {
		logger.Error("Failed to enable K3s service", zap.Error(err))
		return fmt.Errorf("failed to enable K3s service: %w", err)
	}

	logger.Info("K3s server started successfully")
	return nil
}

// startK3sAgent starts K3s as an agent
func startK3sAgent(rc *eos_io.RuntimeContext, options *K3sInstallOptions) error {
	ctx, span := telemetry.Start(rc.Ctx, "container.startK3sAgent")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Starting K3s agent")

	// Build agent arguments
	args := []string{"agent"}

	// Add server URL and token
	args = append(args, "--server", options.ServerURL)
	args = append(args, "--token", options.Token)

	// Add data directory if specified
	if options.DataDir != "" {
		args = append(args, "--data-dir", options.DataDir)
	}

	// Add extra arguments
	args = append(args, options.ExtraArgs...)

	// Set environment variables for agent
	env := os.Environ()
	env = append(env, fmt.Sprintf("K3S_URL=%s", options.ServerURL))
	env = append(env, fmt.Sprintf("K3S_TOKEN=%s", options.Token))

	// Convert args to environment variable for K3s installer
	if len(args) > 1 { // Skip the first "agent" argument
		argsStr := strings.Join(args[1:], " ")
		env = append(env, fmt.Sprintf("INSTALL_K3S_EXEC=%s", argsStr))
	}

	// Install K3s agent service
	cmd := exec.CommandContext(ctx, "sh", "-c", "curl -sfL https://get.k3s.io | sh -")
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	logger.Info("Installing K3s agent service")
	if err := cmd.Run(); err != nil {
		logger.Error("Failed to install K3s agent", zap.Error(err))
		return fmt.Errorf("failed to install K3s agent: %w", err)
	}

	logger.Info("K3s agent started successfully")
	return nil
}

// configureK3sKubectl configures kubectl for K3s
func configureK3sKubectl(rc *eos_io.RuntimeContext) error {
	ctx, span := telemetry.Start(rc.Ctx, "container.configureK3sKubectl")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Configuring kubectl for K3s")

	// Get current user's home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		logger.Error("Failed to get home directory", zap.Error(err))
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	kubeDir := fmt.Sprintf("%s/.kube", homeDir)

	// Create .kube directory
	if err := os.MkdirAll(kubeDir, 0755); err != nil {
		logger.Error("Failed to create .kube directory", zap.Error(err))
		return fmt.Errorf("failed to create .kube directory: %w", err)
	}

	// Copy K3s kubeconfig
	configPath := fmt.Sprintf("%s/config", kubeDir)
	cmd := exec.CommandContext(ctx, "cp", "/etc/rancher/k3s/k3s.yaml", configPath)
	if err := cmd.Run(); err != nil {
		logger.Error("Failed to copy K3s config", zap.Error(err))
		return fmt.Errorf("failed to copy K3s config: %w", err)
	}

	// Change ownership to current user
	userID := os.Getuid()
	groupID := os.Getgid()
	cmd = exec.CommandContext(ctx, "chown", fmt.Sprintf("%d:%d", userID, groupID), configPath)
	if err := cmd.Run(); err != nil {
		logger.Error("Failed to change config ownership", zap.Error(err))
		return fmt.Errorf("failed to change config ownership: %w", err)
	}

	// Set proper permissions
	if err := os.Chmod(configPath, 0600); err != nil {
		logger.Error("Failed to set config permissions", zap.Error(err))
		return fmt.Errorf("failed to set config permissions: %w", err)
	}

	logger.Info("kubectl configured successfully for K3s")
	return nil
}

// waitForK3sReady waits for K3s to be ready
func waitForK3sReady(rc *eos_io.RuntimeContext) error {
	ctx, span := telemetry.Start(rc.Ctx, "container.waitForK3sReady")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Waiting for K3s to be ready")

	// Wait for K3s to be ready using kubectl
	cmd := exec.CommandContext(ctx, "k3s", "kubectl", "wait", "--for=condition=Ready", "nodes", "--all", "--timeout=300s")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		logger.Error("K3s failed to become ready", zap.Error(err))
		return fmt.Errorf("K3s failed to become ready: %w", err)
	}

	logger.Info("K3s is ready")
	return nil
}

// GetK3sStatus gets the status of K3s cluster
func GetK3sStatus(rc *eos_io.RuntimeContext) error {
	ctx, span := telemetry.Start(rc.Ctx, "container.GetK3sStatus")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Getting K3s status")

	// Get nodes
	cmd := exec.CommandContext(ctx, "k3s", "kubectl", "get", "nodes")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		logger.Error("Failed to get nodes", zap.Error(err))
		return fmt.Errorf("failed to get nodes: %w", err)
	}

	// Get pods in kube-system
	cmd = exec.CommandContext(ctx, "k3s", "kubectl", "get", "pods", "-n", "kube-system")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		logger.Error("Failed to get system pods", zap.Error(err))
		return fmt.Errorf("failed to get system pods: %w", err)
	}

	// Get all resources
	cmd = exec.CommandContext(ctx, "k3s", "kubectl", "get", "all", "--all-namespaces")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		logger.Error("Failed to get all resources", zap.Error(err))
		return fmt.Errorf("failed to get all resources: %w", err)
	}

	return nil
}

// UninstallK3s removes K3s from the system
func UninstallK3s(rc *eos_io.RuntimeContext) error {
	ctx, span := telemetry.Start(rc.Ctx, "container.UninstallK3s")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Uninstalling K3s")

	// Check if running as root
	if os.Geteuid() != 0 {
		logger.Error("Root privileges required")
		return eos_err.NewExpectedError(ctx, fmt.Errorf("this operation requires root privileges. Try using sudo"))
	}

	// Run K3s uninstall script if it exists
	if _, err := os.Stat("/usr/local/bin/k3s-uninstall.sh"); err == nil {
		cmd := exec.CommandContext(ctx, "/usr/local/bin/k3s-uninstall.sh")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			logger.Error("Failed to run K3s uninstall script", zap.Error(err))
			return fmt.Errorf("failed to run K3s uninstall script: %w", err)
		}
	}

	// Run K3s agent uninstall script if it exists
	if _, err := os.Stat("/usr/local/bin/k3s-agent-uninstall.sh"); err == nil {
		cmd := exec.CommandContext(ctx, "/usr/local/bin/k3s-agent-uninstall.sh")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			logger.Error("Failed to run K3s agent uninstall script", zap.Error(err))
			return fmt.Errorf("failed to run K3s agent uninstall script: %w", err)
		}
	}

	logger.Info("K3s uninstalled successfully")
	return nil
}

// GetK3sToken retrieves the K3s node token for joining agents
func GetK3sToken(rc *eos_io.RuntimeContext) (string, error) {
	ctx, span := telemetry.Start(rc.Ctx, "container.GetK3sToken")
	defer span.End()

	logger := otelzap.Ctx(ctx)
	logger.Info("Getting K3s node token")

	// Read the node token from K3s
	tokenFile := "/var/lib/rancher/k3s/server/node-token"
	tokenBytes, err := os.ReadFile(tokenFile)
	if err != nil {
		logger.Error("Failed to read K3s token", zap.Error(err))
		return "", fmt.Errorf("failed to read K3s token: %w", err)
	}

	token := strings.TrimSpace(string(tokenBytes))
	logger.Info("K3s token retrieved successfully")
	return token, nil
}
