package update

import (
	"fmt"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ssh"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	sshHost      string
	sshKeyPath   string
	sshHosts     string
	sshUsername  string
)

var SecureSSHCmd = &cobra.Command{
	Use:   "ssh",
	Short: "SSH security diagnostics and troubleshooting",
	Long: `Perform comprehensive SSH security diagnostics including:
- Credential validation
- Key permission verification
- Network connectivity testing
- Service status checking

Examples:
  eos secure ssh --host user@hostname
  eos secure ssh --host user@hostname --key ~/.ssh/id_rsa
  eos secure ssh  # Interactive mode`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return runSecureSSH(rc, cmd, args)
	}),
}

var CheckSSHCredsCmd = &cobra.Command{
	Use:   "check-credentials",
	Short: "Check SSH credentials for a specific host",
	Long: `Validate SSH credentials by attempting a connection test.
This performs a quick validation without full troubleshooting.

Examples:
  eos secure ssh check-credentials --host user@hostname
  eos secure ssh check-credentials --host user@hostname --key ~/.ssh/id_rsa`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return runCheckSSHCredentials(rc, cmd, args)
	}),
}

var DisableRootCmd = &cobra.Command{
	Use:   "disable-root",
	Short: "Disable SSH root login for security hardening",
	Long: `Disable SSH root login by modifying the SSH daemon configuration.
This security hardening measure prevents direct root login via SSH.

This command will:
- Create a backup of the current SSH configuration
- Modify /etc/ssh/sshd_config to set PermitRootLogin no
- Restart the SSH service to apply changes

Requires root privileges (sudo).

Examples:
  sudo eos secure ssh disable-root`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return runDisableRoot(rc, cmd, args)
	}),
}

var CopyKeysCmd = &cobra.Command{
	Use:   "copy-keys",
	Short: "Copy SSH keys to multiple remote hosts",
	Long: `Copy SSH public keys to multiple remote hosts using ssh-copy-id.
This command automates SSH key distribution for passwordless authentication.

Examples:
  eos secure ssh copy-keys --hosts host1,host2,host3 --user username
  eos secure ssh copy-keys  # Interactive mode`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return runCopyKeys(rc, cmd, args)
	}),
}

var DistributeKeysCmd = &cobra.Command{
	Use:   "distribute-keys",
	Short: "Distribute SSH keys to Tailscale network peers",
	Long: `Distribute SSH keys to other machines in your Tailscale network.
This command requires Tailscale to be running and connected.

Examples:
  eos secure ssh distribute-keys`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return runDistributeKeys(rc, cmd, args)
	}),
}

func init() {
	UpdateCmd.AddCommand(SecureSSHCmd)
	SecureSSHCmd.AddCommand(CheckSSHCredsCmd)
	SecureSSHCmd.AddCommand(DisableRootCmd)
	SecureSSHCmd.AddCommand(CopyKeysCmd)
	SecureSSHCmd.AddCommand(DistributeKeysCmd)
	
	// Add flags to commands that need SSH connection
	for _, cmd := range []*cobra.Command{SecureSSHCmd, CheckSSHCredsCmd} {
		cmd.Flags().StringVar(&sshHost, "host", "", "SSH host in format user@hostname[:port]")
		cmd.Flags().StringVar(&sshKeyPath, "key", "", "Path to SSH private key (auto-detected if not specified)")
	}
	
	// Add flags for copy-keys command
	CopyKeysCmd.Flags().StringVar(&sshHosts, "hosts", "", "Comma-separated list of hosts to copy keys to")
	CopyKeysCmd.Flags().StringVar(&sshUsername, "user", "", "SSH username for remote hosts")
}

func runSecureSSH(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	otelzap.Ctx(rc.Ctx).Info("Starting SSH security diagnostics")
	
	// Get SSH host if not provided
	if sshHost == "" {
		var err error
		sshHost, err = interaction.PromptUser(rc, "Enter SSH host (user@hostname[:port]): ")
		if err != nil {
			return fmt.Errorf("failed to get SSH host: %w", err)
		}
	}
	
	// Perform comprehensive troubleshooting
	if err := ssh.TroubleshootSSH(rc, sshHost, sshKeyPath); err != nil {
		otelzap.Ctx(rc.Ctx).Error("SSH troubleshooting failed", zap.Error(err))
		return err
	}
	
	otelzap.Ctx(rc.Ctx).Info("SSH security diagnostics completed successfully")
	return nil
}

func runCheckSSHCredentials(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	otelzap.Ctx(rc.Ctx).Info("Checking SSH credentials")
	
	// Get SSH host if not provided
	if sshHost == "" {
		var err error
		sshHost, err = interaction.PromptUser(rc, "Enter SSH host (user@hostname[:port]): ")
		if err != nil {
			return fmt.Errorf("failed to get SSH host: %w", err)
		}
	}
	
	// Parse SSH path
	creds, err := ssh.ParseSSHPath(sshHost)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to parse SSH path", zap.Error(err))
		return fmt.Errorf("invalid SSH path format: %w", err)
	}
	
	// Select SSH key if not provided
	if sshKeyPath == "" {
		sshKeyPath, err = ssh.SelectSSHKey(rc)
		if err != nil {
			return err
		}
	}
	
	creds.KeyPath = sshKeyPath
	
	// Check credentials
	if err := ssh.CheckSSHCredentials(rc, creds); err != nil {
		otelzap.Ctx(rc.Ctx).Error("SSH credential check failed", zap.Error(err))
		return err
	}
	
	otelzap.Ctx(rc.Ctx).Info("SSH credentials are valid")
	return nil
}

func runDisableRoot(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	otelzap.Ctx(rc.Ctx).Info("Starting SSH root login disable process")
	
	// Disable SSH root login
	if err := ssh.DisableRootLogin(rc); err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to disable SSH root login", zap.Error(err))
		return err
	}
	
	otelzap.Ctx(rc.Ctx).Info("SSH root login disabled successfully")
	return nil
}

func runCopyKeys(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	otelzap.Ctx(rc.Ctx).Info("Starting SSH key copy process")

	// Get hosts if not provided
	hosts := sshHosts
	if hosts == "" {
		var err error
		hosts, err = interaction.PromptUser(rc, "Enter the hosts you want to copy your SSH key to (comma-separated): ")
		if err != nil {
			return fmt.Errorf("failed to get hosts: %w", err)
		}
	}

	// Parse hosts list
	hostList := strings.Split(hosts, ",")
	for i, host := range hostList {
		hostList[i] = strings.TrimSpace(host)
	}

	// Get username if not provided
	username := sshUsername
	if username == "" {
		var err error
		username, err = interaction.PromptUser(rc, "Enter the SSH username: ")
		if err != nil {
			return fmt.Errorf("failed to get username: %w", err)
		}
	}

	// Copy SSH keys to hosts
	if err := ssh.CopySSHKeys(rc, hostList, username); err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to copy SSH keys", zap.Error(err))
		return err
	}

	otelzap.Ctx(rc.Ctx).Info("SSH key copy process completed successfully")
	return nil
}

func runDistributeKeys(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	otelzap.Ctx(rc.Ctx).Info("Starting SSH key distribution to Tailscale peers")

	// Get list of Tailscale peers
	peers, err := ssh.GetTailscalePeers(rc)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to get Tailscale peers", zap.Error(err))
		return err
	}

	// Display available peers
	otelzap.Ctx(rc.Ctx).Info("Available Tailscale peers:")
	for i, peer := range peers {
		otelzap.Ctx(rc.Ctx).Info(fmt.Sprintf("%d. %s", i+1, peer))
	}

	// Prompt for host selection
	hostsInput, err := interaction.PromptUser(rc, "Enter the hostnames or IP addresses of machines to distribute SSH key to (space-separated): ")
	if err != nil {
		return fmt.Errorf("failed to get host selection: %w", err)
	}

	selectedHosts := strings.Fields(strings.TrimSpace(hostsInput))
	if len(selectedHosts) == 0 {
		otelzap.Ctx(rc.Ctx).Error("No hosts selected")
		return fmt.Errorf("no hosts selected for SSH key distribution")
	}

	// Confirm selection
	otelzap.Ctx(rc.Ctx).Info("Selected hosts", zap.Strings("hosts", selectedHosts))
	confirmation, err := interaction.PromptUser(rc, "Proceed with SSH key distribution? (y/n): ")
	if err != nil {
		return fmt.Errorf("failed to get confirmation: %w", err)
	}

	if strings.ToLower(strings.TrimSpace(confirmation)) != "y" {
		otelzap.Ctx(rc.Ctx).Info("SSH key distribution cancelled")
		return nil
	}

	// Distribute SSH keys to selected Tailscale hosts
	if err := ssh.DistributeSSHKeysToTailscale(rc, selectedHosts); err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to distribute SSH keys to Tailscale peers", zap.Error(err))
		return err
	}

	otelzap.Ctx(rc.Ctx).Info("SSH key distribution to Tailscale peers completed successfully")
	return nil
}