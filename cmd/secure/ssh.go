package secure

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ssh"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	sshHost    string
	sshKeyPath string
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

func init() {
	SecureCmd.AddCommand(SecureSSHCmd)
	SecureSSHCmd.AddCommand(CheckSSHCredsCmd)
	
	// Add flags to both commands
	for _, cmd := range []*cobra.Command{SecureSSHCmd, CheckSSHCredsCmd} {
		cmd.Flags().StringVar(&sshHost, "host", "", "SSH host in format user@hostname[:port]")
		cmd.Flags().StringVar(&sshKeyPath, "key", "", "Path to SSH private key (auto-detected if not specified)")
	}
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