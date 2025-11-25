package read

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ssh"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	sshReadHost     string
	sshReadUser     string
	sshReadPort     string
	sshReadKey      string
	sshReadPassword string
	sshReadSudoPass string
)

// readSSHCmd reports SSH forwarding-related configuration for a remote host.
var readSSHCmd = &cobra.Command{
	Use:   "ssh",
	Short: "Inspect SSH forwarding configuration on a host",
	Long: `Shows forwarding-related sshd_config directives and SSH service status.

Examples:
  eos read ssh --host vhost1
  eos read ssh --host user@vhost1 --key ~/.ssh/id_ed25519
  eos read ssh --host vhost1 --user henry --password '...' --sudo-pass '...'`,
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		if sshReadHost == "" {
			return fmt.Errorf("--host is required (e.g., vhost1 or user@vhost1)")
		}

		connCfg, err := ssh.BuildConnectionConfig(sshReadHost, sshReadUser, sshReadPort, sshReadKey, sshReadPassword, sshReadSudoPass)
		if err != nil {
			return err
		}

		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("Connecting to host for SSH forwarding status",
			zap.String("host", connCfg.Host),
			zap.String("user", connCfg.User),
			zap.String("port", connCfg.Port))

		client, err := ssh.ConnectSSHClient(rc, connCfg)
		if err != nil {
			return fmt.Errorf("failed to connect to %s: %w", connCfg.Host, err)
		}
		defer func() { _ = client.Close() }()

		status, err := ssh.ReadForwardingStatus(rc, client)
		if err != nil {
			return err
		}

		logger.Info("SSH forwarding configuration",
			zap.String("allow_tcp_forwarding", status.AllowTcpForwarding),
			zap.String("allow_stream_local_forwarding", status.AllowStreamLocalForwarding),
			zap.Strings("permit_open", status.PermitOpen),
			zap.String("service_status", status.ServiceStatus))

		return nil
	}),
}

func init() {
	ReadCmd.AddCommand(readSSHCmd)

	readSSHCmd.Flags().StringVar(&sshReadHost, "host", "", "Target host (e.g., vhost1 or user@vhost1)")
	readSSHCmd.Flags().StringVar(&sshReadUser, "user", "", "SSH username override (defaults to current user)")
	readSSHCmd.Flags().StringVar(&sshReadPort, "port", "22", "SSH port (default 22)")
	readSSHCmd.Flags().StringVar(&sshReadKey, "key", "", "Path to SSH private key (defaults to first available)")
	readSSHCmd.Flags().StringVar(&sshReadPassword, "password", "", "SSH password (optional if key-based auth works)")
	readSSHCmd.Flags().StringVar(&sshReadSudoPass, "sudo-pass", "", "Sudo password for reading sshd_config (defaults to --password)")
}
