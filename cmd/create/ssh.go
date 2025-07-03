package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ssh"
	"github.com/spf13/cobra"
)

var (
	targetLogin string
	keyName     string
	force       bool
	alias       string
)

var CreateSSHCmd = &cobra.Command{
	Use:   "ssh",
	Short: "Create a FIPS-compliant SSH key and connect it to a remote host",
	Long: `Generates a 2048-bit RSA key for FIPS compliance, installs it to a remote host using ssh-copy-id,
and configures it in your ~/.ssh/config for easy reuse.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return ssh.CreateSSH(rc, cmd, args)
	}),
}

func init() {
	CreateCmd.AddCommand(CreateSSHCmd)
	CreateSSHCmd.Flags().StringVar(&targetLogin, "user", "", "Target SSH login in the format <user@host>")
	CreateSSHCmd.Flags().StringVar(&keyName, "key-name", "id_rsa_fips", "Filename for the SSH key")
	CreateSSHCmd.Flags().BoolVar(&force, "force", false, "Overwrite existing key if it already exists")
	CreateSSHCmd.Flags().StringVar(&alias, "alias", "", "Custom alias to use in SSH config (default: host)")
}
