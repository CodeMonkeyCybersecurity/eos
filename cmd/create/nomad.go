// cmd/create/nomad.go
package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/nomad"

	"github.com/spf13/cobra"
)

// CreateNomadCmd replaces the deprecated K3s command with Nomad orchestration
var CreateNomadCmd = &cobra.Command{
	Use:   "nomad",
	Short: "Deploy HashiCorp Nomad on a server or client node",
	Long: `Deploy HashiCorp Nomad orchestration platform on a node with interactive prompts.
For server nodes, you'll be prompted for datacenter configuration and encryption setup.
For client nodes, you'll be prompted for server addresses and encryption key.
Additional checks for IPv6 and Tailscale are performed.

This command replaces the deprecated K3s/Kubernetes functionality with Nomad orchestration,
following the Eos architectural standard: SaltStack → Terraform → Nomad.

Examples:
  eos create nomad                    # Interactive server/client selection
  eos create nomad --role server      # Deploy as server node
  eos create nomad --role client      # Deploy as client node`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return nomad.DeployNomad(rc)
	}),
}

func init() {
	// Register the nomad command
	CreateCmd.AddCommand(CreateNomadCmd)
	
	// Add command flags
	CreateNomadCmd.Flags().String("role", "", "Node role: server or client")
	CreateNomadCmd.Flags().String("datacenter", "dc1", "Nomad datacenter name")
	CreateNomadCmd.Flags().StringSlice("servers", []string{}, "Server addresses for client nodes")
	CreateNomadCmd.Flags().String("encrypt", "", "Gossip encryption key")
}