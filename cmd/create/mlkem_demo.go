// cmd/create/mlkem_demo.go
package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto/pq"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

var mlkemDemoCmd = &cobra.Command{
	Use:     "mlkem-demo",
	Aliases: []string{"pq-demo", "quantum-demo", "mlkem-example"},
	Short:   "Demonstrate complete ML-KEM key exchange workflow",
	Long: `Run a complete demonstration of ML-KEM key exchange showing the full workflow:

1. Keypair Generation - Generate a new ML-KEM-768 keypair
2. Encapsulation - Use the public key to encapsulate a shared secret
3. Decapsulation - Use the private key to recover the shared secret
4. Verification - Confirm that both parties have the same shared secret

This demo uses in-memory keys to provide a complete end-to-end example of 
post-quantum key exchange without requiring external key storage.

Examples:
  eos create mlkem-demo                         # Run complete ML-KEM demonstration`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return pq.DemoMLKEMWorkflow(rc)
	}),
}

func init() {
	CreateCmd.AddCommand(mlkemDemoCmd)
}