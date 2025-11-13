// cmd/create/mlkem_keypair.go
package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto/pq"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

var mlkemKeypairCmd = &cobra.Command{
	Use:     "mlkem-keypair",
	Aliases: []string{"mlkem-keys", "pq-keypair", "quantum-keypair"},
	Short:   "Generate a new ML-KEM-768 keypair",
	Long: `Generate a new ML-KEM-768 keypair for quantum-resistant key exchange.

ML-KEM (Module-Lattice-based Key Encapsulation Mechanism) is a NIST-standardized 
post-quantum cryptographic algorithm that provides security against both classical 
and quantum computer attacks.

The generated keypair can be used for establishing shared secrets that remain secure 
even when quantum computers become available.

Examples:
  eos create mlkem-keypair                      # Generate new ML-KEM keypair`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		_, err := pq.GenerateAndDisplayMLKEMKeypair(rc)
		return err
	}),
}

func init() {
	CreateCmd.AddCommand(mlkemKeypairCmd)
}
