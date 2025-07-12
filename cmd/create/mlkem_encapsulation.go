// cmd/create/mlkem_encapsulation.go
package create

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto/pq"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

var mlkemEncapsulationCmd = &cobra.Command{
	Use:     "mlkem-encapsulation <public_key_hex>",
	Aliases: []string{"mlkem-encaps", "pq-encapsulation"},
	Short:   "Encapsulate a shared secret using ML-KEM public key",
	Args:    cobra.ExactArgs(1),
	Long: `Perform ML-KEM encapsulation to establish a shared secret.

This operation takes a public key (in hex format) and generates both a ciphertext 
and a shared secret. The ciphertext can be sent to the holder of the corresponding 
private key, who can then decapsulate it to recover the same shared secret.

This establishes a secure communication channel that is resistant to attacks 
from both classical and quantum computers.

Examples:
  eos create mlkem-encapsulation <public_key_hex>   # Encapsulate with public key`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		publicKeyHex := args[0]
		_, err := pq.PerformMLKEMEncapsulation(rc, publicKeyHex)
		return err
	}),
}

func init() {
	CreateCmd.AddCommand(mlkemEncapsulationCmd)
}
