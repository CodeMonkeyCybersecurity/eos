// cmd/read/mlkem_secret.go
package read

import (
	"encoding/hex"
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto/pq"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var mlkemSecretCmd = &cobra.Command{
	Use:     "mlkem-secret <private_key_hex> <ciphertext_hex>",
	Aliases: []string{"mlkem-decaps", "pq-decapsulation", "mlkem-decrypt"},
	Short:   "Decapsulate shared secret using ML-KEM private key and ciphertext",
	Args:    cobra.ExactArgs(2),
	Long: `Perform ML-KEM decapsulation to recover the shared secret.

This operation takes a private key and ciphertext (both in hex format) and recovers 
the original shared secret that was established during encapsulation. This completes 
the key exchange process and establishes a secure communication channel.

The recovered shared secret can then be used for symmetric encryption, message 
authentication, or other cryptographic operations.

Examples:
  eos read mlkem-secret <private_key_hex> <ciphertext_hex>   # Recover shared secret`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		privateKeyHex := args[0]
		ciphertextHex := args[1]

		privateKey, err := hex.DecodeString(privateKeyHex)
		if err != nil {
			logger.Error("Invalid private key format", zap.Error(err))
			return fmt.Errorf("invalid hex private key: %w", err)
		}

		ciphertext, err := hex.DecodeString(ciphertextHex)
		if err != nil {
			logger.Error("Invalid ciphertext format", zap.Error(err))
			return fmt.Errorf("invalid hex ciphertext: %w", err)
		}

		logger.Info("Performing ML-KEM decapsulation",
			zap.Int("private_key_size", len(privateKey)),
			zap.Int("ciphertext_size", len(ciphertext)),
		)

		sharedSecret, err := pq.DecapsulateSecret(rc, privateKey, ciphertext)
		if err != nil {
			logger.Error("Decapsulation failed", zap.Error(err))
			return fmt.Errorf("decapsulation failed: %w", err)
		}

		logger.Info("ML-KEM Decapsulation Completed")
		logger.Info("Recovered Shared Secret (hex)",
			zap.String("shared_secret", hex.EncodeToString(sharedSecret)),
			zap.Int("size_bytes", len(sharedSecret)),
		)

		return nil
	}),
}

func init() {
	ReadCmd.AddCommand(mlkemSecretCmd)
}