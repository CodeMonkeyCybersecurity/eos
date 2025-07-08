// cmd/read/mlkem_validation.go
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

var mlkemValidationCmd = &cobra.Command{
	Use:     "mlkem-validation <key_type> <key_hex>",
	Aliases: []string{"mlkem-validate", "pq-validate", "mlkem-verify"},
	Short:   "Validate ML-KEM public or private keys",
	Args:    cobra.ExactArgs(2),
	Long: `Validate ML-KEM-768 keys to ensure they are properly formatted and valid.

This command verifies that the provided key data conforms to the ML-KEM-768 
specification and contains valid cryptographic material. This is useful for 
debugging key exchange issues or verifying key integrity.

Supported key types:
- public: Validate ML-KEM public key (1184 bytes)
- private: Validate ML-KEM private key (2400 bytes)

Examples:
  eos read mlkem-validation public <public_key_hex>     # Validate public key
  eos read mlkem-validation private <private_key_hex>   # Validate private key`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		keyType := args[0]
		keyHex := args[1]

		keyBytes, err := hex.DecodeString(keyHex)
		if err != nil {
			logger.Error("Invalid key format", zap.Error(err))
			return fmt.Errorf("invalid hex key: %w", err)
		}

		switch keyType {
		case "public":
			err = pq.ValidateMLKEMPublicKey(rc, keyBytes)
		case "private":
			err = pq.ValidateMLKEMPrivateKey(rc, keyBytes)
		default:
			logger.Error("Invalid key type", zap.String("key_type", keyType))
			return fmt.Errorf("invalid key type: must be 'public' or 'private'")
		}

		if err != nil {
			logger.Error("Key validation failed", zap.Error(err))
			return fmt.Errorf("key validation failed: %w", err)
		}

		logger.Info("Key validation successful",
			zap.String("key_type", keyType),
			zap.Int("key_size", len(keyBytes)),
		)

		return nil
	}),
}

func init() {
	ReadCmd.AddCommand(mlkemValidationCmd)
}