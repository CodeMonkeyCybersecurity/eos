// cmd/crypto/crypto.go

package crypto

import (
	"encoding/hex"
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto/pq"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CryptoCmd represents the crypto command group
var CryptoCmd = &cobra.Command{
	Use:   "crypto",
	Short: "Cryptographic operations and post-quantum crypto testing",
	Long: `Post-quantum cryptographic operations including ML-KEM key exchange,
digital signatures, and hybrid classical+post-quantum implementations.

Examples:
  eos crypto mlkem keygen
  eos crypto mlkem demo
  eos crypto info`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("🔐 Crypto command executed - use subcommands for specific operations")
		_ = cmd.Help()
		return nil
	}),
}

func init() {
	CryptoCmd.AddCommand(mlkemCmd)
	CryptoCmd.AddCommand(infoCmd)
	CryptoCmd.AddCommand(demoCmd)
}

// mlkemCmd represents the ML-KEM operations
var mlkemCmd = &cobra.Command{
	Use:   "mlkem",
	Short: "ML-KEM (Kyber) post-quantum key exchange operations",
	Long: `ML-KEM-768 post-quantum key encapsulation mechanism operations.
Implements NIST FIPS 203 for quantum-resistant key exchange.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Info("🔐 ML-KEM command - use subcommands for specific operations")
		_ = cmd.Help()
		return nil
	}),
}

func init() {
	mlkemCmd.AddCommand(keygenCmd)
	mlkemCmd.AddCommand(encapsulateCmd)
	mlkemCmd.AddCommand(decapsulateCmd)
	mlkemCmd.AddCommand(validateCmd)
}

// keygenCmd generates a new ML-KEM keypair
var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a new ML-KEM-768 keypair",
	Long: `Generate a new ML-KEM-768 keypair for quantum-resistant key exchange.
The keypair can be used for establishing shared secrets that are secure
against both classical and quantum computer attacks.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		_, err := pq.GenerateAndDisplayMLKEMKeypair(rc)
		return err
	}),
}

// encapsulateCmd performs ML-KEM encapsulation
var encapsulateCmd = &cobra.Command{
	Use:   "encapsulate <public_key_hex>",
	Short: "Encapsulate a shared secret using ML-KEM public key",
	Args:  cobra.ExactArgs(1),
	Long: `Perform ML-KEM encapsulation to establish a shared secret.
Takes a public key (in hex format) and generates both a ciphertext
and a shared secret that can be recovered by the private key holder.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		publicKeyHex := args[0]
		_, err := pq.PerformMLKEMEncapsulation(rc, publicKeyHex)
		return err
	}),
}

// decapsulateCmd performs ML-KEM decapsulation
var decapsulateCmd = &cobra.Command{
	Use:   "decapsulate <private_key_hex> <ciphertext_hex>",
	Short: "Decapsulate shared secret using ML-KEM private key and ciphertext",
	Args:  cobra.ExactArgs(2),
	Long: `Perform ML-KEM decapsulation to recover the shared secret.
Takes a private key and ciphertext (both in hex format) and recovers
the original shared secret that was established during encapsulation.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		
		privateKeyHex := args[0]
		ciphertextHex := args[1]
		
		privateKey, err := hex.DecodeString(privateKeyHex)
		if err != nil {
			logger.Error("❌ Invalid private key format", zap.Error(err))
			return fmt.Errorf("invalid hex private key: %w", err)
		}
		
		ciphertext, err := hex.DecodeString(ciphertextHex)
		if err != nil {
			logger.Error("❌ Invalid ciphertext format", zap.Error(err))
			return fmt.Errorf("invalid hex ciphertext: %w", err)
		}
		
		logger.Info("🔐 Performing ML-KEM decapsulation",
			zap.Int("private_key_size", len(privateKey)),
			zap.Int("ciphertext_size", len(ciphertext)),
		)
		
		sharedSecret, err := pq.DecapsulateSecret(rc, privateKey, ciphertext)
		if err != nil {
			logger.Error("❌ Decapsulation failed", zap.Error(err))
			return fmt.Errorf("decapsulation failed: %w", err)
		}
		
		logger.Info("✅ ML-KEM Decapsulation Completed")
		logger.Info("🔑 Recovered Shared Secret (hex)",
			zap.String("shared_secret", hex.EncodeToString(sharedSecret)),
			zap.Int("size_bytes", len(sharedSecret)),
		)
		
		return nil
	}),
}

// validateCmd validates ML-KEM keys
var validateCmd = &cobra.Command{
	Use:   "validate <key_type> <key_hex>",
	Short: "Validate ML-KEM public or private keys",
	Args:  cobra.ExactArgs(2),
	Long: `Validate ML-KEM-768 keys to ensure they are properly formatted and valid.
Key types: 'public' or 'private'`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		
		keyType := args[0]
		keyHex := args[1]
		
		keyBytes, err := hex.DecodeString(keyHex)
		if err != nil {
			logger.Error("❌ Invalid key format", zap.Error(err))
			return fmt.Errorf("invalid hex key: %w", err)
		}
		
		switch keyType {
		case "public":
			err = pq.ValidateMLKEMPublicKey(rc, keyBytes)
		case "private":
			err = pq.ValidateMLKEMPrivateKey(rc, keyBytes)
		default:
			logger.Error("❌ Invalid key type", zap.String("key_type", keyType))
			return fmt.Errorf("invalid key type: must be 'public' or 'private'")
		}
		
		if err != nil {
			logger.Error("❌ Key validation failed", zap.Error(err))
			return fmt.Errorf("key validation failed: %w", err)
		}
		
		logger.Info("✅ Key validation successful",
			zap.String("key_type", keyType),
			zap.Int("key_size", len(keyBytes)),
		)
		
		return nil
	}),
}

// infoCmd displays information about crypto implementations
var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Display information about cryptographic implementations",
	Long: `Display detailed information about the cryptographic algorithms
and implementations available in Eos, including post-quantum algorithms.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		
		logger.Info("🔐 Eos Cryptographic Information")
		
		// ML-KEM Information
		mlkemInfo := pq.GetMLKEMInfo()
		logger.Info("📋 ML-KEM-768 Information",
			zap.Any("details", mlkemInfo),
		)
		
		logger.Info("🛡️ Quantum Resistance Status",
			zap.Bool("ml_kem_available", true),
			zap.String("ml_kem_library", "filippo.io/mlkem768"),
			zap.Bool("quantum_resistant", true),
		)
		
		logger.Info("📊 Performance Characteristics",
			zap.String("keygen_time", "~0.1ms"),
			zap.String("encaps_time", "~0.2ms"),
			zap.String("decaps_time", "~0.2ms"),
		)
		
		return nil
	}),
}

// demoCmd demonstrates complete ML-KEM workflow
var demoCmd = &cobra.Command{
	Use:   "demo",
	Short: "Demonstrate complete ML-KEM key exchange workflow",
	Long: `Run a complete demonstration of ML-KEM key exchange showing:
1. Keypair generation
2. Encapsulation 
3. Decapsulation
4. Shared secret verification

This demo uses in-memory keys to avoid API limitations with key storage.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return pq.DemoMLKEMWorkflow(rc)
	}),
}