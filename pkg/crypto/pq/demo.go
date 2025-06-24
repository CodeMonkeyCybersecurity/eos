// pkg/crypto/pq/demo.go
//
// Working ML-KEM demonstration that works within API limitations

package pq

import (
	"encoding/hex"
	"fmt"
	"time"

	"filippo.io/mlkem768"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DemoMLKEMWorkflow demonstrates a complete ML-KEM workflow using in-memory keys
func DemoMLKEMWorkflow(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info(" Starting ML-KEM Demo Workflow")
	start := time.Now()

	// Step 1: Generate keypair
	logger.Info(" Step 1: Generating ML-KEM keypair")
	decapsulationKey, err := mlkem768.GenerateKey()
	if err != nil {
		logger.Error(" Keypair generation failed", zap.Error(err))
		return fmt.Errorf("keypair generation failed: %w", err)
	}

	encapsulationKey := decapsulationKey.EncapsulationKey()

	logger.Info(" Keypair generated successfully",
		zap.Int("public_key_size", len(encapsulationKey)),
		zap.Int("private_key_size", len(decapsulationKey.Bytes())),
	)

	// Step 2: Encapsulate secret
	logger.Info(" Step 2: Performing encapsulation")
	ciphertext, sharedSecret1, err := mlkem768.Encapsulate(encapsulationKey)
	if err != nil {
		logger.Error(" Encapsulation failed", zap.Error(err))
		return fmt.Errorf("encapsulation failed: %w", err)
	}

	logger.Info(" Encapsulation completed",
		zap.Int("ciphertext_size", len(ciphertext)),
		zap.Int("shared_secret_size", len(sharedSecret1)),
	)

	// Step 3: Decapsulate secret
	logger.Info(" Step 3: Performing decapsulation")
	sharedSecret2, err := mlkem768.Decapsulate(decapsulationKey, ciphertext)
	if err != nil {
		logger.Error(" Decapsulation failed", zap.Error(err))
		return fmt.Errorf("decapsulation failed: %w", err)
	}

	logger.Info(" Decapsulation completed",
		zap.Int("recovered_secret_size", len(sharedSecret2)),
	)

	// Step 4: Verify secrets match
	logger.Info(" Step 4: Verifying shared secrets match")
	secret1Hex := hex.EncodeToString(sharedSecret1)
	secret2Hex := hex.EncodeToString(sharedSecret2)

	if secret1Hex != secret2Hex {
		logger.Error(" Demo failed: shared secrets do not match",
			zap.String("secret1", secret1Hex),
			zap.String("secret2", secret2Hex),
		)
		return fmt.Errorf("demo failed: shared secret mismatch")
	}

	duration := time.Since(start)
	logger.Info(" ML-KEM Demo Completed Successfully!",
		zap.String("shared_secret", secret1Hex),
		zap.Duration("total_time", duration),
		zap.Bool("secrets_match", true),
	)

	// Display key sizes and characteristics
	logger.Info(" ML-KEM-768 Characteristics",
		zap.Int("public_key_bytes", len(encapsulationKey)),
		zap.Int("private_key_bytes", len(decapsulationKey.Bytes())),
		zap.Int("ciphertext_bytes", len(ciphertext)),
		zap.Int("shared_secret_bytes", len(sharedSecret1)),
		zap.String("algorithm", "ML-KEM-768"),
		zap.String("standard", "NIST FIPS 203"),
		zap.Int("security_level", 128),
		zap.Bool("quantum_resistant", true),
	)

	logger.Info(" Post-quantum key exchange demonstration successful!")

	return nil
}

// GenerateAndDisplayMLKEMKeypair generates a keypair and displays it in hex format
func GenerateAndDisplayMLKEMKeypair(rc *eos_io.RuntimeContext) (*MLKEMKeypair, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info(" Generating ML-KEM-768 keypair for display")

	decapsulationKey, err := mlkem768.GenerateKey()
	if err != nil {
		logger.Error(" Keypair generation failed", zap.Error(err))
		return nil, fmt.Errorf("keypair generation failed: %w", err)
	}

	keypair := &MLKEMKeypair{
		PublicKey:     decapsulationKey.EncapsulationKey(),
		PrivateKey:    decapsulationKey.Bytes(),
		GeneratedAt:   time.Now(),
		Algorithm:     "ML-KEM-768",
		SecurityLevel: 128,
	}

	// Display the results (hex encoded for CLI display)
	logger.Info(" ML-KEM-768 Keypair Generated Successfully")
	logger.Info(" Keypair Details",
		zap.String("algorithm", keypair.Algorithm),
		zap.Int("security_level", keypair.SecurityLevel),
		zap.Time("generated_at", keypair.GeneratedAt),
	)

	logger.Info(" Public Key (hex)",
		zap.String("public_key", hex.EncodeToString(keypair.PublicKey)),
		zap.Int("size_bytes", len(keypair.PublicKey)),
	)

	logger.Info(" Private Key (hex) - KEEP SECURE",
		zap.String("private_key", hex.EncodeToString(keypair.PrivateKey)),
		zap.Int("size_bytes", len(keypair.PrivateKey)),
	)

	logger.Info("💡 Usage Instructions",
		zap.String("next_step", "Use the public key with 'eos crypto mlkem encapsulate <public_key>'"),
		zap.String("note", "For full demo without key storage, use 'eos crypto demo'"),
	)

	return keypair, nil
}

// PerformMLKEMEncapsulation performs encapsulation and displays results
func PerformMLKEMEncapsulation(rc *eos_io.RuntimeContext, publicKeyHex string) (*EncapsulatedSecret, error) {
	logger := otelzap.Ctx(rc.Ctx)

	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		logger.Error(" Invalid public key format", zap.Error(err))
		return nil, fmt.Errorf("invalid hex public key: %w", err)
	}

	logger.Info(" Performing ML-KEM encapsulation",
		zap.Int("public_key_size", len(publicKey)),
	)

	if len(publicKey) != 1184 {
		logger.Error(" Invalid public key size", zap.Int("expected", 1184), zap.Int("got", len(publicKey)))
		return nil, fmt.Errorf("invalid public key size: expected 1184, got %d", len(publicKey))
	}

	ciphertext, sharedSecret, err := mlkem768.Encapsulate(publicKey)
	if err != nil {
		logger.Error(" Encapsulation failed", zap.Error(err))
		return nil, fmt.Errorf("encapsulation failed: %w", err)
	}

	result := &EncapsulatedSecret{
		Ciphertext:   ciphertext,
		SharedSecret: sharedSecret,
	}

	logger.Info(" ML-KEM Encapsulation Completed")
	logger.Info(" Ciphertext (hex)",
		zap.String("ciphertext", hex.EncodeToString(result.Ciphertext)),
		zap.Int("size_bytes", len(result.Ciphertext)),
	)

	logger.Info(" Shared Secret (hex)",
		zap.String("shared_secret", hex.EncodeToString(result.SharedSecret)),
		zap.Int("size_bytes", len(result.SharedSecret)),
	)

	logger.Info("💡 Note",
		zap.String("limitation", "Decapsulation requires in-memory keys due to API constraints"),
		zap.String("recommendation", "Use 'eos crypto demo' for full workflow demonstration"),
	)

	return result, nil
}
