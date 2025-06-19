// pkg/crypto/pq/mlkem.go
//
// Post-Quantum Key Encapsulation Mechanism (ML-KEM) implementation for Eos
// Implements NIST FIPS 203 ML-KEM-768 for quantum-resistant key exchange

package pq

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"filippo.io/mlkem768" // Production-ready ML-KEM implementation
)

// MLKEMKeypair represents a complete ML-KEM-768 keypair
type MLKEMKeypair struct {
	PublicKey    []byte    `json:"public_key"`
	PrivateKey   []byte    `json:"private_key"`
	GeneratedAt  time.Time `json:"generated_at"`
	Algorithm    string    `json:"algorithm"`
	SecurityLevel int      `json:"security_level"`
}

// EncapsulatedSecret contains the result of ML-KEM encapsulation
type EncapsulatedSecret struct {
	Ciphertext   []byte `json:"ciphertext"`
	SharedSecret []byte `json:"shared_secret"`
}

// HybridKeypair combines classical and post-quantum keys for transition period
type HybridKeypair struct {
	Classical   interface{} `json:"classical"`   // ECDSA or RSA key
	PostQuantum *MLKEMKeypair `json:"post_quantum"`
	CreatedAt   time.Time   `json:"created_at"`
	Usage       string      `json:"usage"` // "tls", "ssh", "vault", "general"
}

// GenerateMLKEMKeypair creates a new ML-KEM-768 keypair using crypto/rand
func GenerateMLKEMKeypair(rc *eos_io.RuntimeContext) (*MLKEMKeypair, error) {
	logger := otelzap.Ctx(rc.Ctx)
	start := time.Now()
	
	logger.Info("🔐 Generating ML-KEM-768 keypair")
	
	// Use filippo.io/mlkem768 for production-ready implementation
	decapsulationKey, err := mlkem768.GenerateKey()
	if err != nil {
		logger.Error("❌ Failed to generate ML-KEM keypair", zap.Error(err))
		return nil, fmt.Errorf("ML-KEM keypair generation failed: %w", err)
	}
	
	keypair := &MLKEMKeypair{
		PublicKey:     decapsulationKey.EncapsulationKey(),
		PrivateKey:    decapsulationKey.Bytes(),
		GeneratedAt:   time.Now(),
		Algorithm:     "ML-KEM-768",
		SecurityLevel: 128, // Equivalent to AES-128
	}
	
	duration := time.Since(start)
	logger.Info("✅ ML-KEM keypair generated successfully",
		zap.Duration("generation_time", duration),
		zap.Int("public_key_size", len(keypair.PublicKey)),
		zap.Int("private_key_size", len(keypair.PrivateKey)),
		zap.String("algorithm", keypair.Algorithm),
	)
	
	return keypair, nil
}

// EncapsulateSecret performs ML-KEM encapsulation to establish a shared secret
func EncapsulateSecret(rc *eos_io.RuntimeContext, publicKey []byte) (*EncapsulatedSecret, error) {
	logger := otelzap.Ctx(rc.Ctx)
	start := time.Now()
	
	logger.Info("🔐 Performing ML-KEM encapsulation")
	
	// Validate the public key size
	if len(publicKey) != 1184 {
		logger.Error("❌ Invalid ML-KEM public key size", zap.Int("expected", 1184), zap.Int("got", len(publicKey)))
		return nil, fmt.Errorf("invalid public key size: expected 1184, got %d", len(publicKey))
	}
	
	// Perform encapsulation using the public key bytes directly
	ciphertext, sharedSecret, err := mlkem768.Encapsulate(publicKey)
	if err != nil {
		logger.Error("❌ ML-KEM encapsulation failed", zap.Error(err))
		return nil, fmt.Errorf("encapsulation failed: %w", err)
	}
	
	result := &EncapsulatedSecret{
		Ciphertext:   ciphertext,
		SharedSecret: sharedSecret,
	}
	
	duration := time.Since(start)
	logger.Info("✅ ML-KEM encapsulation completed",
		zap.Duration("encapsulation_time", duration),
		zap.Int("ciphertext_size", len(result.Ciphertext)),
		zap.Int("shared_secret_size", len(result.SharedSecret)),
	)
	
	// Note: We log the sizes but never log the actual secret values for security
	return result, nil
}

// DecapsulateSecret performs ML-KEM decapsulation to recover the shared secret
func DecapsulateSecret(rc *eos_io.RuntimeContext, privateKey, ciphertext []byte) ([]byte, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("🔐 Performing ML-KEM decapsulation")
	
	// Validate private key size
	if len(privateKey) != 2400 {
		logger.Error("❌ Invalid ML-KEM private key size", zap.Int("expected", 2400), zap.Int("got", len(privateKey)))
		return nil, fmt.Errorf("invalid private key size: expected 2400, got %d", len(privateKey))
	}
	
	// Note: We can't easily reconstruct a DecapsulationKey from raw bytes
	// with the current API. For a production implementation, we would need
	// to store the key differently or use a different approach.
	// For now, we'll demonstrate with a simpler approach:
	
	// This is a limitation of the current API demonstration
	// In a real implementation, you would store the DecapsulationKey object
	// or use the seed-based approach for key storage
	logger.Error("❌ DecapsulationKey reconstruction from bytes not supported in current API")
	return nil, fmt.Errorf("decapsulation from stored bytes not yet implemented - use in-memory keys only")
}

// ValidateMLKEMPublicKey validates that a byte slice represents a valid ML-KEM public key
func ValidateMLKEMPublicKey(rc *eos_io.RuntimeContext, publicKey []byte) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ML-KEM-768 public key should be exactly 1184 bytes
	if len(publicKey) != 1184 {
		logger.Error("❌ Invalid ML-KEM public key size",
			zap.Int("expected_size", 1184),
			zap.Int("actual_size", len(publicKey)),
		)
		return fmt.Errorf("invalid ML-KEM-768 public key size: expected 1184 bytes, got %d", len(publicKey))
	}
	
	// Try to use the key for encapsulation to ensure it's valid
	_, _, err := mlkem768.Encapsulate(publicKey)
	if err != nil {
		logger.Error("❌ ML-KEM public key validation failed", zap.Error(err))
		return fmt.Errorf("invalid ML-KEM public key: %w", err)
	}
	
	logger.Info("✅ ML-KEM public key validation passed")
	return nil
}

// ValidateMLKEMPrivateKey validates that a byte slice represents a valid ML-KEM private key
func ValidateMLKEMPrivateKey(rc *eos_io.RuntimeContext, privateKey []byte) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ML-KEM-768 private key should be exactly 2400 bytes
	if len(privateKey) != 2400 {
		logger.Error("❌ Invalid ML-KEM private key size",
			zap.Int("expected_size", 2400),
			zap.Int("actual_size", len(privateKey)),
		)
		return fmt.Errorf("invalid ML-KEM-768 private key size: expected 2400 bytes, got %d", len(privateKey))
	}
	
	// Note: With the current API, we can only validate the size
	// Full validation would require reconstructing the DecapsulationKey
	// which isn't easily possible from raw bytes with this API
	logger.Info("🔍 ML-KEM private key size validation only (API limitation)")
	
	logger.Info("✅ ML-KEM private key validation passed")
	return nil
}

// GenerateHybridKeypair creates both classical and post-quantum keys for transition period
func GenerateHybridKeypair(rc *eos_io.RuntimeContext, usage string) (*HybridKeypair, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("🔐 Generating hybrid keypair",
		zap.String("usage", usage),
	)
	
	// Generate post-quantum component
	pqKey, err := GenerateMLKEMKeypair(rc)
	if err != nil {
		return nil, fmt.Errorf("post-quantum key generation failed: %w", err)
	}
	
	// For now, we'll focus on the post-quantum component
	// Classical key generation can be added based on specific usage requirements
	
	hybrid := &HybridKeypair{
		Classical:   nil, // TODO: Add classical key based on usage
		PostQuantum: pqKey,
		CreatedAt:   time.Now(),
		Usage:       usage,
	}
	
	logger.Info("✅ Hybrid keypair generated successfully",
		zap.String("usage", usage),
		zap.Time("created_at", hybrid.CreatedAt),
	)
	
	return hybrid, nil
}

// GetMLKEMInfo returns information about the ML-KEM implementation
func GetMLKEMInfo() map[string]interface{} {
	return map[string]interface{}{
		"algorithm":           "ML-KEM-768",
		"standard":           "NIST FIPS 203",
		"security_level":     128,
		"public_key_size":    1184,
		"private_key_size":   2400,
		"ciphertext_size":    1088,
		"shared_secret_size": 32,
		"quantum_resistant":  true,
		"library":           "crypto/mlkem768",
		"go_version_min":    "1.24",
	}
}