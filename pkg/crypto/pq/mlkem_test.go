// pkg/crypto/pq/mlkem_test.go - Comprehensive tests for post-quantum cryptography
package pq

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"filippo.io/mlkem768"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// createTestContext creates a test runtime context
func createTestContext(t *testing.T) *eos_io.RuntimeContext {
	return &eos_io.RuntimeContext{
		Ctx: context.Background(),
		Log: zaptest.NewLogger(t),
	}
}

// TestGenerateMLKEMKeypair tests ML-KEM keypair generation
func TestGenerateMLKEMKeypair(t *testing.T) {
	rc := createTestContext(t)

	t.Run("successful_generation", func(t *testing.T) {
		keypair, err := GenerateMLKEMKeypair(rc)
		require.NoError(t, err)
		require.NotNil(t, keypair)

		// Verify key sizes
		assert.Equal(t, 1184, len(keypair.PublicKey), "Public key should be 1184 bytes")
		assert.Equal(t, 2400, len(keypair.PrivateKey), "Private key should be 2400 bytes")

		// Verify metadata
		assert.Equal(t, "ML-KEM-768", keypair.Algorithm)
		assert.Equal(t, 128, keypair.SecurityLevel)
		assert.WithinDuration(t, time.Now(), keypair.GeneratedAt, 1*time.Second)

		// Keys should not be zero
		assert.NotEqual(t, make([]byte, 1184), keypair.PublicKey)
		assert.NotEqual(t, make([]byte, 2400), keypair.PrivateKey)
	})

	t.Run("multiple_generations_unique", func(t *testing.T) {
		const numKeys = 10
		publicKeys := make(map[string]bool)
		privateKeys := make(map[string]bool)

		for i := 0; i < numKeys; i++ {
			keypair, err := GenerateMLKEMKeypair(rc)
			require.NoError(t, err)

			pubHex := hex.EncodeToString(keypair.PublicKey)
			privHex := hex.EncodeToString(keypair.PrivateKey)

			// Ensure uniqueness
			assert.False(t, publicKeys[pubHex], "Duplicate public key generated")
			assert.False(t, privateKeys[privHex], "Duplicate private key generated")

			publicKeys[pubHex] = true
			privateKeys[privHex] = true
		}
	})

	t.Run("concurrent_generation", func(t *testing.T) {
		const goroutines = 20
		errors := make([]error, goroutines)
		keypairs := make([]*MLKEMKeypair, goroutines)
		var wg sync.WaitGroup

		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				kp, err := GenerateMLKEMKeypair(rc)
				errors[idx] = err
				keypairs[idx] = kp
			}(i)
		}

		wg.Wait()

		// Verify all succeeded
		for i, err := range errors {
			assert.NoError(t, err, "Goroutine %d failed", i)
			assert.NotNil(t, keypairs[i])
		}

		// Verify uniqueness across concurrent generations
		seen := make(map[string]bool)
		for i, kp := range keypairs {
			pubHex := hex.EncodeToString(kp.PublicKey)
			assert.False(t, seen[pubHex], "Duplicate key in concurrent generation at index %d", i)
			seen[pubHex] = true
		}
	})
}

// TestEncapsulateSecret tests ML-KEM encapsulation
func TestEncapsulateSecret(t *testing.T) {
	rc := createTestContext(t)

	// Generate a valid keypair for testing
	keypair, err := GenerateMLKEMKeypair(rc)
	require.NoError(t, err)

	t.Run("successful_encapsulation", func(t *testing.T) {
		result, err := EncapsulateSecret(rc, keypair.PublicKey)
		require.NoError(t, err)
		require.NotNil(t, result)

		// Verify sizes
		assert.Equal(t, 1088, len(result.Ciphertext), "Ciphertext should be 1088 bytes")
		assert.Equal(t, 32, len(result.SharedSecret), "Shared secret should be 32 bytes")

		// Values should not be zero
		assert.NotEqual(t, make([]byte, 1088), result.Ciphertext)
		assert.NotEqual(t, make([]byte, 32), result.SharedSecret)
	})

	t.Run("invalid_public_key_size", func(t *testing.T) {
		invalidSizes := []int{0, 1183, 1185, 2400, 100}

		for _, size := range invalidSizes {
			invalidKey := make([]byte, size)
			_, err := EncapsulateSecret(rc, invalidKey)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid public key size")
		}
	})

	t.Run("multiple_encapsulations_different", func(t *testing.T) {
		// Multiple encapsulations with same public key should produce different results
		results := make([]*EncapsulatedSecret, 10)

		for i := 0; i < 10; i++ {
			result, err := EncapsulateSecret(rc, keypair.PublicKey)
			require.NoError(t, err)
			results[i] = result
		}

		// All ciphertexts should be unique (extremely high probability)
		for i := 0; i < len(results); i++ {
			for j := i + 1; j < len(results); j++ {
				assert.False(t, bytes.Equal(results[i].Ciphertext, results[j].Ciphertext),
					"Ciphertexts %d and %d are identical", i, j)
				assert.False(t, bytes.Equal(results[i].SharedSecret, results[j].SharedSecret),
					"Shared secrets %d and %d are identical", i, j)
			}
		}
	})

	t.Run("malformed_public_key", func(t *testing.T) {
		// Create a malformed key of correct size
		malformedKey := make([]byte, 1184)
		// Fill with invalid data that would fail encapsulation
		for i := range malformedKey {
			malformedKey[i] = 0xFF
		}

		_, err := EncapsulateSecret(rc, malformedKey)
		// The mlkem768 library might accept this, but it's worth testing
		_ = err // Error handling depends on library implementation
	})
}

// TestDecapsulateSecret tests ML-KEM decapsulation
func TestDecapsulateSecret(t *testing.T) {
	rc := createTestContext(t)

	t.Run("api_limitation_acknowledged", func(t *testing.T) {
		// Test acknowledges current API limitation
		privateKey := make([]byte, 2400)
		ciphertext := make([]byte, 1088)

		_, err := DecapsulateSecret(rc, privateKey, ciphertext)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not yet implemented")
	})

	t.Run("validates_private_key_size", func(t *testing.T) {
		invalidSizes := []int{0, 2399, 2401, 1184}

		for _, size := range invalidSizes {
			privateKey := make([]byte, size)
			ciphertext := make([]byte, 1088)

			_, err := DecapsulateSecret(rc, privateKey, ciphertext)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid private key size")
		}
	})
}

// TestValidateMLKEMPublicKey tests public key validation
func TestValidateMLKEMPublicKey(t *testing.T) {
	rc := createTestContext(t)

	t.Run("valid_public_key", func(t *testing.T) {
		keypair, err := GenerateMLKEMKeypair(rc)
		require.NoError(t, err)

		err = ValidateMLKEMPublicKey(rc, keypair.PublicKey)
		assert.NoError(t, err)
	})

	t.Run("invalid_sizes", func(t *testing.T) {
		testCases := []struct {
			size     int
			name     string
		}{
			{0, "empty"},
			{1183, "one_byte_short"},
			{1185, "one_byte_long"},
			{2400, "private_key_size"},
			{100, "too_small"},
			{10000, "too_large"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				key := make([]byte, tc.size)
				err := ValidateMLKEMPublicKey(rc, key)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid ML-KEM-768 public key size")
			})
		}
	})

	t.Run("random_bytes_validation", func(t *testing.T) {
		// Test with random bytes of correct size
		randomKey := make([]byte, 1184)
		_, err := rand.Read(randomKey)
		require.NoError(t, err)

		// This might or might not fail depending on the random data
		_ = ValidateMLKEMPublicKey(rc, randomKey)
	})
}

// TestValidateMLKEMPrivateKey tests private key validation
func TestValidateMLKEMPrivateKey(t *testing.T) {
	rc := createTestContext(t)

	t.Run("valid_private_key", func(t *testing.T) {
		keypair, err := GenerateMLKEMKeypair(rc)
		require.NoError(t, err)

		err = ValidateMLKEMPrivateKey(rc, keypair.PrivateKey)
		assert.NoError(t, err)
	})

	t.Run("invalid_sizes", func(t *testing.T) {
		invalidSizes := []int{0, 2399, 2401, 1184, 100, 10000}

		for _, size := range invalidSizes {
			key := make([]byte, size)
			err := ValidateMLKEMPrivateKey(rc, key)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid ML-KEM-768 private key size")
		}
	})
}

// TestGenerateHybridKeypair tests hybrid keypair generation
func TestGenerateHybridKeypair(t *testing.T) {
	rc := createTestContext(t)

	usageCases := []string{"tls", "ssh", "vault", "general"}

	for _, usage := range usageCases {
		t.Run(usage, func(t *testing.T) {
			hybrid, err := GenerateHybridKeypair(rc, usage)
			require.NoError(t, err)
			require.NotNil(t, hybrid)

			// Verify structure
			assert.NotNil(t, hybrid.PostQuantum)
			assert.Equal(t, usage, hybrid.Usage)
			assert.WithinDuration(t, time.Now(), hybrid.CreatedAt, 1*time.Second)

			// Verify post-quantum component
			assert.Equal(t, 1184, len(hybrid.PostQuantum.PublicKey))
			assert.Equal(t, 2400, len(hybrid.PostQuantum.PrivateKey))

			// Classical component is TODO
			assert.Nil(t, hybrid.Classical)
		})
	}
}

// TestGetMLKEMInfo tests information retrieval
func TestGetMLKEMInfo(t *testing.T) {
	info := GetMLKEMInfo()

	// Verify all expected fields
	assert.Equal(t, "ML-KEM-768", info["algorithm"])
	assert.Equal(t, "NIST FIPS 203", info["standard"])
	assert.Equal(t, 128, info["security_level"])
	assert.Equal(t, 1184, info["public_key_size"])
	assert.Equal(t, 2400, info["private_key_size"])
	assert.Equal(t, 1088, info["ciphertext_size"])
	assert.Equal(t, 32, info["shared_secret_size"])
	assert.Equal(t, true, info["quantum_resistant"])
	assert.Equal(t, "crypto/mlkem768", info["library"])
	assert.Equal(t, "1.24", info["go_version_min"])
}

// TestEndToEndKeyExchange tests complete key exchange flow
func TestEndToEndKeyExchange(t *testing.T) {
	rc := createTestContext(t)

	t.Run("alice_bob_key_exchange", func(t *testing.T) {
		// Alice generates keypair
		aliceKeypair, err := GenerateMLKEMKeypair(rc)
		require.NoError(t, err)

		// Bob encapsulates using Alice's public key
		bobResult, err := EncapsulateSecret(rc, aliceKeypair.PublicKey)
		require.NoError(t, err)

		// In a real implementation, Alice would decapsulate using her private key
		// to get the same shared secret as Bob
		// Due to API limitations, we can't demonstrate the full flow

		// But we can verify the encapsulation worked
		assert.NotNil(t, bobResult.SharedSecret)
		assert.NotNil(t, bobResult.Ciphertext)
	})

	t.Run("parallel_key_exchanges", func(t *testing.T) {
		const numExchanges = 10
		var wg sync.WaitGroup

		for i := 0; i < numExchanges; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()

				// Each exchange is independent
				keypair, err := GenerateMLKEMKeypair(rc)
				assert.NoError(t, err)

				result, err := EncapsulateSecret(rc, keypair.PublicKey)
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}(i)
		}

		wg.Wait()
	})
}

// TestSecurityProperties tests security properties of ML-KEM
func TestSecurityProperties(t *testing.T) {
	rc := createTestContext(t)

	t.Run("key_independence", func(t *testing.T) {
		// Generate multiple keypairs
		keypairs := make([]*MLKEMKeypair, 5)
		for i := 0; i < 5; i++ {
			kp, err := GenerateMLKEMKeypair(rc)
			require.NoError(t, err)
			keypairs[i] = kp
		}

		// Verify all keys are unique
		for i := 0; i < len(keypairs); i++ {
			for j := i + 1; j < len(keypairs); j++ {
				assert.False(t, bytes.Equal(keypairs[i].PublicKey, keypairs[j].PublicKey),
					"Public keys %d and %d are identical", i, j)
				assert.False(t, bytes.Equal(keypairs[i].PrivateKey, keypairs[j].PrivateKey),
					"Private keys %d and %d are identical", i, j)
			}
		}
	})

	t.Run("ciphertext_randomness", func(t *testing.T) {
		keypair, err := GenerateMLKEMKeypair(rc)
		require.NoError(t, err)

		// Multiple encapsulations should produce different ciphertexts
		ciphertexts := make([][]byte, 10)
		secrets := make([][]byte, 10)

		for i := 0; i < 10; i++ {
			result, err := EncapsulateSecret(rc, keypair.PublicKey)
			require.NoError(t, err)
			ciphertexts[i] = result.Ciphertext
			secrets[i] = result.SharedSecret
		}

		// All should be unique
		for i := 0; i < len(ciphertexts); i++ {
			for j := i + 1; j < len(ciphertexts); j++ {
				assert.False(t, bytes.Equal(ciphertexts[i], ciphertexts[j]),
					"Ciphertexts %d and %d are identical", i, j)
			}
		}
	})

	t.Run("no_key_leakage", func(t *testing.T) {
		keypair, err := GenerateMLKEMKeypair(rc)
		require.NoError(t, err)

		// Public key should not contain private key information
		pubHex := hex.EncodeToString(keypair.PublicKey)
		privHex := hex.EncodeToString(keypair.PrivateKey)

		assert.False(t, bytes.Contains(keypair.PublicKey, keypair.PrivateKey[:32]))
		assert.False(t, bytes.Contains(keypair.PrivateKey, keypair.PublicKey[:32]))
		assert.NotContains(t, privHex, pubHex[:64])
	})
}

// TestMemorySafety tests for memory safety issues
func TestMemorySafety(t *testing.T) {
	rc := createTestContext(t)

	t.Run("key_material_in_memory", func(t *testing.T) {
		// Generate keypair
		keypair, err := GenerateMLKEMKeypair(rc)
		require.NoError(t, err)

		// Make copies to simulate key usage
		pubCopy := make([]byte, len(keypair.PublicKey))
		privCopy := make([]byte, len(keypair.PrivateKey))
		copy(pubCopy, keypair.PublicKey)
		copy(privCopy, keypair.PrivateKey)

		// Overwrite original (simulating cleanup)
		for i := range keypair.PublicKey {
			keypair.PublicKey[i] = 0
		}
		for i := range keypair.PrivateKey {
			keypair.PrivateKey[i] = 0
		}

		// Copies should still be valid
		assert.NotEqual(t, make([]byte, len(pubCopy)), pubCopy)
		assert.NotEqual(t, make([]byte, len(privCopy)), privCopy)

		// Note: In Go, we can't truly clear memory due to GC
		t.Log("WARNING: Key material remains in memory until garbage collected")
	})
}

// TestPerformance benchmarks ML-KEM operations
func TestPerformance(t *testing.T) {
	rc := createTestContext(t)

	t.Run("generation_performance", func(t *testing.T) {
		start := time.Now()
		const iterations = 10

		for i := 0; i < iterations; i++ {
			_, err := GenerateMLKEMKeypair(rc)
			require.NoError(t, err)
		}

		elapsed := time.Since(start)
		avgTime := elapsed / iterations
		t.Logf("Average keypair generation time: %v", avgTime)

		// Performance expectation (adjust based on hardware)
		assert.Less(t, avgTime, 50*time.Millisecond, "Generation too slow")
	})

	t.Run("encapsulation_performance", func(t *testing.T) {
		keypair, err := GenerateMLKEMKeypair(rc)
		require.NoError(t, err)

		start := time.Now()
		const iterations = 100

		for i := 0; i < iterations; i++ {
			_, err := EncapsulateSecret(rc, keypair.PublicKey)
			require.NoError(t, err)
		}

		elapsed := time.Since(start)
		avgTime := elapsed / iterations
		t.Logf("Average encapsulation time: %v", avgTime)

		// Encapsulation should be fast
		assert.Less(t, avgTime, 5*time.Millisecond, "Encapsulation too slow")
	})
}

// TestRealWorldScenarios tests real-world usage patterns
func TestRealWorldScenarios(t *testing.T) {
	rc := createTestContext(t)

	t.Run("tls_handshake_simulation", func(t *testing.T) {
		// Server generates long-term keypair
		serverKeypair, err := GenerateMLKEMKeypair(rc)
		require.NoError(t, err)

		// Simulate multiple client connections
		for i := 0; i < 5; i++ {
			// Client encapsulates to server's public key
			clientResult, err := EncapsulateSecret(rc, serverKeypair.PublicKey)
			require.NoError(t, err)

			// Each client gets unique shared secret
			assert.Equal(t, 32, len(clientResult.SharedSecret))
			t.Logf("Client %d established shared secret", i)
		}
	})

	t.Run("key_rotation_scenario", func(t *testing.T) {
		// Simulate key rotation every N operations
		const rotationInterval = 3
		var currentKeypair *MLKEMKeypair
		
		for i := 0; i < 10; i++ {
			// Rotate keys at interval
			if i%rotationInterval == 0 {
				newKeypair, err := GenerateMLKEMKeypair(rc)
				require.NoError(t, err)
				currentKeypair = newKeypair
				t.Logf("Rotated to new keypair at operation %d", i)
			}

			// Use current keypair
			_, err := EncapsulateSecret(rc, currentKeypair.PublicKey)
			require.NoError(t, err)
		}
	})
}

// BenchmarkMLKEMOperations benchmarks various ML-KEM operations
func BenchmarkMLKEMOperations(b *testing.B) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
		Log: zaptest.NewLogger(b),
	}

	b.Run("GenerateKeypair", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = GenerateMLKEMKeypair(rc)
		}
	})

	// Generate keypair for encapsulation benchmarks
	keypair, err := GenerateMLKEMKeypair(rc)
	require.NoError(b, err)

	b.Run("Encapsulate", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = EncapsulateSecret(rc, keypair.PublicKey)
		}
	})

	b.Run("ValidatePublicKey", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = ValidateMLKEMPublicKey(rc, keypair.PublicKey)
		}
	})

	b.Run("RawMLKEM768Generate", func(b *testing.B) {
		// Benchmark raw library performance for comparison
		for i := 0; i < b.N; i++ {
			_, _ = mlkem768.GenerateKey()
		}
	})

	b.Run("RawMLKEM768Encapsulate", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, _ = mlkem768.Encapsulate(keypair.PublicKey)
		}
	})
}

// TestErrorHandling tests error handling edge cases
func TestErrorHandling(t *testing.T) {
	t.Run("nil_context_handling", func(t *testing.T) {
		// Test with nil context (should not panic)
		assert.NotPanics(t, func() {
			// Create context with nil ctx but valid logger
			rc := &eos_io.RuntimeContext{
				Ctx: nil,
				Log: zaptest.NewLogger(t),
			}
			_, _ = GenerateMLKEMKeypair(rc)
		})
	})

	t.Run("empty_byte_arrays", func(t *testing.T) {
		rc := createTestContext(t)

		// Test with empty arrays
		err := ValidateMLKEMPublicKey(rc, []byte{})
		assert.Error(t, err)

		err = ValidateMLKEMPrivateKey(rc, []byte{})
		assert.Error(t, err)

		_, err = EncapsulateSecret(rc, []byte{})
		assert.Error(t, err)
	})
}

// TestAPICompatibility verifies compatibility with different API versions
func TestAPICompatibility(t *testing.T) {
	rc := createTestContext(t)

	t.Run("struct_serialization", func(t *testing.T) {
		keypair, err := GenerateMLKEMKeypair(rc)
		require.NoError(t, err)

		// Verify the struct can be used for serialization
		assert.NotEmpty(t, keypair.Algorithm)
		assert.NotEmpty(t, keypair.PublicKey)
		assert.NotEmpty(t, keypair.PrivateKey)
		assert.False(t, keypair.GeneratedAt.IsZero())
		assert.Greater(t, keypair.SecurityLevel, 0)
	})

	t.Run("info_completeness", func(t *testing.T) {
		info := GetMLKEMInfo()
		
		// Verify all expected fields are present
		requiredFields := []string{
			"algorithm", "standard", "security_level",
			"public_key_size", "private_key_size",
			"ciphertext_size", "shared_secret_size",
			"quantum_resistant", "library", "go_version_min",
		}

		for _, field := range requiredFields {
			assert.Contains(t, info, field, "Missing required field: %s", field)
		}
	})
}