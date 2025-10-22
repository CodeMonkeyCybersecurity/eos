package secrets

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// TestDefaultOptions tests the default options creation
func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts == nil {
		t.Fatal("DefaultOptions returned nil")
	}

	if opts.Length != 32 {
		t.Errorf("Default length = %d, want 32", opts.Length)
	}

	if opts.Format != "hex" {
		t.Errorf("Default format = %q, want %q", opts.Format, "hex")
	}
}

// TestGenerate tests the Generate function
func TestGenerate(t *testing.T) {
	tests := []struct {
		name    string
		opts    *GenerateSecretOptions
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid hex generation",
			opts: &GenerateSecretOptions{
				Length: 16,
				Format: "hex",
			},
			wantErr: false,
		},
		{
			name: "valid base64 generation",
			opts: &GenerateSecretOptions{
				Length: 24,
				Format: "base64",
			},
			wantErr: false,
		},
		{
			name: "zero length",
			opts: &GenerateSecretOptions{
				Length: 0,
				Format: "hex",
			},
			wantErr: true,
			errMsg:  "hex secret too short: min byte length 7", // Updated: now delegates to crypto
		},
		{
			name: "negative length",
			opts: &GenerateSecretOptions{
				Length: -10,
				Format: "hex",
			},
			wantErr: true,
			errMsg:  "hex secret too short: min byte length 7", // Updated: now delegates to crypto
		},
		{
			name: "unsupported format",
			opts: &GenerateSecretOptions{
				Length: 16,
				Format: "binary",
			},
			wantErr: false, // Updated: unsupported formats default to hex
		},
		{
			name: "empty format",
			opts: &GenerateSecretOptions{
				Length: 16,
				Format: "",
			},
			wantErr: false, // Updated: empty format defaults to hex
		},
		{
			name: "large length",
			opts: &GenerateSecretOptions{
				Length: 1024,
				Format: "hex",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Generate(tt.opts)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errMsg != "" && err.Error() != tt.errMsg {
					t.Errorf("Error = %q, want %q", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Fatalf("Generate() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Verify result format
			switch tt.opts.Format {
			case "hex":
				// Hex string should be 2x the byte length
				expectedLen := tt.opts.Length * 2
				if len(result) != expectedLen {
					t.Errorf("Hex result length = %d, want %d", len(result), expectedLen)
				}
				// Verify it's valid hex
				if _, err := hex.DecodeString(result); err != nil {
					t.Errorf("Invalid hex string: %v", err)
				}

			case "base64":
				// Verify it's valid base64
				decoded, err := base64.StdEncoding.DecodeString(result)
				if err != nil {
					t.Errorf("Invalid base64 string: %v", err)
				}
				// Decoded length should match requested length
				if len(decoded) != tt.opts.Length {
					t.Errorf("Decoded length = %d, want %d", len(decoded), tt.opts.Length)
				}
			}
		})
	}
}

// TestGenerateHex tests the convenience hex generation function
func TestGenerateHex(t *testing.T) {
	tests := []struct {
		length  int
		wantErr bool
	}{
		{16, false},
		{32, false},
		{64, false},
		{0, true},
		{-1, true},
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.length)), func(t *testing.T) {
			result, err := GenerateHex(tt.length)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("GenerateHex() error = %v", err)
			}

			// Verify hex format
			expectedLen := tt.length * 2
			if len(result) != expectedLen {
				t.Errorf("Result length = %d, want %d", len(result), expectedLen)
			}

			if _, err := hex.DecodeString(result); err != nil {
				t.Errorf("Invalid hex string: %v", err)
			}
		})
	}
}

// TestGenerateBase64 tests the convenience base64 generation function
func TestGenerateBase64(t *testing.T) {
	tests := []struct {
		length  int
		wantErr bool
	}{
		{16, false},
		{24, false},
		{32, false},
		{0, true},
		{-1, true},
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.length)), func(t *testing.T) {
			result, err := GenerateBase64(tt.length)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("GenerateBase64() error = %v", err)
			}

			// Verify base64 format
			decoded, err := base64.StdEncoding.DecodeString(result)
			if err != nil {
				t.Errorf("Invalid base64 string: %v", err)
			}

			if len(decoded) != tt.length {
				t.Errorf("Decoded length = %d, want %d", len(decoded), tt.length)
			}
		})
	}
}

// TestGenerateUniqueness tests that generated secrets are unique
func TestGenerateUniqueness(t *testing.T) {
	opts := &GenerateSecretOptions{
		Length: 16,
		Format: "hex",
	}

	secrets := make(map[string]bool)
	iterations := 100

	for i := 0; i < iterations; i++ {
		secret, err := Generate(opts)
		if err != nil {
			t.Fatalf("Generate() failed: %v", err)
		}

		if secrets[secret] {
			t.Errorf("Duplicate secret generated: %s", secret)
		}
		secrets[secret] = true
	}

	if len(secrets) != iterations {
		t.Errorf("Expected %d unique secrets, got %d", iterations, len(secrets))
	}
}

// TestGenerateRandomness tests the randomness of generated secrets
func TestGenerateRandomness(t *testing.T) {
	// Generate multiple secrets and check for patterns
	opts := &GenerateSecretOptions{
		Length: 32,
		Format: "hex",
	}

	// Generate 10 secrets
	var secrets []string
	for i := 0; i < 10; i++ {
		secret, err := Generate(opts)
		if err != nil {
			t.Fatalf("Generate() failed: %v", err)
		}
		secrets = append(secrets, secret)
	}

	// Check that secrets don't have obvious patterns
	for i := 0; i < len(secrets)-1; i++ {
		if secrets[i] == secrets[i+1] {
			t.Error("Consecutive secrets are identical")
		}

		// Check if secrets share common prefixes (unlikely with good randomness)
		if len(secrets[i]) > 16 && secrets[i][:16] == secrets[i+1][:16] {
			t.Error("Secrets share long common prefix")
		}
	}
}

// TestGenerateConcurrency tests concurrent secret generation
func TestGenerateConcurrency(t *testing.T) {
	opts := &GenerateSecretOptions{
		Length: 16,
		Format: "hex",
	}

	done := make(chan string, 100)
	errors := make(chan error, 100)

	// Generate secrets concurrently
	for i := 0; i < 100; i++ {
		go func() {
			secret, err := Generate(opts)
			if err != nil {
				errors <- err
				return
			}
			done <- secret
		}()
	}

	// Collect results
	secrets := make(map[string]bool)
	for i := 0; i < 100; i++ {
		select {
		case err := <-errors:
			t.Errorf("Concurrent generation failed: %v", err)
		case secret := <-done:
			if secrets[secret] {
				t.Errorf("Duplicate secret in concurrent generation: %s", secret)
			}
			secrets[secret] = true
		}
	}
}

// TestGenerateEdgeCases tests edge cases
func TestGenerateEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		opts *GenerateSecretOptions
	}{
		// NOTE: Minimum length test removed because crypto.GenerateHex enforces MinPasswordLen/2 = 7 bytes
		{
			name: "very large length",
			opts: &GenerateSecretOptions{
				Length: 10240, // 10KB
				Format: "hex",
			},
		},
		{
			name: "case sensitivity in format",
			opts: &GenerateSecretOptions{
				Length: 16,
				Format: "HEX", // Should fail
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Generate(tt.opts)

			// Case sensitivity test - Updated: unsupported formats default to hex
			if tt.opts.Format == "HEX" {
				if err != nil {
					t.Errorf("Unexpected error for uppercase format (should default to hex): %v", err)
				}
				// Verify it still generated a result
				if result == "" {
					t.Error("Expected hex result for uppercase format")
				}
				return
			}

			if err != nil {
				t.Errorf("Generate() error = %v", err)
				return
			}

			// Verify result is not empty
			if result == "" {
				t.Error("Generated empty secret")
			}
		})
	}
}

// TestErrorMessages tests that error messages are informative
func TestErrorMessages(t *testing.T) {
	tests := []struct {
		name             string
		opts             *GenerateSecretOptions
		wantErrSubstring string
	}{
		{
			name: "negative length error",
			opts: &GenerateSecretOptions{
				Length: -5,
				Format: "hex",
			},
			wantErrSubstring: "length must be greater than 0",
		},
		{
			name: "invalid format error",
			opts: &GenerateSecretOptions{
				Length: 16,
				Format: "octal",
			},
			wantErrSubstring: "unsupported format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Generate(tt.opts)
			if err == nil {
				t.Fatal("Expected error but got none")
			}

			if !strings.Contains(err.Error(), tt.wantErrSubstring) {
				t.Errorf("Error message %q doesn't contain %q", err.Error(), tt.wantErrSubstring)
			}
		})
	}
}

// TestBase64Padding tests that base64 output is properly padded
func TestBase64Padding(t *testing.T) {
	// Test various lengths that might result in different padding
	lengths := []int{1, 2, 3, 4, 5, 10, 15, 16, 20, 31, 32, 33}

	for _, length := range lengths {
		t.Run(string(rune(length)), func(t *testing.T) {
			result, err := GenerateBase64(length)
			if err != nil {
				t.Fatalf("GenerateBase64() error = %v", err)
			}

			// Base64 should always be valid
			decoded, err := base64.StdEncoding.DecodeString(result)
			if err != nil {
				t.Errorf("Invalid base64 for length %d: %v", length, err)
			}

			if len(decoded) != length {
				t.Errorf("Decoded length = %d, want %d", len(decoded), length)
			}

			// Check proper padding
			if len(result)%4 != 0 {
				t.Errorf("Base64 result not properly padded, length = %d", len(result))
			}
		})
	}
}

// Benchmark tests
func BenchmarkGenerateHex16(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateHex(16)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateHex32(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateHex(32)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateBase64_32(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateBase64(32)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Note: Random source failure testing would require dependency injection
// of the random source, which is not currently implemented.
// This is documented for completeness.
func TestRandomSourceFailureDocumentation(t *testing.T) {
	// In a production system, you might want to make the random source
	// configurable for testing. The current implementation directly uses
	// crypto/rand.Read which is difficult to mock.
	t.Skip("Cannot test random source failure without dependency injection")
}
