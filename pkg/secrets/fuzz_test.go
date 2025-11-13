package secrets

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// FuzzGenerate tests the Generate function with fuzzy inputs
func FuzzGenerate(f *testing.F) {
	// Add seed corpus
	seeds := []struct {
		length int
		format string
	}{
		{16, "hex"},
		{32, "base64"},
		{0, "hex"},
		{-1, "base64"},
		{1024, "hex"},
		{1, "base64"},
		{100, "HEX"},
		{50, "BASE64"},
		{10, "binary"},
		{20, ""},
		{2147483647, "hex"},  // Max int32
		{-2147483648, "hex"}, // Min int32
	}

	for _, seed := range seeds {
		f.Add(seed.length, seed.format)
	}

	f.Fuzz(func(t *testing.T, length int, format string) {
		opts := &GenerateSecretOptions{
			Length: length,
			Format: format,
		}

		result, err := Generate(opts)

		// Validate error cases
		if length <= 0 {
			if err == nil {
				t.Error("Expected error for non-positive length")
			}
			return
		}

		if format != "hex" && format != "base64" {
			if err == nil {
				t.Error("Expected error for unsupported format")
			}
			return
		}

		// For valid inputs, should not error
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
			return
		}

		// Validate output format
		switch format {
		case "hex":
			// Hex length should be 2x input length
			expectedLen := length * 2
			if len(result) != expectedLen {
				t.Errorf("Hex length = %d, want %d", len(result), expectedLen)
			}

			// Should be valid hex
			decoded, err := hex.DecodeString(result)
			if err != nil {
				t.Errorf("Invalid hex: %v", err)
			}
			if len(decoded) != length {
				t.Errorf("Decoded hex length = %d, want %d", len(decoded), length)
			}

		case "base64":
			// Should be valid base64
			decoded, err := base64.StdEncoding.DecodeString(result)
			if err != nil {
				t.Errorf("Invalid base64: %v", err)
			}
			if len(decoded) != length {
				t.Errorf("Decoded base64 length = %d, want %d", len(decoded), length)
			}
		}

		// Result should not be empty for valid inputs
		if result == "" {
			t.Error("Empty result for valid input")
		}
	})
}

// FuzzGenerateHex tests GenerateHex with fuzzy lengths
func FuzzGenerateHex(f *testing.F) {
	// Add seed corpus
	seeds := []int{
		0, 1, 16, 32, 64, 128, 256, 512, 1024,
		-1, -100, -2147483648,
		2147483647,
		1000000,
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, length int) {
		result, err := GenerateHex(length)

		if length <= 0 {
			if err == nil {
				t.Error("Expected error for non-positive length")
			}
			return
		}

		// Very large lengths might cause memory issues
		if length > 1<<20 { // 1MB
			// Skip very large allocations in fuzzing
			t.Skip("Skipping very large allocation")
		}

		if err != nil {
			t.Errorf("Unexpected error for length %d: %v", length, err)
			return
		}

		// Verify hex format
		expectedLen := length * 2
		if len(result) != expectedLen {
			t.Errorf("Result length = %d, want %d", len(result), expectedLen)
		}

		// Should decode properly
		decoded, err := hex.DecodeString(result)
		if err != nil {
			t.Errorf("Invalid hex: %v", err)
		}
		if len(decoded) != length {
			t.Errorf("Decoded length = %d, want %d", len(decoded), length)
		}

		// All characters should be hex digits
		for _, c := range result {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("Invalid hex character: %c", c)
			}
		}
	})
}

// FuzzGenerateBase64 tests GenerateBase64 with fuzzy lengths
func FuzzGenerateBase64(f *testing.F) {
	// Add seed corpus
	seeds := []int{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		15, 16, 17,
		31, 32, 33,
		63, 64, 65,
		100, 256, 1024,
		-1, -10,
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, length int) {
		result, err := GenerateBase64(length)

		if length <= 0 {
			if err == nil {
				t.Error("Expected error for non-positive length")
			}
			return
		}

		// Very large lengths might cause memory issues
		if length > 1<<20 { // 1MB
			// Skip very large allocations in fuzzing
			t.Skip("Skipping very large allocation")
		}

		if err != nil {
			t.Errorf("Unexpected error for length %d: %v", length, err)
			return
		}

		// Should be valid base64
		decoded, err := base64.StdEncoding.DecodeString(result)
		if err != nil {
			t.Errorf("Invalid base64: %v", err)
			return
		}

		if len(decoded) != length {
			t.Errorf("Decoded length = %d, want %d", len(decoded), length)
		}

		// Base64 length should be correctly padded
		if len(result)%4 != 0 {
			t.Errorf("Base64 not properly padded, length = %d", len(result))
		}

		// Verify character set
		for _, c := range result {
			isValid := (c >= 'A' && c <= 'Z') ||
				(c >= 'a' && c <= 'z') ||
				(c >= '0' && c <= '9') ||
				c == '+' || c == '/' || c == '='
			if !isValid {
				t.Errorf("Invalid base64 character: %c", c)
			}
		}
	})
}

// FuzzGenerateOptions tests various option combinations
func FuzzGenerateOptions(f *testing.F) {
	// Add seed corpus with various formats
	formats := []string{
		"hex", "base64", "HEX", "BASE64", "Hex", "Base64",
		"binary", "octal", "decimal", "", " ", "\n", "\x00",
		"hex ", " hex", " hex ",
		"hexadecimal", "base-64", "base_64",
	}

	for _, format := range formats {
		for _, length := range []int{0, 1, 16, 32} {
			f.Add(length, format)
		}
	}

	f.Fuzz(func(t *testing.T, length int, format string) {
		opts := &GenerateSecretOptions{
			Length: length,
			Format: format,
		}

		result, err := Generate(opts)

		// Check expected errors
		hasError := err != nil
		shouldHaveError := length <= 0 || (format != "hex" && format != "base64")

		if hasError != shouldHaveError {
			t.Errorf("Error mismatch: got error=%v, expected error=%v for length=%d, format=%q",
				hasError, shouldHaveError, length, format)
		}

		// If we expect success, validate the result
		if !shouldHaveError && err == nil {
			if result == "" {
				t.Error("Empty result for valid input")
			}

			// Additional format validation
			switch format {
			case "hex":
				if _, err := hex.DecodeString(result); err != nil {
					t.Errorf("Invalid hex output: %v", err)
				}
			case "base64":
				if _, err := base64.StdEncoding.DecodeString(result); err != nil {
					t.Errorf("Invalid base64 output: %v", err)
				}
			}
		}
	})
}

// FuzzSecretUniqueness tests that secrets remain unique under various conditions
func FuzzSecretUniqueness(f *testing.F) {
	// Seed with different lengths
	seeds := []int{1, 2, 4, 8, 16, 32, 64}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, length int) {
		if length <= 0 || length > 1024 {
			t.Skip("Skipping invalid or very large length")
		}

		// Skip very small lengths where collisions are likely
		if length < 4 {
			t.Skip("Skipping small length where collisions are expected")
		}

		// Generate multiple secrets with the same parameters
		secrets := make(map[string]bool)
		iterations := 10

		for i := 0; i < iterations; i++ {
			secret, err := GenerateHex(length)
			if err != nil {
				t.Fatalf("Failed to generate secret: %v", err)
			}

			if secrets[secret] {
				// For small lengths, collisions might happen
				if length >= 8 {
					t.Errorf("Unexpected duplicate secret for length %d", length)
				}
			}
			secrets[secret] = true
		}

		// For reasonable lengths, we expect all unique
		if length >= 8 && len(secrets) != iterations {
			t.Errorf("Expected %d unique secrets, got %d", iterations, len(secrets))
		}
	})
}

// FuzzDefaultOptions tests that defaults handle various modifications
func FuzzDefaultOptions(f *testing.F) {
	// Seed with field modifications
	seeds := []struct {
		lengthDelta int
		format      string
	}{
		{0, "hex"},
		{-32, "hex"},
		{100, "base64"},
		{-1000, "invalid"},
	}

	for _, seed := range seeds {
		f.Add(seed.lengthDelta, seed.format)
	}

	f.Fuzz(func(t *testing.T, lengthDelta int, format string) {
		opts := DefaultOptions()

		// Modify the default options
		opts.Length += lengthDelta
		if format != "" {
			opts.Format = format
		}

		result, err := Generate(opts)

		// Validate based on modified options
		if opts.Length <= 0 {
			if err == nil {
				t.Error("Expected error for non-positive length")
			}
			return
		}

		if opts.Format != "hex" && opts.Format != "base64" {
			if err == nil {
				t.Error("Expected error for invalid format")
			}
			return
		}

		// Should succeed for valid options
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if result == "" {
			t.Error("Empty result for valid options")
		}
	})
}
