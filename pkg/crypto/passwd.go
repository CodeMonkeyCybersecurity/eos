// pkg/crypto/passwd.go

package crypto

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"unicode"
)

// Constants and charsets for password generation
const MinPasswordLen = 14

// These should come from your shared package or be defined here directly
var (
	lowerChars  = "abcdefghijklmnopqrstuvwxyz"
	upperChars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitChars  = "0123456789"
	symbolChars = "!@#%^&*()-_=+[]{}|;:,.<>?/" // Removed $ to prevent shell injection
	allChars    = lowerChars + upperChars + digitChars + symbolChars

	// Alphanumeric-only characters for maximum compatibility
	// Safe for: URLs, databases, APIs, config files, shells, legacy systems
	// No special chars = no escaping needed anywhere
	alphanumericChars = lowerChars + upperChars + digitChars
)

// GeneratePassword creates a strong random password with at least 1 of each char class.
func GeneratePassword(length int) (string, error) {
	if length < MinPasswordLen {
		return "", errors.New("password too short: min length " + fmt.Sprintf("%d", MinPasswordLen))
	}
	pw := make([]byte, 0, length)
	groups := []string{lowerChars, upperChars, digitChars, symbolChars}

	// Guarantee at least one of each
	for _, group := range groups {
		c, err := randomChar(group)
		if err != nil {
			return "", err
		}
		pw = append(pw, c)
	}
	// Fill rest
	for i := len(groups); i < length; i++ {
		c, err := randomChar(allChars)
		if err != nil {
			return "", err
		}
		pw = append(pw, c)
	}
	// Shuffle
	if err := shuffle(pw); err != nil {
		return "", err
	}
	return string(pw), nil
}

// GenerateURLSafePassword generates a cryptographically secure password
// using ONLY alphanumeric characters [a-zA-Z0-9].
//
// Why alphanumeric-only is BETTER than special characters for service credentials:
// 1. No escaping needed in ANY context (URLs, shells, SQL, YAML, TOML, JSON)
// 2. Maximum compatibility (works with legacy systems that reject special chars)
// 3. Length compensates for character set reduction - security is equivalent
// 4. Eliminates entire classes of bugs related to special character handling
//
// Character set: [a-zA-Z0-9] (62 possible characters)
// Entropy: log2(62^32) ≈ 190 bits for 32-character password (exceeds AES-128)
//
// Use this for:
//   - Database passwords in connection strings (DATABASE_URL)
//   - API keys and tokens
//   - Service-to-service authentication
//   - Any password that appears in config files, URLs, or shell commands
//   - Passwords passed through multiple systems/parsers
//
// DO NOT use for human user passwords - use GeneratePassword() instead
// (human passwords benefit from special characters for complexity requirements)
func GenerateURLSafePassword(length int) (string, error) {
	if length < MinPasswordLen {
		return "", errors.New("password too short: min length " + fmt.Sprintf("%d", MinPasswordLen))
	}

	password := make([]byte, length)
	for i := 0; i < length; i++ {
		c, err := randomChar(alphanumericChars)
		if err != nil {
			return "", fmt.Errorf("failed to generate random character: %w", err)
		}
		password[i] = c
	}

	return string(password), nil
}

// ValidateStrongPassword checks that the password meets security policy.
func ValidateStrongPassword(_ctx context.Context, input string) error {
	if len(input) < MinPasswordLen {
		return errors.New("password too short")
	}
	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, r := range input {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r), unicode.IsSymbol(r):
			hasSymbol = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit || !hasSymbol {
		return errors.New("password missing required character class")
	}
	return nil
}

// randomChar selects a random character from charset using crypto/rand.
func randomChar(charset string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
	if err != nil {
		return 0, err
	}
	return charset[n.Int64()], nil
}

// shuffle randomizes a byte slice in place.
func shuffle(b []byte) error {
	for i := len(b) - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		j := int(jBig.Int64())
		b[i], b[j] = b[j], b[i]
	}
	return nil
}

// ReadPassword reads a password from a bufio.Reader (e.g., for tests or non-interactive use).
func ReadPassword(reader *bufio.Reader) (string, error) {
	pw, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(pw), nil
}

// GenerateAPIKey generates a secure alphanumeric API key of specified length.
// Uses only [a-zA-Z0-9] for maximum compatibility (no base64 padding issues).
//
// Character set: [a-zA-Z0-9] (62 possible characters)
// Default length: 32 characters = log2(62^32) ≈ 190 bits entropy
//
// Use this for:
//   - API authentication keys
//   - Service access tokens
//   - Client credentials
//   - Any key stored in headers, URLs, or config files
func GenerateAPIKey(length int) (string, error) {
	if length < MinPasswordLen {
		return "", errors.New("API key too short: min length " + fmt.Sprintf("%d", MinPasswordLen))
	}

	return GenerateURLSafePassword(length)
}

// GenerateToken generates a secure alphanumeric token of specified length.
// Identical to GenerateAPIKey but semantically distinct (for tokens vs keys).
//
// Character set: [a-zA-Z0-9] (62 possible characters)
// Default length: 32 characters = log2(62^32) ≈ 190 bits entropy
//
// Use this for:
//   - Session tokens
//   - CSRF tokens
//   - One-time use tokens
//   - Temporary access credentials
func GenerateToken(length int) (string, error) {
	if length < MinPasswordLen {
		return "", errors.New("token too short: min length " + fmt.Sprintf("%d", MinPasswordLen))
	}

	return GenerateURLSafePassword(length)
}

// GenerateJWTSecret generates a secure alphanumeric JWT signing secret.
//
// Character set: [a-zA-Z0-9] (62 possible characters)
// Default length: 32 characters = log2(62^32) ≈ 190 bits entropy
//
// Use this for:
//   - JWT HMAC signing keys (HS256, HS384, HS512)
//   - Symmetric encryption keys
//   - Cookie signing secrets
//   - Session encryption keys
//
// Security note: For production JWT signing, consider asymmetric keys (RS256, ES256)
// instead of symmetric HMAC. This function is suitable for development or symmetric scenarios.
func GenerateJWTSecret(length int) (string, error) {
	if length < MinPasswordLen {
		return "", errors.New("JWT secret too short: min length " + fmt.Sprintf("%d", MinPasswordLen))
	}

	// For JWT secrets, use longer default for extra security margin
	if length < 32 {
		length = 32
	}

	return GenerateURLSafePassword(length)
}

// GenerateHex generates a hex-encoded secret of the specified byte length.
//
// Character set: [0-9a-f] (16 possible characters)
// Output length: byteLength * 2 (hex encoding doubles the length)
// Entropy: log2(256^byteLength) = byteLength * 8 bits
//
// Use this for:
//   - Cryptographic keys in hex format
//   - Hash digests
//   - Binary data representation
//   - Systems requiring hex-only input
//
// Example: GenerateHex(32) → 64 hex characters representing 32 bytes (256 bits)
func GenerateHex(byteLength int) (string, error) {
	if byteLength < MinPasswordLen/2 {
		return "", errors.New("hex secret too short: min byte length " + fmt.Sprintf("%d", MinPasswordLen/2))
	}

	bytes := make([]byte, byteLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Convert to hex string
	hexChars := "0123456789abcdef"
	hex := make([]byte, byteLength*2)
	for i, b := range bytes {
		hex[i*2] = hexChars[b>>4]
		hex[i*2+1] = hexChars[b&0x0f]
	}

	return string(hex), nil
}

// GenerateBase64 generates a base64-encoded secret of the specified byte length.
//
// Character set: [A-Za-z0-9+/] with optional padding (=)
// Output length: ceiling(byteLength * 4/3) (base64 encoding increases by ~33%)
// Entropy: log2(256^byteLength) = byteLength * 8 bits
//
// Use this for:
//   - Legacy systems requiring base64 format
//   - Binary data in JSON/XML
//   - Email-safe encoding (consider base64url variant)
//
// Example: GenerateBase64(32) → 44 base64 characters representing 32 bytes (256 bits)
//
// NOTE: For most use cases, GenerateAPIKey/GenerateToken (alphanumeric-only) is preferred
// because base64 padding (=) and special chars (+/) can cause issues in URLs and shells.
func GenerateBase64(byteLength int) (string, error) {
	if byteLength < MinPasswordLen/2 {
		return "", errors.New("base64 secret too short: min byte length " + fmt.Sprintf("%d", MinPasswordLen/2))
	}

	bytes := make([]byte, byteLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Manual base64 encoding to avoid import
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	// Calculate output length with padding
	outputLen := ((byteLength + 2) / 3) * 4
	output := make([]byte, outputLen)

	var j int
	for i := 0; i < byteLength; i += 3 {
		// Get three bytes (or remaining bytes)
		b1 := bytes[i]
		var b2, b3 byte
		if i+1 < byteLength {
			b2 = bytes[i+1]
		}
		if i+2 < byteLength {
			b3 = bytes[i+2]
		}

		// Encode to 4 base64 characters
		output[j] = base64Chars[b1>>2]
		output[j+1] = base64Chars[((b1&0x03)<<4)|(b2>>4)]

		if i+1 < byteLength {
			output[j+2] = base64Chars[((b2&0x0f)<<2)|(b3>>6)]
		} else {
			output[j+2] = '='
		}

		if i+2 < byteLength {
			output[j+3] = base64Chars[b3&0x3f]
		} else {
			output[j+3] = '='
		}

		j += 4
	}

	return string(output), nil
}
