package shared

import (
	"encoding/base64"
	"encoding/hex"
	"math"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzCryptographicInputValidation tests cryptographic input validation for security issues
func FuzzCryptographicInputValidation(f *testing.F) {
	// Cryptographic attack vectors and edge cases
	seeds := []string{
		// Weak encryption keys
		"password123",
		"admin",
		"1234567890123456",                 // predictable 16-byte key
		"00000000000000000000000000000000", // all zeros
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // all ones
		strings.Repeat("A", 16),            // repeated characters

		// Invalid key lengths
		"short",                   // too short
		strings.Repeat("x", 1000), // too long
		"",                        // empty key

		// Invalid base64 encoded keys
		"InvalidBase64!@#$",
		"SGVsbG8gV29ybGQ", // "Hello World" - not cryptographic
		"==InvalidPadding",
		"VGhpcyBpcyBub3QgYSBzZWN1cmUga2V5", // "This is not a secure key"

		// Hex-encoded weak keys
		"deadbeefdeadbeefdeadbeefdeadbeef",
		"1234567890abcdef1234567890abcdef",
		"0000000000000000000000000000000000000000000000000000000000000000",

		// Common weak passphrases
		"password",
		"qwerty",
		"123456789",
		"letmein",
		"welcome",
		"monkey",
		"dragon",

		// Dictionary words
		"sunshine",
		"butterfly",
		"computer",
		"internet",
		"security",

		// Patterns that might bypass validation
		"PASSWORD123",  // case variation
		"p@ssw0rd",     // character substitution
		"password!",    // special character addition
		"pass word",    // spaces
		"password\x00", // null termination

		// Cryptographic constants (should be rejected)
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // SHA256 of empty string
		"da39a3ee5e6b4b0d3255bfef95601890afd80709",                         // SHA1 of empty string
		"d41d8cd98f00b204e9800998ecf8427e",                                 // MD5 of empty string

		// Initialization vectors (should be random)
		"1234567890123456", // predictable IV
		"0000000000000000", // zero IV
		"AAAAAAAAAAAAAAAA", // repeated IV

		//  values (should be unique)
		"",
		"sea",
		"12345678",
		strings.Repeat("0", 32), // zero

		// Certificate/key-like structures (PEM format)
		"-----BEGIN PRIVATE KEY-----\nInvalidKeyData\n-----END PRIVATE KEY-----",
		"-----BEGIN CERTIFICATE-----\nInvalidCertData\n-----END CERTIFICATE-----",
		"-----BEGIN RSA PRIVATE KEY-----\nMaliciousData\n-----END RSA PRIVATE KEY-----",

		// JWT tokens (potentially malicious)
		"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJhdHRhY2tlciJ9.", // None algorithm
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.InvalidPayload",           // Invalid payload

		// API keys that might be leaked
		"sk_test_1234567890abcdef",
		"pk_live_abcdef1234567890",
		"AKIA1234567890ABCDEF", // AWS access key format
		"ghp_1234567890abcdef", // GitHub personal access token format

		// Hash values (various formats)
		"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", // SHA256
		"adc83b19e793491b1c6ea0fd8b46cd9f32e592fc",                         // SHA1
		"098f6bcd4621d373cade4e832627b4f6",                                 // MD5

		// Unicode and encoding attacks
		"pаssword",       // Cyrillic 'а' instead of 'a'
		"раssword",       // Mixed Cyrillic/Latin
		"password\u200b", // Zero-width space
		"password\ufeff", // BOM
		"password\u202e", // Right-to-left override

		// Buffer overflow attempts
		strings.Repeat("A", 10000),
		strings.Repeat("🔐", 1000), // Unicode emoji

		// Format string attacks
		"%s%s%s%s",
		"%n%n%n%n",
		"%x%x%x%x",

		// SQL injection in crypto fields
		"'; DROP TABLE keys; --",
		"' OR '1'='1",

		// Command injection
		"key; rm -rf /",
		"key$(whoami)",
		"key`cat /etc/passwd`",

		// Valid cryptographic inputs (should pass)
		"a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456", // 64-char hex
		"SGVsbG8gV29ybGQgdGhpcyBpcyBhIHZhbGlkIDMyIGJ5dGUga2V5ISEhISEhISE=", // Valid base64
		base64.StdEncoding.EncodeToString([]byte(strings.Repeat("securekey", 3))),
		"",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, cryptoInput string) {
		// Test cryptographic input validation
		isValidCrypto := validateCryptographicInput(cryptoInput)
		_ = isValidCrypto

		// Test key strength validation
		if looksLikeCryptoKey(cryptoInput) {
			strength := assessKeyStrength(cryptoInput)
			if strength < MinimumKeyStrength && isValidCrypto {
				t.Errorf("Weak cryptographic key accepted: %s (strength: %d)", cryptoInput, strength)
			}
		}

		// Test entropy validation
		if len(cryptoInput) > 0 {
			entropy := calculateEntropy(cryptoInput)
			if entropy < MinimumEntropy && containsCryptographicPatterns(cryptoInput) {
				t.Errorf("Low entropy cryptographic input: %s (entropy: %.2f)", cryptoInput, entropy)
			}
		}

		// Test encoding validation
		if appearsBase64(cryptoInput) {
			decoded, err := base64.StdEncoding.DecodeString(cryptoInput)
			if err == nil {
				if isWeakCryptographicData(decoded) {
					t.Errorf("Decoded cryptographic data is weak: %s", cryptoInput)
				}
			}
		}

		if appearsHex(cryptoInput) {
			decoded, err := hex.DecodeString(cryptoInput)
			if err == nil {
				if isWeakCryptographicData(decoded) {
					t.Errorf("Hex-decoded cryptographic data is weak: %s", cryptoInput)
				}
			}
		}

		// Test for common cryptographic vulnerabilities
		if isKnownWeakCryptoPattern(cryptoInput) {
			sanitized := sanitizeCryptographicInput(cryptoInput)
			if containsVulnerablePatterns(sanitized) {
				t.Errorf("Sanitization failed to remove vulnerable crypto pattern: %s -> %s", cryptoInput, sanitized)
			}
		}

		// Test for data leakage patterns
		if containsSensitiveCryptoData(cryptoInput) {
			masked := maskSensitiveCryptoData(cryptoInput)
			if stillContainsSensitiveData(masked) {
				t.Errorf("Failed to mask sensitive crypto data: %s -> %s", cryptoInput, masked)
			}
		}
	})
}

// FuzzHashValidation tests hash input validation and security
func FuzzHashValidation(f *testing.F) {
	seeds := []string{
		// Valid hash formats
		"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", // SHA256
		"adc83b19e793491b1c6ea0fd8b46cd9f32e592fc",                         // SHA1
		"098f6bcd4621d373cade4e832627b4f6",                                 // MD5
		"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", // SHA512

		// Invalid hash formats
		"invalid_hash",
		"12345",                            // too short
		"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", // invalid hex characters
		"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d",   // one char short
		"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d88", // one char long

		// Hash collision attempts
		"320fb04e8db24ac65ba49e6c8af3f99055da1d3fb60b9d4568b62ff6e8c1e6c2", // potential collision
		"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", // weak pattern

		// Rainbow table hashes (common passwords)
		"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", // "hello"
		"ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f", // "secret"
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // empty string
		"2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", // "foo"

		// Case variations
		"5E884898DA28047151D0E56F8DC6292773603D0D6AABBDD62A11EF721D1542D8", // uppercase
		"5e884898DA28047151d0e56f8DC6292773603d0d6AABBDD62a11ef721D1542d8", // mixed case

		// With prefixes/suffixes
		"sha256:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
		"0x5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
		"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8\n",

		// Malformed but potentially dangerous
		"'; DROP TABLE hashes; --",
		"<script>alert('xss')</script>",
		"$(whoami)",

		// Binary data as hex
		strings.Repeat("00", 32), // all zeros
		strings.Repeat("FF", 32), // all ones
		strings.Repeat("AA", 32), // repeated pattern

		// Unicode attempts
		"5е884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", // Cyrillic 'е'

		// Empty and whitespace
		"",
		"   ",
		"\t\n\r",

		// Very long inputs
		strings.Repeat("a", 1000),
		strings.Repeat("1234567890abcdef", 100),
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, hashInput string) {
		// Test hash format validation
		isValidHash := validateHashFormat(hashInput)
		hashType := detectHashType(hashInput)

		// Test hash normalization
		normalized := normalizeHash(hashInput)
		if isValidHash && !isNormalizedSafe(normalized) {
			t.Errorf("Hash normalization made valid hash unsafe: %s -> %s", hashInput, normalized)
		}

		// Test for known weak hashes
		if isKnownWeakHash(hashInput) && isValidHash {
			t.Errorf("Known weak hash accepted as valid: %s", hashInput)
		}

		// Test hash length validation
		if hashType != "unknown" {
			expectedLength := getExpectedHashLength(hashType)
			if len(normalized) != expectedLength && isValidHash {
				t.Errorf("Hash length mismatch for type %s: expected %d, got %d", hashType, expectedLength, len(normalized))
			}
		}

		// Test for hash collision vulnerabilities
		if isCollisionVulnerable(hashInput) {
			secureAlternative := suggestSecureHashAlgorithm(hashType)
			if secureAlternative == hashType {
				t.Errorf("Collision-vulnerable hash type not upgraded: %s", hashType)
			}
		}
	})
}

// FuzzCertificateValidation tests certificate and key validation
func FuzzCertificateValidation(f *testing.F) {
	seeds := []string{
		// Valid PEM structures (headers/footers)
		"-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END CERTIFICATE-----",
		"-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VJTUt9Us8cKB\n-----END PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7S8+xPiHvfQ+8UjQdmKrKa7VXGhCrMIGo0+OxNtLfD0x\n-----END RSA PRIVATE KEY-----",
		"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7S8+xPiHvfQ+\n-----END PUBLIC KEY-----",

		// Invalid PEM structures
		"-----BEGIN CERTIFICATE-----\nInvalidBase64Data!@#$\n-----END CERTIFICATE-----",
		"-----BEGIN PRIVATE KEY-----\n\n-----END PRIVATE KEY-----",                     // empty
		"-----BEGIN CERTIFICATE-----\nTWFsaWNpb3VzRGF0YQ==\n-----END CERTIFICATE-----", // "MaliciousData"

		// Mismatched headers/footers
		"-----BEGIN CERTIFICATE-----\ndata\n-----END PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----\ndata\n-----END CERTIFICATE-----",

		// Missing headers/footers
		"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA",                              // raw base64
		"-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA", // missing footer
		"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END CERTIFICATE-----",   // missing header

		// Weak key lengths (simulated)
		"-----BEGIN RSA PRIVATE KEY-----\nMIGWAgEAAiEAwf8VpPPXlVpJSN3LzpYvC2nglWn7N3kj\n-----END RSA PRIVATE KEY-----", // Short key

		// Malicious content injection
		"-----BEGIN CERTIFICATE-----\n'; DROP TABLE certificates; --\n-----END CERTIFICATE-----",
		"-----BEGIN PRIVATE KEY-----\n<script>alert('xss')</script>\n-----END PRIVATE KEY-----",
		"-----BEGIN CERTIFICATE-----\n$(whoami)\n-----END CERTIFICATE-----",

		// Binary data attempts
		"-----BEGIN CERTIFICATE-----\n\x00\x01\x02\x03\n-----END CERTIFICATE-----",
		"-----BEGIN PRIVATE KEY-----\n\xff\xfe\xfd\xfc\n-----END PRIVATE KEY-----",

		// Very long certificates (DoS)
		"-----BEGIN CERTIFICATE-----\n" + strings.Repeat("A", 100000) + "\n-----END CERTIFICATE-----",

		// Multiple certificates
		"-----BEGIN CERTIFICATE-----\ndata1\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\ndata2\n-----END CERTIFICATE-----",

		// Invalid base64 in PEM
		"-----BEGIN CERTIFICATE-----\nThis is not base64!\n-----END CERTIFICATE-----",
		"-----BEGIN PRIVATE KEY-----\n!@#$%^&*()\n-----END PRIVATE KEY-----",

		// Unicode in PEM
		"-----BEGIN CERTIFICATE-----\ncаfé\n-----END CERTIFICATE-----", // Cyrillic 'а'
		"-----BEGIN PRIVATE KEY-----\n🔐🔑\n-----END PRIVATE KEY-----",   // Emoji

		// Null bytes
		"-----BEGIN CERTIFICATE-----\ndata\x00injection\n-----END CERTIFICATE-----",

		// Valid inputs (should pass)
		"", // empty (might be valid in some contexts)
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, certInput string) {
		// Test certificate format validation
		isValidCert := validateCertificateFormat(certInput)
		pemType := detectPEMType(certInput)

		// Test PEM parsing security
		if containsPEMStructure(certInput) {
			pemBlocks := extractPEMBlocks(certInput)
			for _, block := range pemBlocks {
				if containsMaliciousContent(block) {
					t.Errorf("PEM block contains malicious content: %s", block)
				}
			}
		}

		// Test certificate chain validation
		if isValidCert {
			chain := parseCertificateChain(certInput)
			if !isValidCertificateChain(chain) {
				t.Errorf("Invalid certificate chain: %s", certInput)
			}
		}

		// Test key strength validation
		if isPrivateKey(pemType) {
			keyStrength := assessPrivateKeyStrength(certInput)
			if keyStrength < MinimumKeyStrength {
				t.Errorf("Weak private key: %s (strength: %d)", certInput, keyStrength)
			}
		}

		// Test for deprecated algorithms
		if containsDeprecatedAlgorithm(certInput) {
			t.Errorf("Certificate uses deprecated algorithm: %s", certInput)
		}
	})
}

// Helper functions (these should be implemented in appropriate crypto packages)

const (
	MinimumKeyStrength = 2048 // bits
	MinimumEntropy     = 3.0  // bits per character
)

func validateCryptographicInput(input string) bool {
	// TODO: Implement comprehensive crypto input validation
	return len(input) > 0 && len(input) < 10000 && utf8.ValidString(input)
}

func looksLikeCryptoKey(input string) bool {
	// Simple heuristic - improve in actual implementation
	return len(input) >= 16 && (appearsBase64(input) || appearsHex(input) || containsPEMStructure(input))
}

func assessKeyStrength(input string) int {
	// TODO: Implement actual key strength assessment
	if len(input) < 16 {
		return 512
	}
	if len(input) < 32 {
		return 1024
	}
	return 2048
}

func calculateEntropy(input string) float64 {
	// TODO: Implement Shannon entropy calculation
	if len(input) == 0 {
		return 0
	}
	charCounts := make(map[rune]int)
	for _, r := range input {
		charCounts[r]++
	}

	entropy := 0.0
	length := float64(len(input))
	for _, count := range charCounts {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * (math.Log2(p))
		}
	}
	return entropy
}

func containsCryptographicPatterns(input string) bool {
	return strings.Contains(input, "key") || strings.Contains(input, "password") ||
		strings.Contains(input, "secret") || appearsBase64(input) || appearsHex(input)
}

func appearsBase64(input string) bool {
	if len(input) == 0 {
		return false
	}
	// Check if it looks like base64 (ends with = padding, contains base64 chars)
	matched, _ := regexp.MatchString(`^[A-Za-z0-9+/]*={0,2}$`, input)
	return matched && len(input)%4 == 0
}

func appearsHex(input string) bool {
	if len(input) == 0 {
		return false
	}
	matched, _ := regexp.MatchString(`^[0-9a-fA-F]+$`, input)
	return matched && len(input)%2 == 0
}

func isWeakCryptographicData(data []byte) bool {
	// TODO: Implement weak crypto data detection
	if len(data) == 0 {
		return true
	}
	// Check for all zeros, all ones, repeated patterns
	first := data[0]
	allSame := true
	for _, b := range data {
		if b != first {
			allSame = false
			break
		}
	}
	return allSame
}

func isKnownWeakCryptoPattern(input string) bool {
	weakPatterns := []string{
		"password", "123456", "admin", "qwerty", "letmein",
		strings.Repeat("0", 32), strings.Repeat("1", 32),
		"deadbeef", "cafebabe",
	}
	lower := strings.ToLower(input)
	for _, pattern := range weakPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func sanitizeCryptographicInput(input string) string {
	// TODO: Implement crypto input sanitization
	return strings.TrimSpace(input)
}

func containsVulnerablePatterns(input string) bool {
	return isKnownWeakCryptoPattern(input)
}

func containsSensitiveCryptoData(input string) bool {
	patterns := []string{"private", "secret", "password", "key", "token"}
	lower := strings.ToLower(input)
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func maskSensitiveCryptoData(input string) string {
	// TODO: Implement sensitive data masking
	if len(input) > 8 {
		return input[:4] + "****" + input[len(input)-4:]
	}
	return "****"
}

func stillContainsSensitiveData(masked string) bool {
	return containsSensitiveCryptoData(masked) && !strings.Contains(masked, "*")
}

func validateHashFormat(input string) bool {
	// TODO: Implement hash format validation
	return appearsHex(input) && (len(input) == 32 || len(input) == 40 || len(input) == 64 || len(input) == 128)
}

func detectHashType(input string) string {
	switch len(input) {
	case 32:
		return "md5"
	case 40:
		return "sha1"
	case 64:
		return "sha256"
	case 128:
		return "sha512"
	default:
		return "unknown"
	}
}

func normalizeHash(input string) string {
	return strings.ToLower(strings.TrimSpace(input))
}

func isNormalizedSafe(input string) bool {
	return validateHashFormat(input)
}

func isKnownWeakHash(input string) bool {
	knownWeak := []string{
		"d41d8cd98f00b204e9800998ecf8427e",                                 // MD5 of empty string
		"da39a3ee5e6b4b0d3255bfef95601890afd80709",                         // SHA1 of empty string
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // SHA256 of empty string
	}
	normalized := normalizeHash(input)
	for _, weak := range knownWeak {
		if normalized == weak {
			return true
		}
	}
	return false
}

func getExpectedHashLength(hashType string) int {
	switch hashType {
	case "md5":
		return 32
	case "sha1":
		return 40
	case "sha256":
		return 64
	case "sha512":
		return 128
	default:
		return 0
	}
}

func isCollisionVulnerable(input string) bool {
	hashType := detectHashType(input)
	// MD5 and SHA1 are collision vulnerable
	return hashType == "md5" || hashType == "sha1"
}

func suggestSecureHashAlgorithm(currentType string) string {
	if currentType == "md5" || currentType == "sha1" {
		return "sha256"
	}
	return currentType
}

func validateCertificateFormat(input string) bool {
	return containsPEMStructure(input)
}

func detectPEMType(input string) string {
	if strings.Contains(input, "BEGIN CERTIFICATE") {
		return "certificate"
	}
	if strings.Contains(input, "BEGIN PRIVATE KEY") {
		return "private_key"
	}
	if strings.Contains(input, "BEGIN PUBLIC KEY") {
		return "public_key"
	}
	if strings.Contains(input, "BEGIN RSA PRIVATE KEY") {
		return "rsa_private_key"
	}
	return "unknown"
}

func containsPEMStructure(input string) bool {
	return strings.Contains(input, "-----BEGIN") && strings.Contains(input, "-----END")
}

func extractPEMBlocks(input string) []string {
	// TODO: Implement PEM block extraction
	return []string{input}
}

func containsMaliciousContent(block string) bool {
	dangerous := []string{"DROP TABLE", "<script>", "$(", ";", "--"}
	for _, pattern := range dangerous {
		if strings.Contains(block, pattern) {
			return true
		}
	}
	return false
}

func parseCertificateChain(input string) []string {
	// TODO: Implement certificate chain parsing
	return []string{input}
}

func isValidCertificateChain(chain []string) bool {
	// TODO: Implement certificate chain validation
	return len(chain) > 0
}

func isPrivateKey(pemType string) bool {
	return strings.Contains(pemType, "private")
}

func assessPrivateKeyStrength(input string) int {
	// TODO: Implement private key strength assessment
	if len(input) < 1000 {
		return 1024
	}
	return 2048
}

func containsDeprecatedAlgorithm(input string) bool {
	deprecated := []string{"md5", "sha1", "des", "3des", "rc4"}
	lower := strings.ToLower(input)
	for _, alg := range deprecated {
		if strings.Contains(lower, alg) {
			return true
		}
	}
	return false
}
