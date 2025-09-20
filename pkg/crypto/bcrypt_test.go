// pkg/crypto/bcrypt_test.go

package crypto

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"golang.org/x/crypto/bcrypt"
)

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		expectError bool
	}{
		{
			name:        "valid password",
			password:    "test123!",
			expectError: false,
		},
		{
			name:        "empty password",
			password:    "",
			expectError: false, // bcrypt allows empty passwords
		},
		{
			name:        "unicode password",
			password:    "测试密码🔒",
			expectError: false,
		},
		{
			name:        "long password",
			password:    strings.Repeat("a", 72), // bcrypt max
			expectError: false,
		},
		{
			name:        "very long password",
			password:    strings.Repeat("a", 100), // over bcrypt max
			expectError: true,                     // bcrypt errors on passwords over 72 bytes
		},
		{
			name:        "password with special chars",
			password:    "!@#$%^&*()_+-={}[]|\\:;\"'<>?,./~`",
			expectError: false,
		},
		{
			name:        "password with null bytes",
			password:    "test\x00password",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashPassword(tt.password)

			if tt.expectError {
				assert.Error(t, err)
				assert.Empty(t, hash)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, hash)
				assert.True(t, strings.HasPrefix(hash, "$2a$"), "Hash should start with bcrypt prefix")

				// Verify hash can be used to verify password
				err = ComparePassword(hash, tt.password)
				assert.NoError(t, err)
			}
		})
	}
}

func TestHashPasswordWithCost(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		cost        int
		expectError bool
	}{
		{
			name:        "minimum cost",
			password:    "test123",
			cost:        bcrypt.MinCost,
			expectError: false,
		},
		{
			name:        "default cost",
			password:    "test123",
			cost:        bcrypt.DefaultCost,
			expectError: false,
		},
		{
			name:        "high cost",
			password:    "test123",
			cost:        14, // High but reasonable cost for testing
			expectError: false,
		},
		{
			name:        "cost too low",
			password:    "test123",
			cost:        bcrypt.MinCost - 1,
			expectError: true,
		},
		{
			name:        "cost too high",
			password:    "test123",
			cost:        bcrypt.MaxCost + 1,
			expectError: true,
		},
		{
			name:        "zero cost",
			password:    "test123",
			cost:        0,
			expectError: true,
		},
		{
			name:        "negative cost",
			password:    "test123",
			cost:        -1,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashPasswordWithCost(tt.password, tt.cost)

			if tt.expectError {
				assert.Error(t, err)
				assert.Empty(t, hash)
				assert.Contains(t, err.Error(), "invalid cost parameter")
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, hash)

				// Verify the hash uses the expected cost
				actualCost, err := bcrypt.Cost([]byte(hash))
				assert.NoError(t, err)
				assert.Equal(t, tt.cost, actualCost)

				// Verify hash can verify password
				err = ComparePassword(hash, tt.password)
				assert.NoError(t, err)
			}
		})
	}
}

func TestComparePassword(t *testing.T) {
	// Create a known hash first
	password := "test123!"
	hash, err := HashPassword(password)
	require.NoError(t, err)

	tests := []struct {
		name        string
		hash        string
		password    string
		expectError bool
	}{
		{
			name:        "correct password",
			hash:        hash,
			password:    password,
			expectError: false,
		},
		{
			name:        "wrong password",
			hash:        hash,
			password:    "wrong123!",
			expectError: true,
		},
		{
			name:        "empty password",
			hash:        hash,
			password:    "",
			expectError: true,
		},
		{
			name:        "invalid hash",
			hash:        "invalid-hash",
			password:    password,
			expectError: true,
		},
		{
			name:        "empty hash",
			hash:        "",
			password:    password,
			expectError: true,
		},
		{
			name:        "case sensitive password",
			hash:        hash,
			password:    strings.ToUpper(password),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ComparePassword(tt.hash, tt.password)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestComparePasswordBool(t *testing.T) {
	// Create a known hash first
	password := "test123!"
	hash, err := HashPassword(password)
	require.NoError(t, err)

	tests := []struct {
		name     string
		hash     string
		password string
		expected bool
	}{
		{
			name:     "correct password",
			hash:     hash,
			password: password,
			expected: true,
		},
		{
			name:     "wrong password",
			hash:     hash,
			password: "wrong123!",
			expected: false,
		},
		{
			name:     "empty password",
			hash:     hash,
			password: "",
			expected: false,
		},
		{
			name:     "invalid hash",
			hash:     "invalid-hash",
			password: password,
			expected: false,
		},
		{
			name:     "empty hash",
			hash:     "",
			password: password,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComparePasswordBool(tt.hash, tt.password)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsHashCostWeak(t *testing.T) {
	// Create hashes with different costs
	password := "test123"
	lowCostHash, err := HashPasswordWithCost(password, bcrypt.MinCost)
	require.NoError(t, err)

	mediumCostHash, err := HashPasswordWithCost(password, 8)
	require.NoError(t, err)

	highCostHash, err := HashPasswordWithCost(password, 12)
	require.NoError(t, err)

	tests := []struct {
		name     string
		hash     string
		minCost  int
		expected bool
	}{
		{
			name:     "low cost hash below threshold",
			hash:     lowCostHash,
			minCost:  8,
			expected: true,
		},
		{
			name:     "medium cost hash meets threshold",
			hash:     mediumCostHash,
			minCost:  8,
			expected: false,
		},
		{
			name:     "high cost hash above threshold",
			hash:     highCostHash,
			minCost:  8,
			expected: false,
		},
		{
			name:     "invalid hash treated as weak",
			hash:     "invalid-hash",
			minCost:  8,
			expected: true,
		},
		{
			name:     "empty hash treated as weak",
			hash:     "",
			minCost:  8,
			expected: true,
		},
		{
			name:     "zero min cost",
			hash:     lowCostHash,
			minCost:  0,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsHashCostWeak(tt.hash, tt.minCost)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestComparePasswordLogging(t *testing.T) {
	// Create a known hash first
	password := "test123!"
	hash, err := HashPassword(password)
	require.NoError(t, err)

	tests := []struct {
		name     string
		hash     string
		password string
		logger   *zap.Logger
		expected bool
		hasLog   bool
	}{
		{
			name:     "correct password with logger",
			hash:     hash,
			password: password,
			logger:   zaptest.NewLogger(t),
			expected: true,
			hasLog:   false,
		},
		{
			name:     "wrong password with logger",
			hash:     hash,
			password: "wrong123!",
			logger:   zaptest.NewLogger(t),
			expected: false,
			hasLog:   true,
		},
		{
			name:     "wrong password without logger",
			hash:     hash,
			password: "wrong123!",
			logger:   nil,
			expected: false,
			hasLog:   false,
		},
		{
			name:     "correct password without logger",
			hash:     hash,
			password: password,
			logger:   nil,
			expected: true,
			hasLog:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComparePasswordLogging(tt.hash, tt.password, tt.logger)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBcryptIntegration(t *testing.T) {
	// Test a complete workflow
	originalPassword := "MySecurePassword123!"

	// Hash the password
	hash, err := HashPassword(originalPassword)
	require.NoError(t, err)

	// Verify the password works
	assert.True(t, ComparePasswordBool(hash, originalPassword))

	// Verify wrong passwords don't work
	assert.False(t, ComparePasswordBool(hash, "WrongPassword"))

	// Check if the hash might be considered weak
	isWeak := IsHashCostWeak(hash, 12)
	if isWeak {
		// Upgrade to higher cost
		newHash, err := HashPasswordWithCost(originalPassword, 12)
		require.NoError(t, err)

		// Verify new hash still works
		assert.True(t, ComparePasswordBool(newHash, originalPassword))

		// Verify new hash is not weak
		assert.False(t, IsHashCostWeak(newHash, 12))
	}
}

func TestBcryptSecurityProperties(t *testing.T) {
	password := "testpassword"

	// Test that same password produces different hashes ()
	hash1, err := HashPassword(password)
	require.NoError(t, err)

	hash2, err := HashPassword(password)
	require.NoError(t, err)

	assert.NotEqual(t, hash1, hash2, "Same password should produce different hashes due to ")

	// Both hashes should verify the same password
	assert.True(t, ComparePasswordBool(hash1, password))
	assert.True(t, ComparePasswordBool(hash2, password))
}

func TestBcryptErrorHandling(t *testing.T) {
	// Test ComparePassword error cases
	err := ComparePassword("", "password")
	assert.Error(t, err)

	err = ComparePassword("invalid", "password")
	assert.Error(t, err)

	// Test extremely long passwords (over bcrypt limit)
	veryLongPassword := strings.Repeat("a", 1000)
	_, err = HashPassword(veryLongPassword)
	assert.Error(t, err) // bcrypt should reject passwords over 72 bytes
	assert.Contains(t, err.Error(), "password length")

	// Test password at the bcrypt limit (72 bytes)
	limitPassword := strings.Repeat("a", 72)
	hash, err := HashPassword(limitPassword)
	assert.NoError(t, err)
	assert.True(t, ComparePasswordBool(hash, limitPassword))
}
