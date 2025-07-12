// pkg/authentication/comprehensive_test.go

package authentication

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockAuthProvider is a mock authentication provider
type MockAuthProvider struct {
	mock.Mock
}

func (m *MockAuthProvider) Authenticate(ctx context.Context, credentials map[string]string) (*AuthResult, error) {
	args := m.Called(ctx, credentials)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*AuthResult), args.Error(1)
}

func (m *MockAuthProvider) ValidateToken(ctx context.Context, token string) (*TokenInfo, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*TokenInfo), args.Error(1)
}

func (m *MockAuthProvider) RevokeToken(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

// Test types
type AuthResult struct {
	UserID      string
	Username    string
	Token       string
	ExpiresAt   time.Time
	Permissions []string
}

type TokenInfo struct {
	UserID      string
	Username    string
	ExpiresAt   time.Time
	IsValid     bool
	Permissions []string
}

// TestUsernameValidation tests username validation rules
func TestUsernameValidation(t *testing.T) {
	tests := []struct {
		name     string
		username string
		expected bool
	}{
		{
			name:     "valid username",
			username: "validuser",
			expected: true,
		},
		{
			name:     "valid with numbers",
			username: "user123",
			expected: true,
		},
		{
			name:     "valid with underscore",
			username: "test_user",
			expected: true,
		},
		{
			name:     "valid with hyphen",
			username: "test-user",
			expected: true,
		},
		{
			name:     "empty username",
			username: "",
			expected: false,
		},
		{
			name:     "username with spaces",
			username: "user name",
			expected: false,
		},
		{
			name:     "username with newline",
			username: "user\nname",
			expected: false,
		},
		{
			name:     "username with null byte",
			username: "user\x00name",
			expected: false,
		},
		{
			name:     "username with shell chars",
			username: "user;whoami",
			expected: false,
		},
		{
			name:     "username too long",
			username: "verylongusernamethatexceedsthemaximumlength",
			expected: false,
		},
		{
			name:     "path traversal attempt",
			username: "../admin",
			expected: false,
		},
		{
			name:     "sql injection attempt",
			username: "admin'; DROP TABLE users;--",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateUsername(tt.username)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestPasswordValidation tests password strength requirements
func TestPasswordValidation(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		wantErr     bool
		expectedErr error
	}{
		{
			name:     "valid strong password",
			password: "StrongP@ssw0rd123",
			wantErr:  false,
		},
		{
			name:        "too short",
			password:    "Short1!",
			wantErr:     true,
			expectedErr: ErrPasswordLength,
		},
		{
			name:        "too long",
			password:    string(make([]byte, 129)),
			wantErr:     true,
			expectedErr: ErrPasswordLength,
		},
		{
			name:        "common weak password",
			password:    "password",
			wantErr:     true,
			expectedErr: ErrPasswordWeak,
		},
		{
			name:        "null byte in password",
			password:    "Pass\x00word123!",
			wantErr:     true,
			expectedErr: ErrPasswordInvalid,
		},
		{
			name:        "numeric only",
			password:    "12345678",
			wantErr:     true,
			expectedErr: ErrPasswordWeak,
		},
		{
			name:     "valid with special chars",
			password: "Test@123$Pass",
			wantErr:  false,
		},
		{
			name:     "valid with unicode",
			password: "Пароль123!",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.expectedErr != nil {
					assert.Equal(t, tt.expectedErr, err)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestEmailValidation tests email format validation
func TestEmailValidation(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		expected bool
	}{
		{
			name:     "valid email",
			email:    "user@example.com",
			expected: true,
		},
		{
			name:     "valid with subdomain",
			email:    "user@mail.example.com",
			expected: true,
		},
		{
			name:     "valid with plus",
			email:    "user+tag@example.com",
			expected: true,
		},
		{
			name:     "valid with dots",
			email:    "first.last@example.com",
			expected: true,
		},
		{
			name:     "empty email",
			email:    "",
			expected: false,
		},
		{
			name:     "missing @",
			email:    "userexample.com",
			expected: false,
		},
		{
			name:     "missing domain",
			email:    "user@",
			expected: false,
		},
		{
			name:     "missing user",
			email:    "@example.com",
			expected: false,
		},
		{
			name:     "multiple @",
			email:    "user@@example.com",
			expected: false,
		},
		{
			name:     "with newline",
			email:    "user@exam\nple.com",
			expected: false,
		},
		{
			name:     "with null byte",
			email:    "user\x00@example.com",
			expected: false,
		},
		{
			name:     "consecutive dots",
			email:    "user@example..com",
			expected: false,
		},
		{
			name:     "too long",
			email:    string(make([]byte, 255)) + "@example.com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateEmail(tt.email)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestAPIKeyValidation tests API key format validation
func TestAPIKeyValidation(t *testing.T) {
	tests := []struct {
		name     string
		apiKey   string
		expected bool
	}{
		{
			name:     "valid API key",
			apiKey:   "sk_live_1234567890abcdef",
			expected: true,
		},
		{
			name:     "valid test key",
			apiKey:   "pk_test_abcdef1234567890",
			expected: true,
		},
		{
			name:     "minimum length",
			apiKey:   "1234567890123456",
			expected: true,
		},
		{
			name:     "empty key",
			apiKey:   "",
			expected: false,
		},
		{
			name:     "too short",
			apiKey:   "shortkey",
			expected: false,
		},
		{
			name:     "too long",
			apiKey:   string(make([]byte, 257)),
			expected: false,
		},
		{
			name:     "with spaces",
			apiKey:   "api key with spaces",
			expected: false,
		},
		{
			name:     "with newline",
			apiKey:   "apikey\nwithnewline",
			expected: false,
		},
		{
			name:     "with null byte",
			apiKey:   "apikey\x00withnull",
			expected: false,
		},
		{
			name:     "with shell chars",
			apiKey:   "apikey;rm -rf /",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateAPIKey(tt.apiKey)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestJWTStructureValidation tests JWT format validation
func TestJWTStructureValidation(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tests := []struct {
		name     string
		token    string
		expected bool
	}{
		{
			name:     "valid JWT structure",
			token:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			expected: true,
		},
		{
			name:     "simple valid structure",
			token:    "header.payload.signature",
			expected: true,
		},
		{
			name:     "empty token",
			token:    "",
			expected: false,
		},
		{
			name:     "missing parts",
			token:    "header.payload",
			expected: false,
		},
		{
			name:     "extra parts",
			token:    "header.payload.signature.extra",
			expected: false,
		},
		{
			name:     "empty part",
			token:    "header..signature",
			expected: false,
		},
		{
			name:     "with newline",
			token:    "header.pay\nload.signature",
			expected: false,
		},
		{
			name:     "with null byte",
			token:    "header.pay\x00load.signature",
			expected: false,
		},
		{
			name:     "too long",
			token:    string(make([]byte, 8193)),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateJWTStructure(rc, tt.token)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestSessionIDValidation tests session ID format validation
func TestSessionIDValidation(t *testing.T) {
	tests := []struct {
		name      string
		sessionID string
		expected  bool
	}{
		{
			name:      "valid hex session ID",
			sessionID: "abc123def456ghi789jkl012mno345pq",
			expected:  true,
		},
		{
			name:      "valid UUID",
			sessionID: "550e8400-e29b-41d4-a716-446655440000",
			expected:  true,
		},
		{
			name:      "minimum length",
			sessionID: "1234567890123456",
			expected:  true,
		},
		{
			name:      "empty session ID",
			sessionID: "",
			expected:  false,
		},
		{
			name:      "too short",
			sessionID: "shortid",
			expected:  false,
		},
		{
			name:      "too long",
			sessionID: string(make([]byte, 129)),
			expected:  false,
		},
		{
			name:      "with spaces",
			sessionID: "session id with spaces",
			expected:  false,
		},
		{
			name:      "with newline",
			sessionID: "session\nid",
			expected:  false,
		},
		{
			name:      "with dangerous chars",
			sessionID: "session;rm -rf /",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateSessionID(tt.sessionID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestAuthenticationFlow tests complete authentication workflow
func TestAuthenticationFlow(t *testing.T) {
	mockProvider := new(MockAuthProvider)

	t.Run("successful authentication", func(t *testing.T) {
		ctx := context.Background()
		credentials := map[string]string{
			"username": "testuser",
			"password": "TestPass123!",
		}

		expectedResult := &AuthResult{
			UserID:      "user123",
			Username:    "testuser",
			Token:       generateTestToken(),
			ExpiresAt:   time.Now().Add(24 * time.Hour),
			Permissions: []string{"read", "write"},
		}

		mockProvider.On("Authenticate", ctx, credentials).Return(expectedResult, nil)

		result, err := mockProvider.Authenticate(ctx, credentials)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, expectedResult.UserID, result.UserID)
		assert.Equal(t, expectedResult.Username, result.Username)
		assert.NotEmpty(t, result.Token)
		mockProvider.AssertExpectations(t)
	})

	t.Run("invalid credentials", func(t *testing.T) {
		ctx := context.Background()
		credentials := map[string]string{
			"username": "testuser",
			"password": "wrongpassword",
		}

		mockProvider.On("Authenticate", ctx, credentials).Return(nil, errors.New("invalid credentials"))

		result, err := mockProvider.Authenticate(ctx, credentials)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "invalid credentials")
		mockProvider.AssertExpectations(t)
	})

	t.Run("missing credentials", func(t *testing.T) {
		ctx := context.Background()
		credentials := map[string]string{
			"username": "",
			"password": "",
		}

		mockProvider.On("Authenticate", ctx, credentials).Return(nil, errors.New("missing credentials"))

		result, err := mockProvider.Authenticate(ctx, credentials)
		assert.Error(t, err)
		assert.Nil(t, result)
		mockProvider.AssertExpectations(t)
	})
}

// TestTokenValidation tests token validation and lifecycle
func TestTokenValidation(t *testing.T) {
	mockProvider := new(MockAuthProvider)

	t.Run("valid token", func(t *testing.T) {
		ctx := context.Background()
		token := generateTestToken()

		expectedInfo := &TokenInfo{
			UserID:      "user123",
			Username:    "testuser",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
			IsValid:     true,
			Permissions: []string{"read", "write"},
		}

		mockProvider.On("ValidateToken", ctx, token).Return(expectedInfo, nil)

		info, err := mockProvider.ValidateToken(ctx, token)
		assert.NoError(t, err)
		assert.NotNil(t, info)
		assert.True(t, info.IsValid)
		assert.Equal(t, expectedInfo.UserID, info.UserID)
		mockProvider.AssertExpectations(t)
	})

	t.Run("expired token", func(t *testing.T) {
		ctx := context.Background()
		token := generateTestToken()

		expectedInfo := &TokenInfo{
			UserID:    "user123",
			Username:  "testuser",
			ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
			IsValid:   false,
		}

		mockProvider.On("ValidateToken", ctx, token).Return(expectedInfo, nil)

		info, err := mockProvider.ValidateToken(ctx, token)
		assert.NoError(t, err)
		assert.NotNil(t, info)
		assert.False(t, info.IsValid)
		mockProvider.AssertExpectations(t)
	})

	t.Run("invalid token", func(t *testing.T) {
		ctx := context.Background()
		token := "invalid-token"

		mockProvider.On("ValidateToken", ctx, token).Return(nil, errors.New("invalid token format"))

		info, err := mockProvider.ValidateToken(ctx, token)
		assert.Error(t, err)
		assert.Nil(t, info)
		mockProvider.AssertExpectations(t)
	})

	t.Run("revoked token", func(t *testing.T) {
		ctx := context.Background()
		token := generateTestToken()

		// First revoke the token
		mockProvider.On("RevokeToken", ctx, token).Return(nil)
		err := mockProvider.RevokeToken(ctx, token)
		assert.NoError(t, err)

		// Then try to validate it
		mockProvider.On("ValidateToken", ctx, token).Return(nil, errors.New("token revoked"))
		info, err := mockProvider.ValidateToken(ctx, token)
		assert.Error(t, err)
		assert.Nil(t, info)
		assert.Contains(t, err.Error(), "revoked")
		mockProvider.AssertExpectations(t)
	})
}

// TestConcurrentAuthentication tests concurrent authentication requests
func TestConcurrentAuthentication(t *testing.T) {
	mockProvider := new(MockAuthProvider)
	ctx := context.Background()

	// Setup mock for concurrent calls
	mockProvider.On("Authenticate", ctx, mock.Anything).Return(&AuthResult{
		UserID:    "user123",
		Username:  "testuser",
		Token:     generateTestToken(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}, nil).Maybe()

	// Run concurrent authentication attempts
	var wg sync.WaitGroup
	errors := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			credentials := map[string]string{
				"username": "user" + string(rune(id)),
				"password": "password123",
			}

			_, err := mockProvider.Authenticate(ctx, credentials)
			if err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	errorCount := 0
	for err := range errors {
		if err != nil {
			errorCount++
		}
	}

	assert.Equal(t, 0, errorCount, "Concurrent authentication had errors")
}

// TestPasswordHashing tests password hashing and verification
func TestPasswordHashing(t *testing.T) {
	passwords := []string{
		"TestPassword123!",
		"AnotherPass456@",
		"Unicode密码123!",
		"Пароль789#",
	}

	for _, password := range passwords {
		t.Run("hash and verify "+password[:4]+"...", func(t *testing.T) {
			// Hash the password
			hash, err := HashPassword(password)
			assert.NoError(t, err)
			assert.NotEmpty(t, hash)
			assert.NotEqual(t, password, hash)

			// Verify correct password
			valid := VerifyPassword(password, hash)
			assert.True(t, valid)

			// Verify incorrect password
			invalid := VerifyPassword("wrongpassword", hash)
			assert.False(t, invalid)

			// Verify hash is different each time
			hash2, err := HashPassword(password)
			assert.NoError(t, err)
			assert.NotEqual(t, hash, hash2)
		})
	}
}

// TestSessionManagement tests session creation and management
func TestSessionManagement(t *testing.T) {
	t.Run("create session", func(t *testing.T) {
		userID := "user123"
		session, err := CreateSession(userID)

		assert.NoError(t, err)
		assert.NotNil(t, session)
		assert.NotEmpty(t, session.ID)
		assert.Equal(t, userID, session.UserID)
		assert.True(t, session.ExpiresAt.After(time.Now()))
		assert.True(t, ValidateSessionID(session.ID))
	})

	t.Run("session expiration", func(t *testing.T) {
		session := &Session{
			ID:        generateSessionID(),
			UserID:    "user123",
			CreatedAt: time.Now().Add(-25 * time.Hour),
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}

		assert.True(t, session.IsExpired())
	})

	t.Run("concurrent session creation", func(t *testing.T) {
		var wg sync.WaitGroup
		sessions := make(map[string]bool)
		mu := sync.Mutex{}

		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				session, err := CreateSession("user" + string(rune(id)))
				require.NoError(t, err)

				mu.Lock()
				// Check for duplicate session IDs
				assert.False(t, sessions[session.ID], "Duplicate session ID generated")
				sessions[session.ID] = true
				mu.Unlock()
			}(i)
		}

		wg.Wait()
		assert.Len(t, sessions, 100)
	})
}

// TestRateLimiting tests authentication rate limiting
func TestRateLimiting(t *testing.T) {
	limiter := NewRateLimiter(3, time.Minute) // 3 attempts per minute

	t.Run("within limit", func(t *testing.T) {
		userID := "user123"

		for i := 0; i < 3; i++ {
			allowed := limiter.Allow(userID)
			assert.True(t, allowed, "Attempt %d should be allowed", i+1)
		}
	})

	t.Run("exceeds limit", func(t *testing.T) {
		userID := "user456"

		// First 3 attempts should succeed
		for i := 0; i < 3; i++ {
			allowed := limiter.Allow(userID)
			assert.True(t, allowed)
		}

		// 4th attempt should fail
		allowed := limiter.Allow(userID)
		assert.False(t, allowed, "4th attempt should be blocked")
	})

	t.Run("different users", func(t *testing.T) {
		// Each user has their own limit
		for i := 0; i < 5; i++ {
			userID := "user" + string(rune(i))
			allowed := limiter.Allow(userID)
			assert.True(t, allowed, "First attempt for user %s should be allowed", userID)
		}
	})
}

// Helper functions
func generateTestToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func generateSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// Mock implementations
func HashPassword(password string) (string, error) {
	// Use proper bcrypt hashing with random salt
	cost := 12
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func VerifyPassword(password, hash string) bool {
	// Use bcrypt comparison
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

type Session struct {
	ID        string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
}

func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

func CreateSession(userID string) (*Session, error) {
	return &Session{
		ID:        generateSessionID(),
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}, nil
}

type RateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	limit    int
	window   time.Duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		attempts: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

func (r *RateLimiter) Allow(userID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-r.window)

	// Clean old attempts
	var validAttempts []time.Time
	for _, attempt := range r.attempts[userID] {
		if attempt.After(windowStart) {
			validAttempts = append(validAttempts, attempt)
		}
	}

	if len(validAttempts) >= r.limit {
		return false
	}

	validAttempts = append(validAttempts, now)
	r.attempts[userID] = validAttempts
	return true
}
