// Package crypto provides domain services for cryptographic operations
package crypto

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode"

	"go.uber.org/zap"
)

// Service implements cryptographic domain logic
type Service struct {
	hashOps       HashOperations
	encryptOps    EncryptionOperations
	signatureOps  SignatureOperations
	certOps       CertificateOperations
	randomOps     RandomOperations
	secureOps     SecureOperations
	keyMgmt       KeyManagement
	policy        CryptoPolicy
	logger        *zap.Logger
}

// NewService creates a new cryptographic service
func NewService(
	hashOps HashOperations,
	encryptOps EncryptionOperations,
	signatureOps SignatureOperations,
	certOps CertificateOperations,
	randomOps RandomOperations,
	secureOps SecureOperations,
	keyMgmt KeyManagement,
	policy CryptoPolicy,
	logger *zap.Logger,
) *Service {
	return &Service{
		hashOps:      hashOps,
		encryptOps:   encryptOps,
		signatureOps: signatureOps,
		certOps:      certOps,
		randomOps:    randomOps,
		secureOps:    secureOps,
		keyMgmt:      keyMgmt,
		policy:       policy,
		logger:       logger,
	}
}

// HashData hashes data with the specified algorithm
func (s *Service) HashData(ctx context.Context, data []byte, algorithm HashAlgorithm) (*HashResult, error) {
	start := time.Now()

	// Validate algorithm
	if !s.isAllowedAlgorithm(string(algorithm)) {
		return nil, fmt.Errorf("algorithm %s not allowed by policy", algorithm)
	}

	// Perform hash
	hash, err := s.hashOps.HashBytes(ctx, data, string(algorithm))
	if err != nil {
		s.logger.Error("Failed to hash data",
			zap.String("algorithm", string(algorithm)),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to hash data: %w", err)
	}

	result := &HashResult{
		Algorithm:   algorithm,
		Hash:        hex.EncodeToString(hash),
		HexEncoded:  true,
		ComputeTime: time.Since(start),
	}

	s.logger.Debug("Data hashed successfully",
		zap.String("algorithm", string(algorithm)),
		zap.Int("data_size", len(data)),
		zap.Duration("compute_time", result.ComputeTime),
	)

	return result, nil
}

// EncryptData encrypts data with automatic key generation if needed
func (s *Service) EncryptData(ctx context.Context, plaintext []byte, keyID string) (*EncryptionResult, error) {
	start := time.Now()

	// Retrieve or generate key
	key, err := s.getOrGenerateKey(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get encryption key: %w", err)
	}
	defer s.secureOps.SecureZero(key)

	// Encrypt data
	ciphertext, err := s.encryptOps.Encrypt(ctx, plaintext, key)
	if err != nil {
		s.logger.Error("Failed to encrypt data",
			zap.String("key_id", keyID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	result := &EncryptionResult{
		Algorithm:    AES256GCM, // Default algorithm
		Ciphertext:   ciphertext,
		EncryptTime:  time.Since(start),
	}

	s.logger.Info("Data encrypted successfully",
		zap.String("key_id", keyID),
		zap.Int("plaintext_size", len(plaintext)),
		zap.Int("ciphertext_size", len(ciphertext)),
		zap.Duration("encrypt_time", result.EncryptTime),
	)

	return result, nil
}

// DecryptData decrypts data using the specified key
func (s *Service) DecryptData(ctx context.Context, ciphertext []byte, keyID string) (*DecryptionResult, error) {
	start := time.Now()

	// Retrieve key
	key, err := s.keyMgmt.RetrieveKey(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve decryption key: %w", err)
	}
	defer s.secureOps.SecureZero(key)

	// Decrypt data
	plaintext, err := s.encryptOps.Decrypt(ctx, ciphertext, key)
	if err != nil {
		s.logger.Error("Failed to decrypt data",
			zap.String("key_id", keyID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	result := &DecryptionResult{
		Plaintext:   plaintext,
		DecryptTime: time.Since(start),
		Verified:    true,
	}

	s.logger.Info("Data decrypted successfully",
		zap.String("key_id", keyID),
		zap.Int("ciphertext_size", len(ciphertext)),
		zap.Int("plaintext_size", len(plaintext)),
		zap.Duration("decrypt_time", result.DecryptTime),
	)

	return result, nil
}

// GenerateSecurePassword generates a password meeting policy requirements
func (s *Service) GenerateSecurePassword(ctx context.Context, length int) (string, error) {
	// Ensure minimum length
	if length < s.policy.PasswordMinLength {
		length = s.policy.PasswordMinLength
	}

	// Generate password
	password, err := s.randomOps.GeneratePassword(ctx, length, s.policy.PasswordRequirements.RequireSpecial)
	if err != nil {
		return "", fmt.Errorf("failed to generate password: %w", err)
	}

	// Validate against policy
	if err := s.ValidatePassword(ctx, password); err != nil {
		// Retry if generated password doesn't meet requirements
		return s.GenerateSecurePassword(ctx, length+4)
	}

	s.logger.Debug("Secure password generated",
		zap.Int("length", len(password)),
	)

	return password, nil
}

// ValidatePassword validates a password against the policy
func (s *Service) ValidatePassword(ctx context.Context, password string) error {
	req := s.policy.PasswordRequirements

	// Check length
	if len(password) < req.MinLength {
		return fmt.Errorf("password must be at least %d characters long", req.MinLength)
	}

	// Check character requirements
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case strings.ContainsRune(CharsetSpecial, r):
			hasSpecial = true
		}
	}

	if req.RequireUpper && !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if req.RequireLower && !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if req.RequireDigit && !hasDigit {
		return fmt.Errorf("password must contain at least one digit")
	}
	if req.RequireSpecial && !hasSpecial {
		return fmt.Errorf("password must contain at least one special character")
	}

	// Check entropy (simplified calculation)
	entropy := s.calculatePasswordEntropy(password)
	if entropy < req.MinEntropy {
		return fmt.Errorf("password entropy too low: %d bits (minimum: %d)", entropy, req.MinEntropy)
	}

	return nil
}

// HashAndStorePassword hashes a password and stores it securely
func (s *Service) HashAndStorePassword(ctx context.Context, userID, password string) error {
	// Validate password first
	if err := s.ValidatePassword(ctx, password); err != nil {
		return fmt.Errorf("password validation failed: %w", err)
	}

	// Hash password
	hash, err := s.hashOps.HashPassword(ctx, password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Store hash
	key := fmt.Sprintf("password:%s", userID)
	if err := s.keyMgmt.StoreKey(ctx, key, []byte(hash)); err != nil {
		return fmt.Errorf("failed to store password hash: %w", err)
	}

	s.logger.Info("Password hashed and stored",
		zap.String("user_id", userID),
	)

	return nil
}

// VerifyUserPassword verifies a user's password
func (s *Service) VerifyUserPassword(ctx context.Context, userID, password string) (bool, error) {
	// Retrieve hash
	key := fmt.Sprintf("password:%s", userID)
	hashBytes, err := s.keyMgmt.RetrieveKey(ctx, key)
	if err != nil {
		return false, fmt.Errorf("failed to retrieve password hash: %w", err)
	}

	// Verify password
	valid, err := s.hashOps.VerifyPassword(ctx, password, string(hashBytes))
	if err != nil {
		return false, fmt.Errorf("failed to verify password: %w", err)
	}

	s.logger.Info("Password verification completed",
		zap.String("user_id", userID),
		zap.Bool("valid", valid),
	)

	return valid, nil
}

// GenerateKeyPair generates a new cryptographic key pair
func (s *Service) GenerateKeyPair(ctx context.Context, algorithm KeyAlgorithm) (*KeyPair, error) {
	// Validate algorithm
	if !s.isAllowedAlgorithm(string(algorithm)) {
		return nil, fmt.Errorf("algorithm %s not allowed by policy", algorithm)
	}

	// Determine key size
	var bits int
	switch algorithm {
	case RSA2048:
		bits = 2048
	case RSA4096:
		bits = 4096
	case ECDSA256:
		bits = 256
	case ECDSA384:
		bits = 384
	case ECDSA521:
		bits = 521
	case Ed25519:
		bits = 256
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	// Generate key pair
	privKey, pubKey, err := s.signatureOps.GenerateKeyPair(ctx, string(algorithm), bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Generate key ID
	keyID, err := s.randomOps.GenerateUUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key ID: %w", err)
	}

	keyPair := &KeyPair{
		Algorithm: algorithm,
		KeyID:     keyID,
		CreatedAt: time.Now(),
	}

	// Store keys (implementation depends on key type)
	// This is simplified - real implementation would serialize properly
	if err := s.keyMgmt.StoreKey(ctx, keyID+":private", []byte(fmt.Sprintf("%v", privKey))); err != nil {
		return nil, fmt.Errorf("failed to store private key: %w", err)
	}
	if err := s.keyMgmt.StoreKey(ctx, keyID+":public", []byte(fmt.Sprintf("%v", pubKey))); err != nil {
		return nil, fmt.Errorf("failed to store public key: %w", err)
	}

	s.logger.Info("Key pair generated",
		zap.String("key_id", keyID),
		zap.String("algorithm", string(algorithm)),
		zap.Int("bits", bits),
	)

	return keyPair, nil
}

// RotateEncryptionKey rotates an encryption key
func (s *Service) RotateEncryptionKey(ctx context.Context, keyID string) error {
	// Generate new key
	newKey, err := s.keyMgmt.RotateKey(ctx, keyID)
	if err != nil {
		return fmt.Errorf("failed to rotate key: %w", err)
	}
	defer s.secureOps.SecureZero(newKey)

	s.logger.Info("Encryption key rotated",
		zap.String("key_id", keyID),
	)

	return nil
}

// SecureCompareData performs constant-time comparison
func (s *Service) SecureCompareData(ctx context.Context, a, b []byte) bool {
	return s.secureOps.SecureCompare(a, b)
}

// RedactSensitiveData redacts sensitive information from strings
func (s *Service) RedactSensitiveData(ctx context.Context, input string, patterns []string) string {
	// Add common sensitive patterns if none provided
	if len(patterns) == 0 {
		patterns = []string{
			`\b\d{3}-\d{2}-\d{4}\b`,              // SSN
			`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`, // Credit card
			`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`, // Email
			`Bearer\s+[A-Za-z0-9\-_]+`,           // Bearer tokens
			`password["\s:=]+[^"\s]+`,            // Passwords in configs
		}
	}

	redacted := s.secureOps.RedactString(ctx, input, patterns)

	if redacted != input {
		s.logger.Debug("Sensitive data redacted",
			zap.Int("original_length", len(input)),
			zap.Int("redacted_length", len(redacted)),
		)
	}

	return redacted
}

// Helper methods

func (s *Service) isAllowedAlgorithm(algorithm string) bool {
	for _, allowed := range s.policy.AllowedAlgorithms {
		if allowed == algorithm {
			return true
		}
	}
	return false
}

func (s *Service) getOrGenerateKey(ctx context.Context, keyID string) ([]byte, error) {
	// Try to retrieve existing key
	key, err := s.keyMgmt.RetrieveKey(ctx, keyID)
	if err == nil {
		return key, nil
	}

	// Generate new key
	key, err = s.encryptOps.GenerateKey(ctx, 256) // 256-bit key
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Store for future use
	if err := s.keyMgmt.StoreKey(ctx, keyID, key); err != nil {
		// Log but don't fail - key can still be used
		s.logger.Warn("Failed to store generated key",
			zap.String("key_id", keyID),
			zap.Error(err),
		)
	}

	return key, nil
}

func (s *Service) calculatePasswordEntropy(password string) int {
	// Simplified entropy calculation
	charsetSize := 0
	hasLower, hasUpper, hasDigit, hasSpecial := false, false, false, false

	for _, r := range password {
		switch {
		case unicode.IsLower(r) && !hasLower:
			charsetSize += 26
			hasLower = true
		case unicode.IsUpper(r) && !hasUpper:
			charsetSize += 26
			hasUpper = true
		case unicode.IsDigit(r) && !hasDigit:
			charsetSize += 10
			hasDigit = true
		case !unicode.IsLetter(r) && !unicode.IsDigit(r) && !hasSpecial:
			charsetSize += 32
			hasSpecial = true
		}
	}

	// Entropy = log2(charset_size^length)
	// Simplified: entropy_per_char * length
	entropyPerChar := 0
	if charsetSize > 0 {
		// Approximate log2 calculation
		temp := charsetSize
		for temp > 1 {
			entropyPerChar++
			temp /= 2
		}
	}

	return entropyPerChar * len(password)
}

// ValidateCertificate validates a certificate according to policy
func (s *Service) ValidateCertificate(ctx context.Context, certData []byte) (*ValidationResult, error) {
	// Parse certificate
	cert, err := s.certOps.ParseCertificate(ctx, certData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Get certificate info
	info, err := s.certOps.GetCertificateInfo(ctx, cert)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate info: %w", err)
	}

	result := &ValidationResult{
		CheckedAt: time.Now(),
		Details:   make(map[string]interface{}),
	}

	// Check key algorithm
	if !s.isAllowedAlgorithm(info.KeyAlgorithm) {
		result.Valid = false
		result.Message = fmt.Sprintf("key algorithm %s not allowed by policy", info.KeyAlgorithm)
		return result, nil
	}

	// Check key size
	if info.KeySize < s.policy.MinKeySize {
		result.Valid = false
		result.Message = fmt.Sprintf("key size %d below minimum %d", info.KeySize, s.policy.MinKeySize)
		return result, nil
	}

	result.Valid = true
	result.Algorithm = info.KeyAlgorithm
	result.Message = "Certificate validation passed"
	result.Details["key_size"] = info.KeySize
	result.Details["issuer"] = info.Issuer
	result.Details["subject"] = info.Subject

	return result, nil
}