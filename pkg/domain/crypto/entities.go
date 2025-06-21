// Package crypto defines domain entities for cryptographic operations
package crypto

import (
	"time"
)

// HashAlgorithm represents supported hash algorithms
type HashAlgorithm string

const (
	SHA256   HashAlgorithm = "sha256"
	SHA384   HashAlgorithm = "sha384"
	SHA512   HashAlgorithm = "sha512"
	MD5      HashAlgorithm = "md5" // For legacy compatibility only
	BLAKE2b  HashAlgorithm = "blake2b"
	BLAKE2s  HashAlgorithm = "blake2s"
	SHA3_256 HashAlgorithm = "sha3-256"
	SHA3_384 HashAlgorithm = "sha3-384"
	SHA3_512 HashAlgorithm = "sha3-512"
)

// EncryptionAlgorithm represents supported encryption algorithms
type EncryptionAlgorithm string

const (
	AES256GCM     EncryptionAlgorithm = "aes-256-gcm"
	AES128GCM     EncryptionAlgorithm = "aes-128-gcm"
	ChaCha20Poly  EncryptionAlgorithm = "chacha20-poly1305"
	XChaCha20Poly EncryptionAlgorithm = "xchacha20-poly1305"
)

// KeyAlgorithm represents supported key algorithms
type KeyAlgorithm string

const (
	RSA2048  KeyAlgorithm = "rsa-2048"
	RSA4096  KeyAlgorithm = "rsa-4096"
	ECDSA256 KeyAlgorithm = "ecdsa-p256"
	ECDSA384 KeyAlgorithm = "ecdsa-p384"
	ECDSA521 KeyAlgorithm = "ecdsa-p521"
	Ed25519  KeyAlgorithm = "ed25519"
)

// PasswordAlgorithm represents password hashing algorithms
type PasswordAlgorithm string

const (
	Bcrypt   PasswordAlgorithm = "bcrypt"
	Argon2id PasswordAlgorithm = "argon2id"
	Scrypt   PasswordAlgorithm = "scrypt"
	PBKDF2   PasswordAlgorithm = "pbkdf2"
)

// HashResult represents the result of a hash operation
type HashResult struct {
	Algorithm   HashAlgorithm `json:"algorithm"`
	Hash        string        `json:"hash"`
	HexEncoded  bool          `json:"hex_encoded"`
	ComputeTime time.Duration `json:"compute_time"`
}

// EncryptionResult represents the result of an encryption operation
type EncryptionResult struct {
	Algorithm   EncryptionAlgorithm `json:"algorithm"`
	Ciphertext  []byte              `json:"ciphertext"`
	Nonce       []byte              `json:"nonce"`
	Tag         []byte              `json:"tag,omitempty"`
	EncryptTime time.Duration       `json:"encrypt_time"`
}

// DecryptionResult represents the result of a decryption operation
type DecryptionResult struct {
	Plaintext   []byte        `json:"plaintext"`
	DecryptTime time.Duration `json:"decrypt_time"`
	Verified    bool          `json:"verified"`
}

// KeyPair represents a cryptographic key pair
type KeyPair struct {
	Algorithm  KeyAlgorithm `json:"algorithm"`
	PrivateKey []byte       `json:"-"` // Never serialize private key
	PublicKey  []byte       `json:"public_key"`
	KeyID      string       `json:"key_id"`
	CreatedAt  time.Time    `json:"created_at"`
	ExpiresAt  *time.Time   `json:"expires_at,omitempty"`
}

// PasswordHash represents a hashed password with metadata
type PasswordHash struct {
	Algorithm   PasswordAlgorithm `json:"algorithm"`
	Hash        string            `json:"hash"`
	Salt        []byte            `json:"-"` // Don't expose salt
	Iterations  int               `json:"iterations,omitempty"`
	Memory      int               `json:"memory,omitempty"`
	Parallelism int               `json:"parallelism,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
}

// RandomData represents generated random data
type RandomData struct {
	Data      []byte    `json:"data"`
	Length    int       `json:"length"`
	Entropy   int       `json:"entropy_bits"`
	Generated time.Time `json:"generated"`
}

// SecureString represents a string that should be handled securely
type SecureString struct {
	value     string
	redacted  bool
	destroyed bool
}

// NewSecureString creates a new secure string
func NewSecureString(value string) *SecureString {
	return &SecureString{
		value:     value,
		redacted:  false,
		destroyed: false,
	}
}

// Value returns the string value if not destroyed
func (s *SecureString) Value() string {
	if s.destroyed {
		return ""
	}
	return s.value
}

// Redact marks the string as redacted
func (s *SecureString) Redact() {
	s.redacted = true
}

// Destroy securely erases the string value
func (s *SecureString) Destroy() {
	// Convert to byte slice to overwrite
	b := []byte(s.value)
	for i := range b {
		b[i] = 0
	}
	s.value = ""
	s.destroyed = true
}

// String implements Stringer interface with redaction
func (s *SecureString) String() string {
	if s.destroyed {
		return "[DESTROYED]"
	}
	if s.redacted {
		return "[REDACTED]"
	}
	return s.value
}

// ValidationResult represents the result of cryptographic validation
type ValidationResult struct {
	Valid     bool                   `json:"valid"`
	Algorithm string                 `json:"algorithm"`
	CheckedAt time.Time              `json:"checked_at"`
	Message   string                 `json:"message,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// CryptoPolicy defines cryptographic policy constraints
type CryptoPolicy struct {
	MinKeySize            int                  `json:"min_key_size"`
	AllowedAlgorithms     []string             `json:"allowed_algorithms"`
	RequireAuthentication bool                 `json:"require_authentication"`
	MaxKeyAge             time.Duration        `json:"max_key_age"`
	PasswordMinLength     int                  `json:"password_min_length"`
	PasswordRequirements  PasswordRequirements `json:"password_requirements"`
}

// PasswordRequirements defines password complexity requirements
type PasswordRequirements struct {
	MinLength      int  `json:"min_length"`
	RequireUpper   bool `json:"require_upper"`
	RequireLower   bool `json:"require_lower"`
	RequireDigit   bool `json:"require_digit"`
	RequireSpecial bool `json:"require_special"`
	MinEntropy     int  `json:"min_entropy_bits"`
}

// DefaultCryptoPolicy returns a secure default policy
func DefaultCryptoPolicy() CryptoPolicy {
	return CryptoPolicy{
		MinKeySize: 2048,
		AllowedAlgorithms: []string{
			string(SHA256), string(SHA384), string(SHA512),
			string(AES256GCM), string(ChaCha20Poly),
			string(RSA2048), string(RSA4096), string(ECDSA256),
		},
		RequireAuthentication: true,
		MaxKeyAge:             365 * 24 * time.Hour, // 1 year
		PasswordMinLength:     12,
		PasswordRequirements: PasswordRequirements{
			MinLength:      12,
			RequireUpper:   true,
			RequireLower:   true,
			RequireDigit:   true,
			RequireSpecial: true,
			MinEntropy:     60,
		},
	}
}

// CharacterSets for password and random string generation
const (
	CharsetLowercase   = "abcdefghijklmnopqrstuvwxyz"
	CharsetUppercase   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	CharsetDigits      = "0123456789"
	CharsetSpecial     = "!@#$%^&*()_+-=[]{}|;:,.<>?"
	CharsetAlphaNum    = CharsetLowercase + CharsetUppercase + CharsetDigits
	CharsetAll         = CharsetAlphaNum + CharsetSpecial
	CharsetSafeSpecial = "!@#$%^&*_+-="
	CharsetSafe        = CharsetAlphaNum + CharsetSafeSpecial
)
