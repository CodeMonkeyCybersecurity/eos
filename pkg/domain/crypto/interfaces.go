// Package crypto defines domain interfaces for cryptographic operations
package crypto

import (
	"context"
	"crypto/x509"
	"io"
)

// HashOperations defines the interface for hashing operations
type HashOperations interface {
	// HashString creates a hash of a string using the specified algorithm
	HashString(ctx context.Context, input string, algorithm string) (string, error)

	// HashBytes creates a hash of bytes using the specified algorithm
	HashBytes(ctx context.Context, input []byte, algorithm string) ([]byte, error)

	// HashFile creates a hash of a file's contents
	HashFile(ctx context.Context, path string, algorithm string) (string, error)

	// VerifyHash verifies that a hash matches the expected value
	VerifyHash(ctx context.Context, input []byte, expectedHash string, algorithm string) (bool, error)

	// HashPassword creates a secure hash of a password (bcrypt, argon2, etc.)
	HashPassword(ctx context.Context, password string) (string, error)

	// VerifyPassword verifies a password against its hash
	VerifyPassword(ctx context.Context, password, hash string) (bool, error)
}

// EncryptionOperations defines the interface for encryption/decryption operations
type EncryptionOperations interface {
	// Encrypt encrypts data using the specified algorithm and key
	Encrypt(ctx context.Context, plaintext []byte, key []byte) ([]byte, error)

	// Decrypt decrypts data using the specified algorithm and key
	Decrypt(ctx context.Context, ciphertext []byte, key []byte) ([]byte, error)

	// EncryptStream encrypts data from a reader to a writer
	EncryptStream(ctx context.Context, reader io.Reader, writer io.Writer, key []byte) error

	// DecryptStream decrypts data from a reader to a writer
	DecryptStream(ctx context.Context, reader io.Reader, writer io.Writer, key []byte) error

	// GenerateKey generates a new encryption key
	GenerateKey(ctx context.Context, bits int) ([]byte, error)

	// DeriveKey derives a key from a password using a key derivation function
	DeriveKey(ctx context.Context, password string, salt []byte, keyLen int) ([]byte, error)
}

// SignatureOperations defines the interface for digital signature operations
type SignatureOperations interface {
	// Sign creates a digital signature for the given data
	Sign(ctx context.Context, data []byte, privateKey interface{}) ([]byte, error)

	// Verify verifies a digital signature
	Verify(ctx context.Context, data []byte, signature []byte, publicKey interface{}) (bool, error)

	// GenerateKeyPair generates a new key pair for signing
	GenerateKeyPair(ctx context.Context, algorithm string, bits int) (interface{}, interface{}, error)
}

// CertificateOperations defines the interface for certificate operations
type CertificateOperations interface {
	// GenerateSelfSignedCert generates a self-signed certificate
	GenerateSelfSignedCert(ctx context.Context, opts CertificateOptions) (*x509.Certificate, interface{}, error)

	// GenerateCSR generates a certificate signing request
	GenerateCSR(ctx context.Context, opts CSROptions) ([]byte, interface{}, error)

	// ParseCertificate parses a certificate from PEM or DER format
	ParseCertificate(ctx context.Context, data []byte) (*x509.Certificate, error)

	// ValidateCertificate validates a certificate against a CA
	ValidateCertificate(ctx context.Context, cert *x509.Certificate, caCert *x509.Certificate) error

	// GetCertificateInfo extracts information from a certificate
	GetCertificateInfo(ctx context.Context, cert *x509.Certificate) (*CertificateInfo, error)
}

// RandomOperations defines the interface for random data generation
type RandomOperations interface {
	// GenerateRandomBytes generates cryptographically secure random bytes
	GenerateRandomBytes(ctx context.Context, length int) ([]byte, error)

	// GenerateRandomString generates a random string with specified character set
	GenerateRandomString(ctx context.Context, length int, charset string) (string, error)

	// GenerateUUID generates a random UUID
	GenerateUUID(ctx context.Context) (string, error)

	// GeneratePassword generates a secure random password
	GeneratePassword(ctx context.Context, length int, includeSpecial bool) (string, error)
}

// SecureOperations defines the interface for secure data handling
type SecureOperations interface {
	// SecureZero overwrites sensitive data in memory
	SecureZero(data []byte)

	// SecureCompare performs constant-time comparison of two byte slices
	SecureCompare(a, b []byte) bool

	// RedactString redacts sensitive parts of a string
	RedactString(ctx context.Context, input string, patterns []string) string

	// SanitizeInput sanitizes user input to prevent injection attacks
	SanitizeInput(ctx context.Context, input string, allowedChars string) (string, error)
}

// KeyManagement defines the interface for cryptographic key management
type KeyManagement interface {
	// StoreKey securely stores a cryptographic key
	StoreKey(ctx context.Context, keyID string, key []byte) error

	// RetrieveKey retrieves a stored cryptographic key
	RetrieveKey(ctx context.Context, keyID string) ([]byte, error)

	// DeleteKey securely deletes a stored key
	DeleteKey(ctx context.Context, keyID string) error

	// RotateKey rotates a cryptographic key
	RotateKey(ctx context.Context, keyID string) ([]byte, error)

	// ListKeys lists all stored key IDs
	ListKeys(ctx context.Context) ([]string, error)
}

// CertificateOptions holds options for certificate generation
type CertificateOptions struct {
	CommonName         string
	Organization       []string
	Country            []string
	Province           []string
	Locality           []string
	StreetAddress      []string
	PostalCode         []string
	DNSNames           []string
	IPAddresses        []string
	EmailAddresses     []string
	ValidityDays       int
	KeyAlgorithm       string
	KeySize            int
	SignatureAlgorithm string
}

// CSROptions holds options for CSR generation
type CSROptions struct {
	CommonName     string
	Organization   []string
	Country        []string
	Province       []string
	Locality       []string
	StreetAddress  []string
	PostalCode     []string
	DNSNames       []string
	IPAddresses    []string
	EmailAddresses []string
	KeyAlgorithm   string
	KeySize        int
}

// CertificateInfo contains parsed certificate information
type CertificateInfo struct {
	Subject        string
	Issuer         string
	SerialNumber   string
	NotBefore      string
	NotAfter       string
	DNSNames       []string
	IPAddresses    []string
	EmailAddresses []string
	KeyAlgorithm   string
	KeySize        int
	SignatureAlgo  string
	IsCA           bool
	IsSelfSigned   bool
}
