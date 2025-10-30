// pkg/hecate/authentik/interfaces.go
// Interfaces for testability and dependency injection

package authentik

import (
	"context"
	"os"
)

// APIClient defines the interface for making Authentik API requests
// This allows for easy mocking in tests
type APIClient interface {
	// DoRequest performs an HTTP request to the Authentik API
	DoRequest(ctx context.Context, method, path string) ([]byte, error)
}

// FileWriter defines the interface for file operations
// This allows for testing without touching the filesystem
type FileWriter interface {
	// WriteFile writes data to a file
	WriteFile(path string, data []byte, perm os.FileMode) error
	
	// ReadFile reads data from a file
	ReadFile(path string) ([]byte, error)
	
	// MkdirAll creates a directory and all parent directories
	MkdirAll(path string, perm os.FileMode) error
}

// Archiver defines the interface for creating archives
// This allows for testing archive creation without executing tar
type Archiver interface {
	// CreateArchive creates a compressed archive of the source directory
	// Returns the path to the created archive
	CreateArchive(sourceDir string) (archivePath string, err error)
}

// TokenProvider defines the interface for retrieving authentication tokens
// This allows for testing without accessing the .env file
type TokenProvider interface {
	// GetToken retrieves the Authentik API token
	GetToken() (string, error)
}

// URLProvider defines the interface for retrieving the Authentik base URL
// This allows for testing without accessing Caddy API
type URLProvider interface {
	// GetBaseURL retrieves the Authentik API base URL
	GetBaseURL(ctx context.Context) (string, error)
}

// DefaultFileWriter implements FileWriter using standard library functions
type DefaultFileWriter struct{}

// WriteFile implements FileWriter.WriteFile
func (w *DefaultFileWriter) WriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

// ReadFile implements FileWriter.ReadFile
func (w *DefaultFileWriter) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// MkdirAll implements FileWriter.MkdirAll
func (w *DefaultFileWriter) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

// DefaultArchiver implements Archiver using the createArchive function
type DefaultArchiver struct{}

// CreateArchive implements Archiver.CreateArchive
func (a *DefaultArchiver) CreateArchive(sourceDir string) (string, error) {
	return createArchive(sourceDir)
}

// DefaultTokenProvider implements TokenProvider using the .env file
type DefaultTokenProvider struct{}

// GetToken implements TokenProvider.GetToken
func (p *DefaultTokenProvider) GetToken() (string, error) {
	return getAuthentikToken()
}

// DefaultURLProvider implements URLProvider using Caddy API
type DefaultURLProvider struct{}

// GetBaseURL implements URLProvider.GetBaseURL
func (p *DefaultURLProvider) GetBaseURL(ctx context.Context) (string, error) {
	// This would need RuntimeContext, but for now we'll use a simplified version
	// In production, you'd pass RuntimeContext through the interface
	return "http://hecate-server-1:9000/api/v3", nil
}
