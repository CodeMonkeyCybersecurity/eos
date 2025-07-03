// Package users provides user management operations following the AIE pattern
package users

// VaultClient defines the interface for Vault operations needed by user management
type VaultClient interface {
	Write(path string, data map[string]interface{}) error
	Read(path string) (map[string]interface{}, error)
	Delete(path string) error
}