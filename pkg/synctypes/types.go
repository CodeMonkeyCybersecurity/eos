// Package synctypes provides shared types for service synchronization.
// This separate package avoids import cycles between sync and sync/connectors.
package synctypes

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// ServiceConnector defines the interface for connecting two services together.
// Implementations must be idempotent and support rollback on failure.
type ServiceConnector interface {
	// Name returns the connector name (e.g., "ConsulVaultConnector")
	Name() string

	// Description returns a human-readable description of what this connector does
	Description() string

	// ServicePair returns the normalized service pair identifier (e.g., "consul-vault")
	ServicePair() string

	// PreflightCheck verifies both services are installed and running.
	// Returns error if prerequisites not met.
	PreflightCheck(rc *eos_io.RuntimeContext, config *SyncConfig) error

	// CheckConnection returns the current connection state between services.
	// Returns SyncState with detailed status information.
	CheckConnection(rc *eos_io.RuntimeContext, config *SyncConfig) (*SyncState, error)

	// Backup creates backups of service configurations before making changes.
	// Returns backup metadata for potential rollback.
	Backup(rc *eos_io.RuntimeContext, config *SyncConfig) (*BackupMetadata, error)

	// Connect establishes the connection between services.
	// Must be idempotent - safe to run multiple times.
	Connect(rc *eos_io.RuntimeContext, config *SyncConfig) error

	// Verify validates the connection is working correctly.
	// Returns error if connection not functional.
	Verify(rc *eos_io.RuntimeContext, config *SyncConfig) error

	// Rollback reverts configuration changes using backup metadata.
	// Called automatically if Connect or Verify fails.
	Rollback(rc *eos_io.RuntimeContext, config *SyncConfig, backup *BackupMetadata) error
}

// SyncConfig contains configuration for service synchronization
type SyncConfig struct {
	// Service names (order-independent)
	Service1 string
	Service2 string

	// Behavior flags
	DryRun          bool // Preview changes without applying
	Force           bool // Force sync even if already connected
	SkipBackup      bool // Skip configuration backup
	SkipHealthCheck bool // Skip health validation after sync

	// ACL Configuration
	ConsulACLToken string // Consul management token for ACL operations (optional)

	// Internal state
	BackupDir string // Directory for configuration backups
}

// SyncState represents the current connection state between two services
type SyncState struct {
	// Connection status
	Connected bool   // Are services currently connected?
	Healthy   bool   // Are both services healthy?
	Reason    string // Explanation of current state

	// Service status
	Service1Installed bool
	Service1Running   bool
	Service1Healthy   bool

	Service2Installed bool
	Service2Running   bool
	Service2Healthy   bool

	// Configuration status
	ConfigurationComplete bool // All config files in place?
	ConfigurationValid    bool // Configuration syntax valid?
}

// BackupMetadata contains information about backed-up configurations
type BackupMetadata struct {
	// Backup location
	BackupDir   string
	BackupTime  string
	BackupFiles map[string]string // original path -> backup path

	// Rollback information
	Service1ConfigPath string
	Service2ConfigPath string
	RestartRequired    bool
}

// SyncResult contains the outcome of a sync operation
type SyncResult struct {
	Success bool
	DryRun  bool
	Message string
	Changes []string // List of changes made or would be made (dry-run)
	Errors  []error  // Any errors encountered
}
