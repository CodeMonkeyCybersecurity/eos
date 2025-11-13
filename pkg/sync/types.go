// Package sync provides functionality to connect and synchronize services.
//
// The package follows the Eos Assess → Intervene → Evaluate pattern:
//   - Assess: Check both services installed, running, not already connected
//   - Intervene: Backup configs, apply connection configuration, restart if needed
//   - Evaluate: Verify connectivity, health checks, rollback on failure
//
// Service Connectors:
//   - Order-independent: "consul vault" and "vault consul" use same connector
//   - Idempotent: Safe to run multiple times
//   - Atomic: Rollback on failure
//   - Validated: Pre-flight checks before any changes
//
// Example usage:
//
//	config := &sync.SyncConfig{
//	    Service1: "consul",
//	    Service2: "vault",
//	    DryRun: false,
//	    Force: false,
//	}
//	connector, err := sync.GetConnector("consul-vault")
//	if err := sync.ExecuteSync(rc, connector, config); err != nil {
//	    log.Fatal(err)
//	}
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."
package sync

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/synctypes"
)

// Re-export types from synctypes to maintain API compatibility
// This avoids import cycles while keeping clean package structure

type ServiceConnector = synctypes.ServiceConnector
type SyncConfig = synctypes.SyncConfig
type SyncState = synctypes.SyncState
type BackupMetadata = synctypes.BackupMetadata
type SyncResult = synctypes.SyncResult
