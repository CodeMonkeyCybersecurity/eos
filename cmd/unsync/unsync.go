// cmd/unsync/unsync.go
package unsync

import (
	"github.com/spf13/cobra"
)

// UnsyncCmd is the root command for service un-synchronization
var UnsyncCmd = &cobra.Command{
	Use:   "unsync",
	Short: "Remove nodes or disconnect synchronized services",
	Long: `Remove nodes from clusters or disconnect synchronized services.

The unsync command reverses synchronization operations, allowing you to:
  - Remove specific nodes from Consul retry_join configuration
  - Disconnect previously synchronized services

Currently supported operations:
  - unsync consul --nodes <node1> [node2] ...  Remove nodes from Consul cluster config

Safety Features:
  - Configuration backups created before any changes (unless --skip-backup)
  - Idempotent operations (safe to run multiple times)
  - Atomic operations with automatic rollback on failure

Examples:
  # Remove vhost5 from Consul retry_join configuration
  eos unsync consul --nodes vhost5

  # Remove multiple nodes
  eos unsync consul --nodes vhost5 vhost7

  # Preview changes without applying
  eos unsync consul --nodes vhost5 --dry-run

Code Monkey Cybersecurity - "Cybersecurity. With humans."`,
}
