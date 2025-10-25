// pkg/consul/acl/errors.go
//
// Actionable error messages for Consul ACL bootstrap token recovery.
//
// This package provides user-friendly error messages that guide users to solutions
// when automatic data directory detection fails during ACL bootstrap reset.
//
// Last Updated: 2025-10-25

package acl

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
)

// createDataDirNotFoundError creates an actionable error message when data directory cannot be determined.
//
// This error includes:
//   - Clear explanation of WHY auto-detection failed
//   - List of all attempted detection methods and their errors
//   - Step-by-step solutions for the user to try
//   - Common data directory locations to check
//
// Parameters:
//   - errors: Slice of errors from each detection method attempted
//
// Returns:
//   - error: User-friendly error with actionable guidance
//
// Example:
//
//	errors := []error{
//	    fmt.Errorf("config parse failed: file not found"),
//	    fmt.Errorf("API query failed: 403 Permission Denied"),
//	}
//	return createDataDirNotFoundError(errors)
func createDataDirNotFoundError(errors []error) error {
	var msg strings.Builder

	msg.WriteString("Cannot determine Consul data directory.\n\n")

	msg.WriteString("Context:\n")
	msg.WriteString("  You're recovering from a lost ACL bootstrap token.\n")
	msg.WriteString("  We cannot query the Consul API because that requires authentication,\n")
	msg.WriteString("  and that's precisely what we're trying to recover.\n\n")

	// Show what we tried
	msg.WriteString("Attempted detection methods (all failed):\n")
	for i, err := range errors {
		if err != nil {
			msg.WriteString(fmt.Sprintf("  %d. %v\n", i+1, err))
		}
	}
	msg.WriteString("\n")

	// Provide solutions
	msg.WriteString("Solutions to try (in order):\n\n")

	msg.WriteString("1. Specify data directory manually:\n")
	msg.WriteString("   eos update consul --bootstrap-token --data-dir /opt/consul\n\n")

	msg.WriteString("2. Find your data directory from config file:\n")
	msg.WriteString("   grep data_dir /etc/consul.d/consul.hcl\n")
	msg.WriteString("   OR\n")
	msg.WriteString("   grep data_dir /etc/consul.d/consul.json\n\n")

	msg.WriteString("3. Find your data directory from running process:\n")
	msg.WriteString("   ps aux | grep consul | grep data-dir\n\n")

	msg.WriteString("4. Find your data directory from systemd service:\n")
	msg.WriteString("   systemctl cat consul | grep ExecStart\n\n")

	msg.WriteString("5. Check common data directory locations:\n")
	msg.WriteString("   • /opt/consul          (Eos default)\n")
	msg.WriteString("   • /var/lib/consul      (Consul default)\n")
	msg.WriteString("   • /var/consul/data     (Alternative location)\n\n")

	msg.WriteString("Example commands:\n")
	msg.WriteString("  # With Eos default location\n")
	msg.WriteString("  eos update consul --bootstrap-token --data-dir /opt/consul\n\n")
	msg.WriteString("  # With Consul default location\n")
	msg.WriteString("  eos update consul --bootstrap-token --data-dir /var/lib/consul\n\n")
	msg.WriteString("  # Preview with dry-run first\n")
	msg.WriteString("  eos update consul --bootstrap-token --data-dir /opt/consul --dry-run\n")

	return eos_err.NewUserError("%s", msg.String())
}

// createDataDirValidationError creates an error when user-provided data directory is invalid.
//
// This is a simpler error for when the user explicitly provided --data-dir but the
// path they provided is not a valid Consul data directory.
func createDataDirValidationError(path string, validationErr error) error {
	var msg strings.Builder

	msg.WriteString(fmt.Sprintf("The specified data directory is not valid: %s\n\n", path))

	msg.WriteString(fmt.Sprintf("Validation error:\n  %v\n\n", validationErr))

	msg.WriteString("A valid Consul data directory must:\n")
	msg.WriteString("  • Exist and be a directory\n")
	msg.WriteString("  • Be readable and writable by root/consul user\n")
	msg.WriteString("  • Contain a raft/ subdirectory (required for Consul server)\n\n")

	msg.WriteString("Common issues:\n")
	msg.WriteString("  • Path doesn't exist (check spelling)\n")
	msg.WriteString("  • Path is a file, not a directory\n")
	msg.WriteString("  • Permission denied (run with sudo)\n")
	msg.WriteString("  • Wrong path (check config: grep data_dir /etc/consul.d/consul.hcl)\n\n")

	msg.WriteString("To find your actual Consul data directory:\n")
	msg.WriteString("  1. Check config: grep data_dir /etc/consul.d/consul.hcl\n")
	msg.WriteString("  2. Check process: ps aux | grep consul | grep data-dir\n")
	msg.WriteString("  3. Check systemd: systemctl cat consul | grep ExecStart\n")

	return eos_err.NewUserError("%s", msg.String())
}

// createAPIAccessError creates an informative message when API access fails during recovery.
//
// This is NOT a fatal error - it's expected when ACLs are locked down.
// We include this in the error chain but continue with other detection methods.
func createAPIAccessError(apiErr error) error {
	return fmt.Errorf("Consul API query failed (expected when ACLs locked down): %w\n"+
		"  This is normal during ACL bootstrap token recovery.\n"+
		"  Continuing with alternative detection methods...",
		apiErr)
}
