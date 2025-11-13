// Package system provides system-level checks for idempotent operations
// These helpers enable "check before act" patterns to avoid unnecessary operations
// and reduce log noise from expected conditions during removal/cleanup.
package system

import (
	"context"
	"os/exec"
	"os/user"
	"strings"
)

// SystemdUnitExists checks if a systemd unit file exists
// Returns true if the unit file is found, false otherwise
func SystemdUnitExists(ctx context.Context, unitName string) bool {
	cmd := exec.CommandContext(ctx, "systemctl", "list-unit-files", unitName, "--no-legend")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) != ""
}

// SystemdUnitActive checks if a systemd unit is currently active
// Returns true if the unit is active (running), false otherwise
func SystemdUnitActive(ctx context.Context, unitName string) bool {
	cmd := exec.CommandContext(ctx, "systemctl", "is-active", unitName)
	err := cmd.Run()
	return err == nil // Exit 0 = active
}

// UserExists checks if a system user exists
// Returns true if the user is found in the system, false otherwise
func UserExists(username string) bool {
	_, err := user.Lookup(username)
	return err == nil
}

// GroupExists checks if a system group exists
// Returns true if the group is found in the system, false otherwise
func GroupExists(groupname string) bool {
	_, err := user.LookupGroup(groupname)
	return err == nil
}

// ProcessesExist checks if any processes match the given pattern
// Uses pgrep to search for processes matching the pattern
// Returns true if at least one matching process is found, false otherwise
func ProcessesExist(ctx context.Context, pattern string) bool {
	cmd := exec.CommandContext(ctx, "pgrep", "-f", pattern)
	err := cmd.Run()
	return err == nil // Exit 0 = found processes
}
