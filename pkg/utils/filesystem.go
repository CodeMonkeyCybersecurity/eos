// Package utils provides filesystem utility functions
package utils

// IsPseudoFilesystem checks if a filesystem is a pseudo filesystem.
// It follows the Assess → Intervene → Evaluate pattern.
func IsPseudoFilesystem(fs string) bool {
	// ASSESS - Define known pseudo filesystems
	pseudo := []string{"proc", "sysfs", "devfs", "devpts", "tmpfs", "securityfs", "cgroup", "debugfs"}

	// INTERVENE - Check if the given filesystem matches any pseudo filesystem
	for _, p := range pseudo {
		if fs == p {
			// EVALUATE - Found a match
			return true
		}
	}

	// EVALUATE - No match found
	return false
}
