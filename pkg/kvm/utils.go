package kvm

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// GenerateVMName generates a unique VM name with timestamp
func GenerateVMName(base string) string {
	timestamp := time.Now().Format("20060102-1504")
	if base == "" {
		base = "ubuntu"
	}
	return fmt.Sprintf("%s-vm-%s", base, timestamp)
}

// GetRealUserIDs returns the real user's UID and GID when running under sudo
// Returns (-1, -1) if not running under sudo or if values can't be determined
func GetRealUserIDs() (uid int, gid int) {
	uid = -1
	gid = -1

	// Check if running under sudo
	sudoUID := os.Getenv("SUDO_UID")
	sudoGID := os.Getenv("SUDO_GID")

	if sudoUID != "" {
		if parsedUID, err := strconv.Atoi(sudoUID); err == nil {
			uid = parsedUID
		}
	}

	if sudoGID != "" {
		if parsedGID, err := strconv.Atoi(sudoGID); err == nil {
			gid = parsedGID
		}
	}

	return uid, gid
}