//go:build darwin
// +build darwin

package storage_monitor

import (
	"syscall"
	"time"
)

// getAccessTime extracts access time from syscall.Stat_t for macOS
func getAccessTime(stat *syscall.Stat_t) time.Time {
	return time.Unix(stat.Atimespec.Sec, stat.Atimespec.Nsec)
}
