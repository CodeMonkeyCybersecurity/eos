//go:build !darwin
// +build !darwin

package monitor

import (
	"syscall"
	"time"
)

// getAccessTime extracts access time from syscall.Stat_t for Unix systems (Linux)
func getAccessTime(stat *syscall.Stat_t) time.Time {
	return time.Unix(stat.Atim.Sec, stat.Atim.Nsec)
}
