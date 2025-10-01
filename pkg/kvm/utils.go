package kvm

import (
	"fmt"
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