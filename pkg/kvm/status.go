//go:build linux

// pkg/kvm/status.go

package kvm

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"go.uber.org/zap"
)

// IsVMRunning checks if the VM appears as 'running' in virsh output.
func IsVMRunning(virshList string, vmName string) bool {
	for _, line := range strings.Split(virshList, "\n") {
		if strings.Contains(line, vmName) && strings.Contains(line, "running") {
			return true
		}
	}
	return false
}

// StartInstallStatusTicker logs ongoing status updates every 10s for disk size, VM state, and DHCP IPs.
func StartInstallStatusTicker(ctx context.Context, log *zap.Logger, vmName, diskPath string) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.Info("⌛ Installation still in progress...")

			// Disk size
			if fi, err := os.Stat(diskPath); err == nil {
				log.Info(" Disk image size", zap.String("path", diskPath), zap.Int64("bytes", fi.Size()))
			} else {
				log.Warn("Failed to stat disk image", zap.String("path", diskPath), zap.Error(err))
			}

			// VM power state
			if out, err := exec.Command("virsh", "dominfo", vmName).Output(); err == nil {
				state := parseDominfoState(out)
				log.Info(" VM state", zap.String("vm", vmName), zap.String("state", state))
			} else {
				log.Warn("Failed to get dominfo", zap.String("vm", vmName), zap.Error(err))
			}

			// DHCP leases
			if ip, err := parseDHCPIP(vmName); err == nil && ip != "" {
				log.Info("🌐 DHCP lease detected", zap.String("vm", vmName), zap.String("ip", ip))
			} else if err != nil {
				log.Debug("No DHCP lease yet", zap.String("vm", vmName), zap.Error(err))
			}
		}
	}
}

// parseDominfoState extracts the "State:" line from virsh dominfo output
func parseDominfoState(output []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if bytes.HasPrefix([]byte(line), []byte("State:")) {
			return line[7:]
		}
	}
	return "unknown"
}

// parseDHCPIP tries to find a matching MAC or IP for the VM (placeholder logic)
// parseDHCPIP finds the IP address by matching the MAC of a given VM
func parseDHCPIP(vmName string) (string, error) {
	// Step 1: Get MAC from domiflist
	out, err := exec.Command("virsh", "domiflist", vmName).Output()
	if err != nil {
		return "", fmt.Errorf("failed to get MAC: %w", err)
	}

	var macAddr string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 5 && strings.HasPrefix(fields[0], "vnet") {
			macAddr = fields[4]
			break
		}
	}
	if macAddr == "" {
		return "", fmt.Errorf("MAC address not found for VM: %s", vmName)
	}

	// Step 2: Match MAC in virsh net-dhcp-leases
	leasesOut, err := exec.Command("virsh", "net-dhcp-leases", "default").Output()
	if err != nil {
		return "", fmt.Errorf("failed to get DHCP leases: %w", err)
	}

	scanner = bufio.NewScanner(bytes.NewReader(leasesOut))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, macAddr) {
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				return strings.Split(fields[3], "/")[0], nil
			}
		}
	}

	return "", fmt.Errorf("no IP lease found for MAC %s", macAddr)
}
