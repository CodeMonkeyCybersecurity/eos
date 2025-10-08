// pkg/consul/helpers/network.go
// Network utilities for Consul installation

package helpers

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NetworkHelper provides network-related utilities
type NetworkHelper struct {
	rc     *eos_io.RuntimeContext
	logger otelzap.LoggerWithCtx
}

// NewNetworkHelper creates a new network helper
func NewNetworkHelper(rc *eos_io.RuntimeContext) *NetworkHelper {
	return &NetworkHelper{
		rc:     rc,
		logger: otelzap.Ctx(rc.Ctx),
	}
}

// GetDefaultBindAddr detects the primary network interface IP
// Returns error if no valid interface found (fail-closed)
func (nh *NetworkHelper) GetDefaultBindAddr() (string, error) {
	nh.logger.Info("Detecting default bind address")

	cmd := exec.Command("hostname", "-I")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("hostname -I failed: %w", err)
	}

	ips := strings.Fields(string(output))
	if len(ips) == 0 {
		return "", fmt.Errorf("no network interfaces detected")
	}

	// Filter out loopback and link-local addresses
	for _, ip := range ips {
		if !strings.HasPrefix(ip, "127.") && !strings.HasPrefix(ip, "169.254.") {
			nh.logger.Info("Detected bind address",
				zap.String("ip", ip))
			return ip, nil
		}
	}

	return "", fmt.Errorf("only loopback/link-local addresses found - no routable interface detected")
}

// IsNetworkMount checks if a path is on a network-mounted filesystem
// Network mounts (NFS, CIFS/SMB, etc.) can cause data loss during network outages
func (nh *NetworkHelper) IsNetworkMount(path string) (bool, error) {
	nh.logger.Debug("Checking if path is on network mount",
		zap.String("path", path))

	// Check if findmnt is available
	if _, err := exec.LookPath("findmnt"); err != nil {
		// findmnt not found, fall back to /proc/mounts parsing
		return nh.isNetworkMountFromProcMounts(path)
	}

	// Use findmnt to check mount point type
	cmd := exec.Command("findmnt", "-n", "-o", "FSTYPE", "-T", path)
	output, err := cmd.Output()
	if err != nil {
		// findmnt failed, fall back to /proc/mounts
		return nh.isNetworkMountFromProcMounts(path)
	}

	fsType := strings.TrimSpace(string(output))

	// Network filesystem types
	networkFS := []string{
		"nfs", "nfs4", "nfs3",     // NFS
		"cifs", "smb", "smbfs",    // CIFS/SMB
		"glusterfs",               // GlusterFS
		"ceph", "cephfs",          // Ceph
		"9p",                      // Plan 9 (QEMU shared folders)
		"fuse.sshfs",              // SSHFS
		"davfs", "fuse.davfs2",    // WebDAV
	}

	for _, nfs := range networkFS {
		if fsType == nfs {
			nh.logger.Warn("Path is on network mount",
				zap.String("path", path),
				zap.String("fstype", fsType))
			return true, nil
		}
	}

	return false, nil
}

// isNetworkMountFromProcMounts checks if a path is on a network mount by parsing /proc/mounts
func (nh *NetworkHelper) isNetworkMountFromProcMounts(path string) (bool, error) {
	// Read /proc/mounts
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		// Cannot check, assume not a network mount (fail open for local systems)
		return false, nil
	}

	// Get absolute path to check
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}

	// Network filesystem types
	networkFS := map[string]bool{
		"nfs":       true,
		"nfs4":      true,
		"nfs3":      true,
		"cifs":      true,
		"smb":       true,
		"smbfs":     true,
		"glusterfs": true,
		"ceph":      true,
		"cephfs":    true,
		"9p":        true,
		"davfs":     true,
	}

	// Parse /proc/mounts (format: device mountpoint fstype options freq passno)
	lines := strings.Split(string(data), "\n")
	var longestMatch string
	var longestMatchFS string

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		mountPoint := fields[1]
		fsType := fields[2]

		// Check if path is under this mount point
		if strings.HasPrefix(absPath, mountPoint) {
			// Keep track of longest matching mount point (most specific)
			if len(mountPoint) > len(longestMatch) {
				longestMatch = mountPoint
				longestMatchFS = fsType
			}
		}
	}

	// Check if the filesystem type is a network filesystem
	if networkFS[longestMatchFS] {
		nh.logger.Warn("Path is on network mount (detected via /proc/mounts)",
			zap.String("path", path),
			zap.String("fstype", longestMatchFS),
			zap.String("mountpoint", longestMatch))
		return true, nil
	}

	return false, nil
}

// FindConsulProcesses checks for running Consul processes not managed by systemd
// Returns list of PIDs for rogue processes
func (nh *NetworkHelper) FindConsulProcesses() ([]string, error) {
	nh.logger.Debug("Checking for rogue Consul processes")

	// Use pgrep to find processes with "consul" in command line
	cmd := exec.Command("pgrep", "-f", "consul agent")
	output, err := cmd.Output()
	if err != nil {
		// Exit code 1 means no processes found (expected)
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return []string{}, nil
		}
		return nil, fmt.Errorf("pgrep failed: %w", err)
	}

	// Parse PIDs from output
	pids := strings.Fields(strings.TrimSpace(string(output)))
	if len(pids) == 0 {
		return []string{}, nil
	}

	// Get systemd's main PID to exclude it
	systemdPID := ""
	cmd = exec.Command("systemctl", "show", "--property=MainPID", "consul")
	if output, err := cmd.Output(); err == nil {
		// Parse "MainPID=1234"
		parts := strings.Split(strings.TrimSpace(string(output)), "=")
		if len(parts) == 2 && parts[1] != "0" {
			systemdPID = parts[1]
		}
	}

	// Filter out systemd-managed process
	roguePIDs := []string{}
	for _, pid := range pids {
		if pid != systemdPID && pid != "0" {
			roguePIDs = append(roguePIDs, pid)
		}
	}

	if len(roguePIDs) > 0 {
		nh.logger.Warn("Found rogue Consul processes",
			zap.Strings("pids", roguePIDs))
	}

	return roguePIDs, nil
}

// GetUbuntuCodename returns the Ubuntu codename for APT repository
func (nh *NetworkHelper) GetUbuntuCodename() string {
	cmd := exec.Command("lsb_release", "-cs")
	output, err := cmd.Output()
	if err != nil {
		nh.logger.Warn("Failed to detect Ubuntu codename, using default",
			zap.Error(err))
		return "noble" // Default to latest LTS
	}

	codename := strings.TrimSpace(string(output))
	nh.logger.Debug("Detected Ubuntu codename",
		zap.String("codename", codename))

	return codename
}
