// pkg/consul/helpers.go
// Utility helper functions for Consul installation

package consul

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// File operations

func (ci *ConsulInstaller) writeFile(path string, content []byte, mode os.FileMode) error {
	return os.WriteFile(path, content, mode)
}

func (ci *ConsulInstaller) fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (ci *ConsulInstaller) createDirectory(path string, mode os.FileMode) error {
	// CRITICAL: Check if path is on network mount before creating
	// Network mounts can cause data loss during network outages
	isNetwork, err := isNetworkMount(path)
	if err != nil {
		ci.logger.Warn("Could not check if path is on network mount",
			zap.String("path", path),
			zap.Error(err))
	} else if isNetwork {
		return fmt.Errorf("refusing to create directory on network mount: %s\nNetwork mounts can cause data loss during outages. Use local storage for Consul data.", path)
	}

	if err := os.MkdirAll(path, mode); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", path, err)
	}

	ci.logger.Info("Created directory",
		zap.String("path", path),
		zap.String("mode", mode.String()))

	return nil
}

// HTTP operations

// httpGet performs HTTP GET request with proper error wrapping and context handling
func (ci *ConsulInstaller) httpGet(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ci.rc.Ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return body, nil
}

// Network detection

// getDefaultBindAddr detects the primary network interface IP
// Returns error if no valid interface found (fail-closed)
func getDefaultBindAddr() (string, error) {
	cmd := exec.Command("hostname", "-I")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to detect network interfaces: %w", err)
	}

	// Get first non-loopback IP
	ips := strings.Fields(string(output))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip != "" && !strings.HasPrefix(ip, "127.") && !strings.HasPrefix(ip, "::1") {
			return ip, nil
		}
	}

	return "", fmt.Errorf("no valid network interface found (only loopback detected)")
}

// isNetworkMount checks if a path is on a network filesystem
func isNetworkMount(path string) (bool, error) {
	// Get absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}

	// Get filesystem type
	var stat unix.Statfs_t
	if err := unix.Statfs(absPath, &stat); err != nil {
		return false, err
	}

	// Check for network filesystem types
	// NFS: 0x6969, CIFS: 0xFF534D42, etc.
	networkFsTypes := map[int64]string{
		0x6969:     "NFS",
		0xFF534D42: "CIFS/SMB",
		0x01021994: "TMPFS", // Not network but also problematic for persistent data
	}

	fsType := int64(stat.Type)
	if fsName, isNetwork := networkFsTypes[fsType]; isNetwork {
		return true, fmt.Errorf("filesystem type: %s", fsName)
	}

	return false, nil
}

// Logrotate configuration

// createLogrotateConfig creates a logrotate configuration for Consul logs
func (ci *ConsulInstaller) createLogrotateConfig() error {
	logrotateConfig := `/var/log/consul/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 consul consul
    sharedscripts
    postrotate
        systemctl reload consul > /dev/null 2>&1 || true
    endscript
}
`

	if err := ci.writeFile("/etc/logrotate.d/consul", []byte(logrotateConfig), 0644); err != nil {
		return fmt.Errorf("failed to create logrotate config: %w", err)
	}

	ci.logger.Info("Created logrotate configuration")
	return nil
}
