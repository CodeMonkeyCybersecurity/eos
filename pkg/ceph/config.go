// pkg/ceph/config.go
package ceph

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CephConfig represents the parsed ceph.conf file
type CephConfig struct {
	Global CephGlobalConfig
	Mon    CephMonConfig
	OSD    CephOSDConfig
	Client CephClientConfig
}

// CephGlobalConfig represents the [global] section
type CephGlobalConfig struct {
	FSID                  string
	MonInitialMembers     string
	MonHost               string
	PublicNetwork         string
	ClusterNetwork        string
	AuthClusterRequired   string
	AuthServiceRequired   string
	AuthClientRequired    string
	OSDJournalSize        string
	OSDPoolDefaultSize    string
	OSDPoolDefaultMinSize string
	OSDPoolDefaultPGNum   string
	OSDPoolDefaultPGPNum  string
}

// CephMonConfig represents the [mon] section
type CephMonConfig struct {
	MonAllowPoolDelete string
}

// CephOSDConfig represents the [osd] section
type CephOSDConfig struct {
	OSDMkfsType        string
	OSDMkfsOptionsXFS  string
	OSDMountOptionsXFS string
}

// CephClientConfig represents the [client] section
type CephClientConfig struct {
	RBDCache                       string
	RBDCacheWritethroughUntilFlush string
}

// ReadCephConf parses /etc/ceph/ceph.conf and returns structured config
func ReadCephConf(logger otelzap.LoggerWithCtx) (*CephConfig, error) {
	return ReadCephConfFromPath(logger, "/etc/ceph/ceph.conf")
}

// ReadCephConfFromPath parses a ceph.conf file from specified path
func ReadCephConfFromPath(logger otelzap.LoggerWithCtx, path string) (*CephConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open ceph.conf: %w", err)
	}
	defer file.Close()

	config := &CephConfig{}
	var currentSection string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Check for section headers
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}

		// Parse key-value pairs
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Assign to appropriate section
		switch currentSection {
		case "global":
			parseGlobalConfig(&config.Global, key, value)
		case "mon":
			parseMonConfig(&config.Mon, key, value)
		case "osd":
			parseOSDConfig(&config.OSD, key, value)
		case "client":
			parseClientConfig(&config.Client, key, value)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading ceph.conf: %w", err)
	}

	logger.Debug("Parsed ceph.conf",
		zap.String("fsid", config.Global.FSID),
		zap.String("mon_host", config.Global.MonHost))

	return config, nil
}

// parseGlobalConfig assigns global section key-value pairs
func parseGlobalConfig(global *CephGlobalConfig, key, value string) {
	switch strings.ReplaceAll(key, " ", "_") {
	case "fsid":
		global.FSID = value
	case "mon_initial_members":
		global.MonInitialMembers = value
	case "mon_host":
		global.MonHost = value
	case "public_network":
		global.PublicNetwork = value
	case "cluster_network":
		global.ClusterNetwork = value
	case "auth_cluster_required":
		global.AuthClusterRequired = value
	case "auth_service_required":
		global.AuthServiceRequired = value
	case "auth_client_required":
		global.AuthClientRequired = value
	case "osd_journal_size":
		global.OSDJournalSize = value
	case "osd_pool_default_size":
		global.OSDPoolDefaultSize = value
	case "osd_pool_default_min_size":
		global.OSDPoolDefaultMinSize = value
	case "osd_pool_default_pg_num":
		global.OSDPoolDefaultPGNum = value
	case "osd_pool_default_pgp_num":
		global.OSDPoolDefaultPGPNum = value
	}
}

// parseMonConfig assigns mon section key-value pairs
func parseMonConfig(mon *CephMonConfig, key, value string) {
	switch strings.ReplaceAll(key, " ", "_") {
	case "mon_allow_pool_delete":
		mon.MonAllowPoolDelete = value
	}
}

// parseOSDConfig assigns osd section key-value pairs
func parseOSDConfig(osd *CephOSDConfig, key, value string) {
	switch strings.ReplaceAll(key, " ", "_") {
	case "osd_mkfs_type":
		osd.OSDMkfsType = value
	case "osd_mkfs_options_xfs":
		osd.OSDMkfsOptionsXFS = value
	case "osd_mount_options_xfs":
		osd.OSDMountOptionsXFS = value
	}
}

// parseClientConfig assigns client section key-value pairs
func parseClientConfig(client *CephClientConfig, key, value string) {
	switch strings.ReplaceAll(key, " ", "_") {
	case "rbd_cache":
		client.RBDCache = value
	case "rbd_cache_writethrough_until_flush":
		client.RBDCacheWritethroughUntilFlush = value
	}
}

// ValidateCephConf validates that ceph.conf has required fields for cluster operation
func ValidateCephConf(logger otelzap.LoggerWithCtx, config *CephConfig) error {
	var errors []string

	// Critical fields that MUST be present
	if config.Global.FSID == "" {
		errors = append(errors, "fsid is missing in [global] section")
	}
	if config.Global.MonHost == "" {
		errors = append(errors, "mon host is missing in [global] section")
	}
	if config.Global.PublicNetwork == "" {
		logger.Warn("public network not specified - Ceph will auto-detect (may be incorrect)")
	}

	// Validate FSID format (should be UUID)
	if config.Global.FSID != "" {
		parts := strings.Split(config.Global.FSID, "-")
		if len(parts) != 5 {
			errors = append(errors, fmt.Sprintf("fsid '%s' is not a valid UUID format", config.Global.FSID))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("ceph.conf validation failed:\n  - %s", strings.Join(errors, "\n  - "))
	}

	logger.Debug("✓ ceph.conf validation passed")
	return nil
}

// GetMonitorHosts parses the mon_host configuration and returns list of monitor addresses
func GetMonitorHosts(config *CephConfig) []string {
	// mon_host can be in multiple formats:
	// - Simple: "192.168.1.10,192.168.1.11,192.168.1.12"
	// - v2/v1: "[v2:192.168.1.10:3300/0,v1:192.168.1.10:6789/0]"
	// - Mixed: "192.168.1.10:6789,192.168.1.11:6789"

	monHost := config.Global.MonHost
	if monHost == "" {
		return []string{}
	}

	// Remove brackets if present
	monHost = strings.Trim(monHost, "[]")

	// Split by comma
	hosts := strings.Split(monHost, ",")

	// Extract IPs (handle v2:/v1: prefixes)
	var ips []string
	for _, host := range hosts {
		host = strings.TrimSpace(host)

		// Remove v2: or v1: prefix
		if strings.Contains(host, ":") {
			parts := strings.Split(host, ":")
			if len(parts) >= 2 && (parts[0] == "v2" || parts[0] == "v1") {
				// Format: v2:192.168.1.10:3300/0
				host = parts[1]
			} else {
				// Format: 192.168.1.10:6789
				host = parts[0]
			}
		}

		// Remove /0 suffix if present
		host = strings.Split(host, "/")[0]

		if host != "" {
			ips = append(ips, host)
		}
	}

	return ips
}

// WriteCephConf writes a ceph.conf file (used during bootstrap)
// Note: This is handled by bootstrap.go:createCephConf for actual bootstrap
// This function provides a way to update existing config
func WriteCephConf(logger otelzap.LoggerWithCtx, config *CephConfig, path string) error {
	content := formatCephConf(config)

	// Backup existing config
	if _, err := os.Stat(path); err == nil {
		backupPath := path + ".backup"
		logger.Info("Backing up existing ceph.conf", zap.String("backup", backupPath))
		if err := os.Rename(path, backupPath); err != nil {
			return fmt.Errorf("failed to backup existing ceph.conf: %w", err)
		}
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write ceph.conf: %w", err)
	}

	logger.Info("Wrote ceph.conf", zap.String("path", path))
	return nil
}

// formatCephConf formats a CephConfig struct into INI-style ceph.conf content
func formatCephConf(config *CephConfig) string {
	var sb strings.Builder

	// [global] section
	sb.WriteString("[global]\n")
	if config.Global.FSID != "" {
		sb.WriteString(fmt.Sprintf("fsid = %s\n", config.Global.FSID))
	}
	if config.Global.MonInitialMembers != "" {
		sb.WriteString(fmt.Sprintf("mon initial members = %s\n", config.Global.MonInitialMembers))
	}
	if config.Global.MonHost != "" {
		sb.WriteString(fmt.Sprintf("mon host = %s\n", config.Global.MonHost))
	}
	if config.Global.PublicNetwork != "" {
		sb.WriteString(fmt.Sprintf("public network = %s\n", config.Global.PublicNetwork))
	}
	if config.Global.ClusterNetwork != "" {
		sb.WriteString(fmt.Sprintf("cluster network = %s\n", config.Global.ClusterNetwork))
	}
	if config.Global.AuthClusterRequired != "" {
		sb.WriteString(fmt.Sprintf("auth cluster required = %s\n", config.Global.AuthClusterRequired))
	}
	if config.Global.AuthServiceRequired != "" {
		sb.WriteString(fmt.Sprintf("auth service required = %s\n", config.Global.AuthServiceRequired))
	}
	if config.Global.AuthClientRequired != "" {
		sb.WriteString(fmt.Sprintf("auth client required = %s\n", config.Global.AuthClientRequired))
	}
	sb.WriteString("\n")

	// [mon] section
	if config.Mon.MonAllowPoolDelete != "" {
		sb.WriteString("[mon]\n")
		sb.WriteString(fmt.Sprintf("mon allow pool delete = %s\n", config.Mon.MonAllowPoolDelete))
		sb.WriteString("\n")
	}

	// [osd] section
	if config.OSD.OSDMkfsType != "" {
		sb.WriteString("[osd]\n")
		sb.WriteString(fmt.Sprintf("osd mkfs type = %s\n", config.OSD.OSDMkfsType))
		if config.OSD.OSDMkfsOptionsXFS != "" {
			sb.WriteString(fmt.Sprintf("osd mkfs options xfs = %s\n", config.OSD.OSDMkfsOptionsXFS))
		}
		if config.OSD.OSDMountOptionsXFS != "" {
			sb.WriteString(fmt.Sprintf("osd mount options xfs = %s\n", config.OSD.OSDMountOptionsXFS))
		}
		sb.WriteString("\n")
	}

	// [client] section
	if config.Client.RBDCache != "" {
		sb.WriteString("[client]\n")
		sb.WriteString(fmt.Sprintf("rbd cache = %s\n", config.Client.RBDCache))
		if config.Client.RBDCacheWritethroughUntilFlush != "" {
			sb.WriteString(fmt.Sprintf("rbd cache writethrough until flush = %s\n", config.Client.RBDCacheWritethroughUntilFlush))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
