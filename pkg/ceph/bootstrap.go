// pkg/ceph/bootstrap.go
package ceph

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/google/uuid"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// BootstrapConfig contains configuration for bootstrapping a Ceph monitor
type BootstrapConfig struct {
	Hostname      string // Monitor hostname (e.g., "vhost5")
	MonitorIP     string // Monitor IP address (e.g., "192.168.6.77")
	PublicNetwork string // Public network CIDR (e.g., "192.168.6.0/24")
	ClusterNetwork string // Cluster network CIDR (optional, defaults to PublicNetwork)
	ClusterName   string // Cluster name (default: "ceph")
	FSID          string // Cluster UUID (generated if empty)
}

// BootstrapState tracks bootstrap progress for resumability
type BootstrapState string

const (
	StateUninitialized       BootstrapState = "uninitialized"
	StateFSIDGenerated       BootstrapState = "fsid_generated"
	StateConfigWritten       BootstrapState = "config_written"
	StateKeyringsCreated     BootstrapState = "keyrings_created"
	StateMonmapGenerated     BootstrapState = "monmap_generated"
	StateMonitorInitialized  BootstrapState = "monitor_initialized"
	StateOwnershipFixed      BootstrapState = "ownership_fixed"
	StateMonitorStarted      BootstrapState = "monitor_started"
	StateBootstrapComplete   BootstrapState = "complete"
)

// BootstrapStateData contains state data for resumption
type BootstrapStateData struct {
	State          BootstrapState     `json:"state"`
	Config         *BootstrapConfig   `json:"config"`
	Timestamp      time.Time          `json:"timestamp"`
	CompletedSteps []string           `json:"completed_steps"`
}

// BootstrapFirstMonitor creates a new Ceph cluster with the first monitor
// This implements the official Ceph manual deployment bootstrap process
// See: https://docs.ceph.com/en/latest/install/manual-deployment/
func BootstrapFirstMonitor(rc *eos_io.RuntimeContext, config *BootstrapConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("================================================================================")
	logger.Info("Ceph Monitor Bootstrap - Creating First Monitor")
	logger.Info("================================================================================")
	logger.Info("")

	// Set defaults
	if config.ClusterName == "" {
		config.ClusterName = "ceph"
	}
	if config.ClusterNetwork == "" {
		config.ClusterNetwork = config.PublicNetwork
	}

	logger.Info("Bootstrap configuration",
		zap.String("hostname", config.Hostname),
		zap.String("monitor_ip", config.MonitorIP),
		zap.String("public_network", config.PublicNetwork),
		zap.String("cluster_name", config.ClusterName))

	// ASSESS: Pre-flight checks
	logger.Info("Step 1: Running pre-flight validation...")
	if err := validateBootstrapPreconditions(logger, config); err != nil {
		return fmt.Errorf("pre-flight validation failed: %w", err)
	}
	logger.Info("✓ Pre-flight validation passed")
	logger.Info("")

	// INTERVENE: Execute bootstrap sequence
	logger.Info("Step 2: Generating cluster identity...")
	if config.FSID == "" {
		config.FSID = uuid.New().String()
		logger.Info("Generated cluster FSID", zap.String("fsid", config.FSID))
	} else {
		logger.Info("Using provided FSID", zap.String("fsid", config.FSID))
	}
	logger.Info("")

	logger.Info("Step 3: Creating cluster configuration...")
	if err := createCephConf(logger, config); err != nil {
		return fmt.Errorf("failed to create ceph.conf: %w", err)
	}
	logger.Info("✓ Created /etc/ceph/ceph.conf")
	logger.Info("")

	logger.Info("Step 4: Creating monitor keyrings...")
	monKeyring, cleanup, err := createMonitorKeyrings(logger, config)
	if err != nil {
		return fmt.Errorf("failed to create keyrings: %w", err)
	}
	defer cleanup() // Clean up temporary keyring
	logger.Info("✓ Created all required keyrings")
	logger.Info("")

	logger.Info("Step 5: Generating monitor map...")
	monmapPath, err := generateMonmap(logger, config)
	if err != nil {
		return fmt.Errorf("failed to generate monmap: %w", err)
	}
	defer os.Remove(monmapPath) // Clean up temporary monmap
	logger.Info("✓ Generated monmap", zap.String("path", monmapPath))
	logger.Info("")

	logger.Info("Step 6: Initializing monitor database...")
	if err := mkfsMonitor(logger, config, monKeyring, monmapPath); err != nil {
		return fmt.Errorf("failed to initialize monitor: %w", err)
	}
	logger.Info("✓ Monitor database initialized")
	logger.Info("")

	logger.Info("Step 7: Fixing ownership and permissions...")
	if err := fixMonitorOwnership(logger, config); err != nil {
		return fmt.Errorf("failed to fix ownership: %w", err)
	}
	logger.Info("✓ Ownership and permissions corrected")
	logger.Info("")

	logger.Info("Step 8: Starting monitor service...")
	if err := startMonitorService(logger, config); err != nil {
		return fmt.Errorf("failed to start monitor: %w", err)
	}
	logger.Info("✓ Monitor service started")
	logger.Info("")

	// EVALUATE: Verify monitor health
	logger.Info("Step 9: Verifying monitor health...")
	if err := verifyMonitorHealth(logger, config); err != nil {
		logger.Warn("Monitor health check failed (may be transient)", zap.Error(err))
		logger.Info("  → Monitor may need a few seconds to form quorum")
		logger.Info("  → Verify manually with: ceph -s")
	} else {
		logger.Info("✓ Monitor is healthy and quorum is formed")
	}
	logger.Info("")

	logger.Info("================================================================================")
	logger.Info("Bootstrap Complete!")
	logger.Info("================================================================================")
	logger.Info("")
	logger.Info("Next steps:")
	logger.Info("  1. Verify cluster status: ceph -s")
	logger.Info("  2. Add more monitors (for HA): eos create ceph-mon --host <hostname>")
	logger.Info("  3. Add OSDs: ceph-volume lvm create --data /dev/<device>")
	logger.Info("  4. Add manager: systemctl start ceph-mgr@<hostname>")
	logger.Info("")
	logger.Info(fmt.Sprintf("Cluster FSID: %s", config.FSID))
	logger.Info(fmt.Sprintf("Monitor name: %s", config.Hostname))
	logger.Info(fmt.Sprintf("Monitor address: %s", config.MonitorIP))
	logger.Info("")

	return nil
}

// validateBootstrapPreconditions performs comprehensive pre-flight checks
func validateBootstrapPreconditions(logger otelzap.LoggerWithCtx, config *BootstrapConfig) error {
	// 1. Check if cluster already reachable (prevent split-brain)
	logger.Debug("Checking if cluster is already reachable...")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ceph", "status", "--connect-timeout=1")
	if err := cmd.Run(); err == nil {
		return fmt.Errorf("cluster already reachable - refusing to bootstrap (split-brain risk). If this is intentional, stop the existing cluster first")
	}
	logger.Debug("✓ No existing cluster detected")

	// 2. Check if monitor data already exists
	logger.Debug("Checking for existing monitor data...")
	monDataDir := filepath.Join("/var/lib/ceph/mon", fmt.Sprintf("%s-%s", config.ClusterName, config.Hostname))
	if _, err := os.Stat(monDataDir); err == nil {
		return fmt.Errorf("monitor data directory %s already exists - manual cleanup required. Run: sudo rm -rf %s", monDataDir, monDataDir)
	}
	logger.Debug("✓ No existing monitor data")

	// 3. Validate required configuration
	if config.Hostname == "" {
		return fmt.Errorf("hostname is required")
	}
	if config.MonitorIP == "" {
		return fmt.Errorf("monitor IP address is required")
	}
	if config.PublicNetwork == "" {
		return fmt.Errorf("public network CIDR is required (e.g., 192.168.1.0/24)")
	}

	// 4. Check if ceph user exists
	logger.Debug("Checking for ceph user...")
	cephUser, err := user.Lookup("ceph")
	if err != nil {
		return fmt.Errorf("ceph user does not exist - install ceph-common package first: sudo apt install ceph-common")
	}
	logger.Debug("✓ Ceph user exists", zap.String("uid", cephUser.Uid), zap.String("gid", cephUser.Gid))

	// 5. Verify required directories exist with correct ownership
	logger.Debug("Checking required directories...")
	requiredDirs := []string{
		"/var/lib/ceph",
		"/var/lib/ceph/mon",
		"/var/lib/ceph/bootstrap-osd",
		"/var/lib/ceph/bootstrap-mgr",
		"/var/lib/ceph/bootstrap-mds",
		"/var/lib/ceph/bootstrap-rgw",
		"/etc/ceph",
	}

	for _, dir := range requiredDirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}

		// Ensure ceph user owns it
		if err := os.Chown(dir, mustAtoi(cephUser.Uid), mustAtoi(cephUser.Gid)); err != nil {
			logger.Warn("Failed to chown directory (continuing anyway)", zap.String("dir", dir), zap.Error(err))
		}
	}
	logger.Debug("✓ Required directories exist")

	// 6. Check for required binaries
	logger.Debug("Checking for required binaries...")
	requiredBinaries := []string{"ceph-mon", "ceph-authtool", "monmaptool"}
	for _, bin := range requiredBinaries {
		if _, err := exec.LookPath(bin); err != nil {
			return fmt.Errorf("required binary '%s' not found - install ceph-mon package: sudo apt install ceph-mon", bin)
		}
	}
	logger.Debug("✓ Required binaries present")

	return nil
}

// createCephConf creates the initial /etc/ceph/ceph.conf
func createCephConf(logger otelzap.LoggerWithCtx, config *BootstrapConfig) error {
	confContent := fmt.Sprintf(`[global]
fsid = %s
mon initial members = %s
mon host = %s
public network = %s
cluster network = %s
auth cluster required = cephx
auth service required = cephx
auth client required = cephx
osd journal size = 1024
osd pool default size = 3
osd pool default min size = 2
osd pool default pg num = 128
osd pool default pgp num = 128
osd crush chooseleaf type = 1
mon allow pool delete = false
mon max pg per osd = 300

[mon]
mon allow pool delete = false

[osd]
osd mkfs type = xfs
osd mkfs options xfs = -f -i size=2048
osd mount options xfs = rw,noatime,inode64,logbufs=8,logbsize=256k,largeio,swalloc

[client]
rbd cache = true
rbd cache writethrough until flush = true
`, config.FSID, config.Hostname, config.MonitorIP, config.PublicNetwork, config.ClusterNetwork)

	confPath := "/etc/ceph/ceph.conf"

	// Backup existing config if present
	if _, err := os.Stat(confPath); err == nil {
		backupPath := confPath + ".backup." + time.Now().Format("20060102-150405")
		logger.Info("Backing up existing ceph.conf", zap.String("backup", backupPath))
		if err := os.Rename(confPath, backupPath); err != nil {
			return fmt.Errorf("failed to backup existing ceph.conf: %w", err)
		}
	}

	if err := os.WriteFile(confPath, []byte(confContent), 0644); err != nil {
		return fmt.Errorf("failed to write ceph.conf: %w", err)
	}

	logger.Debug("Created ceph.conf", zap.String("path", confPath))
	return nil
}

// createMonitorKeyrings creates all required keyrings for bootstrap
func createMonitorKeyrings(logger otelzap.LoggerWithCtx, config *BootstrapConfig) (string, func(), error) {
	// Create temporary monitor keyring
	monKeyring, err := createSecureKeyring("mon")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create monitor keyring: %w", err)
	}

	cleanup := func() {
		os.Remove(monKeyring)
		logger.Debug("Cleaned up temporary monitor keyring", zap.String("path", monKeyring))
	}

	// 1. Create monitor keyring
	logger.Debug("Creating monitor keyring...")
	cmd := exec.Command("ceph-authtool", "--create-keyring", monKeyring,
		"--gen-key", "-n", "mon.", "--cap", "mon", "allow *")
	if output, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("failed to create monitor keyring: %s", output)
	}

	// 2. Create admin keyring
	logger.Debug("Creating admin keyring...")
	adminKeyring := "/etc/ceph/ceph.client.admin.keyring"
	cmd = exec.Command("ceph-authtool", "--create-keyring", adminKeyring,
		"--gen-key", "-n", "client.admin",
		"--cap", "mon", "allow *",
		"--cap", "osd", "allow *",
		"--cap", "mds", "allow *",
		"--cap", "mgr", "allow *")
	if output, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("failed to create admin keyring: %s", output)
	}

	// 3. Create bootstrap keyrings
	bootstrapKeyrings := map[string]string{
		"bootstrap-osd": "profile bootstrap-osd",
		"bootstrap-mgr": "profile bootstrap-mgr",
		"bootstrap-mds": "profile bootstrap-mds",
		"bootstrap-rgw": "profile bootstrap-rgw",
	}

	for bootstrap, profile := range bootstrapKeyrings {
		logger.Debug("Creating " + bootstrap + " keyring...")
		keyringPath := filepath.Join("/var/lib/ceph", bootstrap, config.ClusterName+".keyring")
		cmd = exec.Command("ceph-authtool", "--create-keyring", keyringPath,
			"--gen-key", "-n", "client."+bootstrap,
			"--cap", "mon", profile,
			"--cap", "mgr", "allow r")
		if output, err := cmd.CombinedOutput(); err != nil {
			logger.Warn("Failed to create "+bootstrap+" keyring (continuing)", zap.String("error", string(output)))
			// Don't fail bootstrap for optional keyrings
		}
	}

	// 4. Import admin and bootstrap keyrings into monitor keyring
	logger.Debug("Importing keyrings into monitor keyring...")
	cmd = exec.Command("ceph-authtool", monKeyring, "--import-keyring", adminKeyring)
	if output, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("failed to import admin keyring: %s", output)
	}

	// Import bootstrap keyrings (best effort)
	for bootstrap := range bootstrapKeyrings {
		keyringPath := filepath.Join("/var/lib/ceph", bootstrap, config.ClusterName+".keyring")
		cmd = exec.Command("ceph-authtool", monKeyring, "--import-keyring", keyringPath)
		if _, err := cmd.CombinedOutput(); err != nil {
			logger.Debug("Skipped importing " + bootstrap + " keyring (not critical)")
		}
	}

	return monKeyring, cleanup, nil
}

// createSecureKeyring creates a temporary keyring with secure permissions
func createSecureKeyring(name string) (string, error) {
	tmpFile, err := os.CreateTemp("", fmt.Sprintf("ceph-%s-*.keyring", name))
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}

	keyringPath := tmpFile.Name()
	tmpFile.Close()

	// Set restrictive permissions (owner read/write only)
	if err := os.Chmod(keyringPath, 0600); err != nil {
		os.Remove(keyringPath)
		return "", fmt.Errorf("failed to set permissions: %w", err)
	}

	return keyringPath, nil
}

// generateMonmap creates the initial monitor map
func generateMonmap(logger otelzap.LoggerWithCtx, config *BootstrapConfig) (string, error) {
	// Create temporary monmap file
	tmpFile, err := os.CreateTemp("", "monmap-")
	if err != nil {
		return "", fmt.Errorf("failed to create temp monmap: %w", err)
	}
	monmapPath := tmpFile.Name()
	tmpFile.Close()

	logger.Debug("Generating monmap...",
		zap.String("hostname", config.Hostname),
		zap.String("ip", config.MonitorIP),
		zap.String("fsid", config.FSID))

	cmd := exec.Command("monmaptool", "--create",
		"--add", config.Hostname, config.MonitorIP,
		"--fsid", config.FSID,
		monmapPath)

	if output, err := cmd.CombinedOutput(); err != nil {
		os.Remove(monmapPath)
		return "", fmt.Errorf("failed to generate monmap: %s", output)
	}

	// Verify monmap was created
	if _, err := os.Stat(monmapPath); err != nil {
		return "", fmt.Errorf("monmap file not created: %w", err)
	}

	return monmapPath, nil
}

// mkfsMonitor initializes the monitor database
func mkfsMonitor(logger otelzap.LoggerWithCtx, config *BootstrapConfig, monKeyring, monmapPath string) error {
	monDataDir := filepath.Join("/var/lib/ceph/mon", fmt.Sprintf("%s-%s", config.ClusterName, config.Hostname))

	// Create monitor data directory
	logger.Debug("Creating monitor data directory", zap.String("path", monDataDir))
	if err := os.MkdirAll(monDataDir, 0755); err != nil {
		return fmt.Errorf("failed to create monitor data directory: %w", err)
	}

	// Get ceph user for running as ceph
	cephUser, err := user.Lookup("ceph")
	if err != nil {
		return fmt.Errorf("ceph user not found: %w", err)
	}

	// Initialize monitor database
	logger.Debug("Initializing monitor database (this may take a moment)...")
	cmd := exec.Command("sudo", "-u", "ceph",
		"ceph-mon", "--cluster", config.ClusterName,
		"--mkfs", "-i", config.Hostname,
		"--monmap", monmapPath,
		"--keyring", monKeyring)

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to initialize monitor database: %s", output)
	}

	// Verify monitor database was created
	storeDB := filepath.Join(monDataDir, "store.db")
	if _, err := os.Stat(storeDB); err != nil {
		return fmt.Errorf("monitor database not created: %w", err)
	}

	// Set ownership to ceph user
	if err := chownRecursive(monDataDir, mustAtoi(cephUser.Uid), mustAtoi(cephUser.Gid)); err != nil {
		logger.Warn("Failed to set ownership (continuing)", zap.Error(err))
	}

	logger.Debug("✓ Monitor database initialized successfully")
	return nil
}

// fixMonitorOwnership ensures correct ownership and permissions
func fixMonitorOwnership(logger otelzap.LoggerWithCtx, config *BootstrapConfig) error {
	cephUser, err := user.Lookup("ceph")
	if err != nil {
		return fmt.Errorf("ceph user not found: %w", err)
	}

	uid := mustAtoi(cephUser.Uid)
	gid := mustAtoi(cephUser.Gid)

	// Fix monitor data directory
	monDataDir := filepath.Join("/var/lib/ceph/mon", fmt.Sprintf("%s-%s", config.ClusterName, config.Hostname))
	if err := chownRecursive(monDataDir, uid, gid); err != nil {
		return fmt.Errorf("failed to fix monitor data ownership: %w", err)
	}

	// Fix admin keyring
	adminKeyring := "/etc/ceph/ceph.client.admin.keyring"
	if err := os.Chown(adminKeyring, uid, gid); err != nil {
		logger.Warn("Failed to chown admin keyring", zap.Error(err))
	}
	if err := os.Chmod(adminKeyring, 0600); err != nil {
		logger.Warn("Failed to chmod admin keyring", zap.Error(err))
	}

	// Fix bootstrap keyrings
	bootstrapDirs := []string{"bootstrap-osd", "bootstrap-mgr", "bootstrap-mds", "bootstrap-rgw"}
	for _, dir := range bootstrapDirs {
		keyringPath := filepath.Join("/var/lib/ceph", dir, config.ClusterName+".keyring")
		if _, err := os.Stat(keyringPath); err == nil {
			if err := os.Chown(keyringPath, uid, gid); err != nil {
				logger.Warn("Failed to chown "+dir+" keyring", zap.Error(err))
			}
			if err := os.Chmod(keyringPath, 0600); err != nil {
				logger.Warn("Failed to chmod "+dir+" keyring", zap.Error(err))
			}
		}
	}

	return nil
}

// startMonitorService enables and starts the monitor systemd service
func startMonitorService(logger otelzap.LoggerWithCtx, config *BootstrapConfig) error {
	serviceName := fmt.Sprintf("ceph-mon@%s", config.Hostname)

	// Enable service
	logger.Debug("Enabling monitor service", zap.String("service", serviceName))
	cmd := exec.Command("systemctl", "enable", serviceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		logger.Warn("Failed to enable service (may already be enabled)",
			zap.String("output", string(output)))
	}

	// Start service
	logger.Debug("Starting monitor service", zap.String("service", serviceName))
	cmd = exec.Command("systemctl", "start", serviceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to start monitor service: %s", output)
	}

	// Wait for service to start
	time.Sleep(3 * time.Second)

	// Check service status
	cmd = exec.Command("systemctl", "is-active", serviceName)
	statusOutput, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("monitor service is not active: %s", statusOutput)
	}

	status := strings.TrimSpace(string(statusOutput))
	if status != "active" {
		return fmt.Errorf("monitor service is %s (expected active)", status)
	}

	logger.Debug("✓ Monitor service is active")
	return nil
}

// verifyMonitorHealth checks if monitor is healthy and quorum is formed
func verifyMonitorHealth(logger otelzap.LoggerWithCtx, config *BootstrapConfig) error {
	// Give monitor time to form quorum (single-node cluster is immediate)
	time.Sleep(2 * time.Second)

	// Try to connect to cluster
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ceph", "status", "--connect-timeout=5")
	output, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("failed to connect to cluster: %s", output)
	}

	// Check if our monitor is in quorum
	outputStr := string(output)
	if !strings.Contains(outputStr, config.Hostname) {
		return fmt.Errorf("monitor %s not found in cluster status", config.Hostname)
	}

	// Check for quorum
	if !strings.Contains(outputStr, "quorum") {
		return fmt.Errorf("no quorum formed yet")
	}

	logger.Debug("Cluster status:", zap.String("output", outputStr))
	return nil
}

// Helper functions

func mustAtoi(s string) int {
	var i int
	fmt.Sscanf(s, "%d", &i)
	return i
}

func chownRecursive(path string, uid, gid int) error {
	return filepath.Walk(path, func(name string, info os.FileInfo, err error) error {
		if err == nil {
			err = os.Chown(name, uid, gid)
		}
		return err
	})
}
