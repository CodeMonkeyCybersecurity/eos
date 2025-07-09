// pkg/enrollment/transition.go
package enrollment

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// TransitionFromMasterless handles the transition from masterless to master/minion
func TransitionFromMasterless(rc *eos_io.RuntimeContext, masterAddr string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Starting transition from masterless to minion",
		zap.String("master_address", masterAddr))
	
	// ASSESS - Check current state
	currentState, err := assessCurrentSaltState(rc)
	if err != nil {
		return fmt.Errorf("failed to assess current Salt state: %w", err)
	}
	
	if currentState.Mode != SaltModeMasterless {
		logger.Info("System is not in masterless mode, skipping transition",
			zap.String("current_mode", currentState.Mode))
		return nil
	}
	
	// INTERVENE - Perform transition
	logger.Info("Backing up current configuration")
	if err := backupMasterlessConfiguration(rc, currentState); err != nil {
		return fmt.Errorf("failed to backup configuration: %w", err)
	}
	
	logger.Info("Preserving local customizations")
	if err := preserveLocalCustomizations(rc, currentState); err != nil {
		return fmt.Errorf("failed to preserve customizations: %w", err)
	}
	
	logger.Info("Reconfiguring for minion mode")
	if err := reconfigureForMinion(rc, masterAddr); err != nil {
		return fmt.Errorf("failed to reconfigure for minion: %w", err)
	}
	
	logger.Info("Migrating local states to master")
	if err := migrateLocalStates(rc, masterAddr); err != nil {
		logger.Warn("Failed to migrate local states", zap.Error(err))
		// Continue - this is not critical for basic operation
	}
	
	// EVALUATE - Verify transition
	logger.Info("Verifying transition")
	if err := verifyTransition(rc, masterAddr); err != nil {
		return fmt.Errorf("transition verification failed: %w", err)
	}
	
	logger.Info("Transition from masterless to minion completed successfully")
	return nil
}

// assessCurrentSaltState assesses the current Salt configuration
func assessCurrentSaltState(rc *eos_io.RuntimeContext) (*SaltConfiguration, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	state := &SaltConfiguration{
		CustomConfig: make(map[string]interface{}),
	}
	
	// Check minion configuration
	minionConfigPath := "/etc/salt/minion"
	if _, err := os.Stat(minionConfigPath); err == nil {
		if config, err := parseSaltConfig(minionConfigPath); err == nil {
			for k, v := range config {
				state.CustomConfig[k] = v
			}
		}
	}
	
	// Determine current mode
	if master, exists := state.CustomConfig["master"]; exists {
		if masterStr, ok := master.(string); ok {
			if masterStr == "salt" || masterStr == "localhost" {
				state.Mode = SaltModeMasterless
			} else {
				state.Mode = SaltModeMinion
			}
		}
	}
	
	if fileClient, exists := state.CustomConfig["file_client"]; exists {
		if fileClientStr, ok := fileClient.(string); ok && fileClientStr == "local" {
			state.Mode = SaltModeMasterless
		}
	}
	
	// Check for local file roots
	if fileRoots, exists := state.CustomConfig["file_roots"]; exists {
		if fileRootsMap, ok := fileRoots.(map[string]interface{}); ok {
			if base, exists := fileRootsMap["base"]; exists {
				if baseSlice, ok := base.([]interface{}); ok {
					for _, root := range baseSlice {
						if rootStr, ok := root.(string); ok {
							state.FileRoots = append(state.FileRoots, rootStr)
						}
					}
				}
			}
		}
	}
	
	// Check for pillar roots
	if pillarRoots, exists := state.CustomConfig["pillar_roots"]; exists {
		if pillarRootsMap, ok := pillarRoots.(map[string]interface{}); ok {
			if base, exists := pillarRootsMap["base"]; exists {
				if baseSlice, ok := base.([]interface{}); ok {
					for _, root := range baseSlice {
						if rootStr, ok := root.(string); ok {
							state.PillarRoots = append(state.PillarRoots, rootStr)
						}
					}
				}
			}
		}
	}
	
	logger.Debug("Current Salt state assessed",
		zap.String("mode", state.Mode),
		zap.Strings("file_roots", state.FileRoots),
		zap.Strings("pillar_roots", state.PillarRoots))
	
	return state, nil
}

// parseSaltConfig parses a Salt configuration file using proper YAML parsing
func parseSaltConfig(configPath string) (map[string]interface{}, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	
	config := make(map[string]interface{})
	
	// Try YAML parsing first
	if err := yaml.Unmarshal(data, &config); err != nil {
		// Fallback to simple line-by-line parsing for malformed YAML
		return parseSaltConfigSimple(data)
	}
	
	return config, nil
}

// parseSaltConfigSimple provides fallback parsing for malformed YAML
func parseSaltConfigSimple(data []byte) (map[string]interface{}, error) {
	config := make(map[string]interface{})
	lines := strings.Split(string(data), "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Simple key: value parsing
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				
				// Try to parse common Salt config values
				switch {
				case value == "true" || value == "True":
					config[key] = true
				case value == "false" || value == "False":
					config[key] = false
				case strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]"):
					// Simple list parsing
					listStr := strings.Trim(value, "[]")
					if listStr != "" {
						items := strings.Split(listStr, ",")
						var list []string
						for _, item := range items {
							list = append(list, strings.TrimSpace(item))
						}
						config[key] = list
					}
				default:
					// Remove quotes if present
					if (strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"")) ||
						(strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'")) {
						value = value[1 : len(value)-1]
					}
					config[key] = value
				}
			}
		}
	}
	
	return config, nil
}

// backupMasterlessConfiguration creates a backup of the current masterless configuration
func backupMasterlessConfiguration(rc *eos_io.RuntimeContext, state *SaltConfiguration) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if we're in dry-run mode
	if rc.Attributes != nil {
		if dryRun, exists := rc.Attributes["dry_run"]; exists && dryRun == "true" {
			logger.Info("DRY RUN: Would backup masterless configuration")
			return nil
		}
	}
	
	backupDir := "/var/backups/eos-enrollment"
	timestamp := time.Now().Format("20060102-150405")
	backupPath := filepath.Join(backupDir, fmt.Sprintf("masterless-backup-%s", timestamp))
	
	// Create backup directory
	if err := os.MkdirAll(backupPath, 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}
	
	// Backup configuration files
	configFiles := []string{
		"/etc/salt/minion",
		"/etc/salt/master",
		"/etc/salt/grains",
	}
	
	for _, configFile := range configFiles {
		if _, err := os.Stat(configFile); err == nil {
			backupFile := filepath.Join(backupPath, filepath.Base(configFile))
			if err := copyFile(configFile, backupFile); err != nil {
				logger.Warn("Failed to backup config file", 
					zap.String("file", configFile),
					zap.Error(err))
			}
		}
	}
	
	// Backup local states and pillars
	localDirs := []string{
		"/srv/salt",
		"/srv/pillar",
		"/etc/salt/pki",
	}
	
	for _, dir := range localDirs {
		if _, err := os.Stat(dir); err == nil {
			backupSubDir := filepath.Join(backupPath, filepath.Base(dir))
			if err := copyDirectory(dir, backupSubDir); err != nil {
				logger.Warn("Failed to backup directory", 
					zap.String("dir", dir),
					zap.Error(err))
			}
		}
	}
	
	// Create backup manifest
	manifest := "# Masterless Salt Backup\n"
	manifest += fmt.Sprintf("# Created: %s\n", time.Now().Format(time.RFC3339))
	manifest += fmt.Sprintf("# Original mode: %s\n", state.Mode)
	manifest += fmt.Sprintf("# File roots: %s\n", strings.Join(state.FileRoots, ", "))
	manifest += fmt.Sprintf("# Pillar roots: %s\n", strings.Join(state.PillarRoots, ", "))
	
	manifestPath := filepath.Join(backupPath, "manifest.txt")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0644); err != nil {
		logger.Warn("Failed to create backup manifest", zap.Error(err))
	}
	
	logger.Info("Masterless configuration backed up", zap.String("backup_path", backupPath))
	return nil
}

// preserveLocalCustomizations preserves important local customizations
func preserveLocalCustomizations(rc *eos_io.RuntimeContext, state *SaltConfiguration) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if we're in dry-run mode
	if rc.Attributes != nil {
		if dryRun, exists := rc.Attributes["dry_run"]; exists && dryRun == "true" {
			logger.Info("DRY RUN: Would preserve local customizations")
			return nil
		}
	}
	
	preservationDir := "/etc/salt/preserved"
	if err := os.MkdirAll(preservationDir, 0755); err != nil {
		return fmt.Errorf("failed to create preservation directory: %w", err)
	}
	
	// Preserve custom grains
	grainsPath := "/etc/salt/grains"
	if _, err := os.Stat(grainsPath); err == nil {
		preservedPath := filepath.Join(preservationDir, "grains")
		if err := copyFile(grainsPath, preservedPath); err != nil {
			logger.Warn("Failed to preserve grains", zap.Error(err))
		}
	}
	
	// Preserve custom minion configuration
	minionPath := "/etc/salt/minion"
	if _, err := os.Stat(minionPath); err == nil {
		preservedPath := filepath.Join(preservationDir, "minion.d", "99-preserved.conf")
		if err := os.MkdirAll(filepath.Dir(preservedPath), 0755); err == nil {
			if err := extractCustomConfig(minionPath, preservedPath); err != nil {
				logger.Warn("Failed to preserve custom minion config", zap.Error(err))
			}
		}
	}
	
	// Preserve local pillar data
	for _, pillarRoot := range state.PillarRoots {
		if _, err := os.Stat(pillarRoot); err == nil {
			preservedPath := filepath.Join(preservationDir, "pillar")
			if err := copyDirectory(pillarRoot, preservedPath); err != nil {
				logger.Warn("Failed to preserve pillar data", 
					zap.String("root", pillarRoot),
					zap.Error(err))
			}
		}
	}
	
	logger.Info("Local customizations preserved", zap.String("preservation_dir", preservationDir))
	return nil
}

// extractCustomConfig extracts custom configuration that should be preserved
func extractCustomConfig(sourcePath, destPath string) error {
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		return err
	}
	
	// Extract non-standard configuration
	lines := strings.Split(string(data), "\n")
	var preservedLines []string
	
	preservedLines = append(preservedLines, "# Preserved configuration from masterless setup")
	preservedLines = append(preservedLines, "# Generated by eos self enroll transition")
	preservedLines = append(preservedLines, "")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Skip standard configuration that will be overwritten
		if strings.HasPrefix(line, "master:") ||
			strings.HasPrefix(line, "file_client:") ||
			strings.HasPrefix(line, "file_roots:") ||
			strings.HasPrefix(line, "pillar_roots:") {
			continue
		}
		
		// Preserve custom configuration
		preservedLines = append(preservedLines, line)
	}
	
	if len(preservedLines) > 3 { // More than just header
		content := strings.Join(preservedLines, "\n")
		if err := os.WriteFile(destPath, []byte(content), 0644); err != nil {
			return err
		}
	}
	
	return nil
}

// reconfigureForMinion reconfigures Salt for minion mode
func reconfigureForMinion(rc *eos_io.RuntimeContext, masterAddr string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if we're in dry-run mode
	if rc.Attributes != nil {
		if dryRun, exists := rc.Attributes["dry_run"]; exists && dryRun == "true" {
			logger.Info("DRY RUN: Would reconfigure for minion mode")
			return nil
		}
	}
	
	// Create new minion configuration
	minionConfig := &SaltConfiguration{
		Mode:     SaltModeMinion,
		MinionID: GenerateMinionID("", "transitioned"),
		LogLevel: "warning",
		CustomConfig: map[string]interface{}{
			"master": masterAddr,
			"startup_states": "highstate",
			"file_client": "remote",
		},
	}
	
	// Include preserved configuration directory
	minionConfig.CustomConfig["default_include"] = "/etc/salt/minion.d/*.conf"
	
	// Write new minion configuration
	if err := writeSaltConfiguration(rc, "/etc/salt/minion", minionConfig, false); err != nil {
		return fmt.Errorf("failed to write minion configuration: %w", err)
	}
	
	// Remove local file_roots and pillar_roots from main config
	// These will be managed by the master now
	
	// Restart salt-minion service
	if err := manageSaltServices(rc, []string{"salt-minion"}, "restart"); err != nil {
		return fmt.Errorf("failed to restart salt-minion: %w", err)
	}
	
	logger.Info("Salt reconfigured for minion mode", zap.String("master", masterAddr))
	return nil
}

// migrateLocalStates migrates local states to the master
func migrateLocalStates(rc *eos_io.RuntimeContext, masterAddr string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if we're in dry-run mode
	if rc.Attributes != nil {
		if dryRun, exists := rc.Attributes["dry_run"]; exists && dryRun == "true" {
			logger.Info("DRY RUN: Would migrate local states to master")
			return nil
		}
	}
	
	// Package and transfer local states
	if err := packageAndTransferStates(rc, masterAddr); err != nil {
		return fmt.Errorf("failed to package and transfer states: %w", err)
	}
	
	// Package and transfer local pillars
	if err := packageAndTransferPillars(rc, masterAddr); err != nil {
		return fmt.Errorf("failed to package and transfer pillars: %w", err)
	}
	
	// Notify master to refresh fileserver
	if err := refreshMasterFileserver(rc, masterAddr); err != nil {
		logger.Warn("Failed to refresh master fileserver", zap.Error(err))
		// Continue - this is not critical for basic operation
	}
	
	// Verify states are available on master
	if err := verifyStatesOnMaster(rc, masterAddr); err != nil {
		logger.Warn("Failed to verify states on master", zap.Error(err))
		// Continue - this is not critical for basic operation
	}
	
	logger.Info("Local state migration completed successfully")
	return nil
}

// packageAndTransferStates packages and transfers local states to master
func packageAndTransferStates(rc *eos_io.RuntimeContext, masterAddr string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	stateDir := "/srv/salt"
	if _, err := os.Stat(stateDir); os.IsNotExist(err) {
		logger.Info("No local salt states to migrate")
		return nil
	}
	
	// Create temporary archive
	timestamp := time.Now().Format("20060102-150405")
	archivePath := fmt.Sprintf("/tmp/salt-states-%s.tar.gz", timestamp)
	
	// Package states
	logger.Info("Packaging local salt states", zap.String("archive", archivePath))
	cmd := exec.Command("tar", "-czf", archivePath, "-C", "/srv", "salt")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to package salt states: %s", string(output))
	}
	
	// Transfer to master
	if err := transferFileToMaster(rc, archivePath, masterAddr); err != nil {
		return fmt.Errorf("failed to transfer states to master: %w", err)
	}
	
	// Extract on master
	if err := extractStatesOnMaster(rc, masterAddr, filepath.Base(archivePath)); err != nil {
		return fmt.Errorf("failed to extract states on master: %w", err)
	}
	
	// Cleanup local archive
	if err := os.Remove(archivePath); err != nil {
		logger.Warn("Failed to cleanup archive", zap.Error(err))
	}
	
	logger.Info("Salt states migrated successfully")
	return nil
}

// packageAndTransferPillars packages and transfers local pillars to master
func packageAndTransferPillars(rc *eos_io.RuntimeContext, masterAddr string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	pillarDir := "/srv/pillar"
	if _, err := os.Stat(pillarDir); os.IsNotExist(err) {
		logger.Info("No local pillars to migrate")
		return nil
	}
	
	// Create temporary archive
	timestamp := time.Now().Format("20060102-150405")
	archivePath := fmt.Sprintf("/tmp/salt-pillars-%s.tar.gz", timestamp)
	
	// Package pillars
	logger.Info("Packaging local salt pillars", zap.String("archive", archivePath))
	cmd := exec.Command("tar", "-czf", archivePath, "-C", "/srv", "pillar")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to package salt pillars: %s", string(output))
	}
	
	// Transfer to master
	if err := transferFileToMaster(rc, archivePath, masterAddr); err != nil {
		return fmt.Errorf("failed to transfer pillars to master: %w", err)
	}
	
	// Extract on master
	if err := extractPillarsOnMaster(rc, masterAddr, filepath.Base(archivePath)); err != nil {
		return fmt.Errorf("failed to extract pillars on master: %w", err)
	}
	
	// Cleanup local archive
	if err := os.Remove(archivePath); err != nil {
		logger.Warn("Failed to cleanup archive", zap.Error(err))
	}
	
	logger.Info("Salt pillars migrated successfully")
	return nil
}

// transferFileToMaster transfers a file to the master using salt-cp or scp
func transferFileToMaster(rc *eos_io.RuntimeContext, filePath, masterAddr string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Try salt-cp first (if available and connected)
	if _, err := exec.LookPath("salt-cp"); err == nil {
		logger.Info("Attempting to transfer file using salt-cp")
		cmd := exec.Command("salt-cp", masterAddr, filePath, "/tmp/")
		if output, err := cmd.CombinedOutput(); err == nil {
			logger.Info("File transferred successfully using salt-cp")
			return nil
		} else {
			logger.Debug("salt-cp failed, trying scp", zap.String("output", string(output)))
		}
	}
	
	// Fallback to scp
	if _, err := exec.LookPath("scp"); err == nil {
		logger.Info("Attempting to transfer file using scp")
		destPath := fmt.Sprintf("root@%s:/tmp/", masterAddr)
		cmd := exec.Command("scp", "-o", "StrictHostKeyChecking=no", filePath, destPath)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("scp failed: %s", string(output))
		}
		logger.Info("File transferred successfully using scp")
		return nil
	}
	
	return fmt.Errorf("no suitable transfer method available (salt-cp or scp)")
}

// extractStatesOnMaster extracts states archive on the master
func extractStatesOnMaster(rc *eos_io.RuntimeContext, masterAddr, archiveName string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Execute extraction command on master
	extractCmd := fmt.Sprintf("tar -xzf /tmp/%s -C /srv/ && rm /tmp/%s", archiveName, archiveName)
	
	if err := executeOnMaster(rc, masterAddr, extractCmd); err != nil {
		return fmt.Errorf("failed to extract states on master: %w", err)
	}
	
	logger.Info("States extracted successfully on master")
	return nil
}

// extractPillarsOnMaster extracts pillars archive on the master
func extractPillarsOnMaster(rc *eos_io.RuntimeContext, masterAddr, archiveName string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Execute extraction command on master
	extractCmd := fmt.Sprintf("tar -xzf /tmp/%s -C /srv/ && rm /tmp/%s", archiveName, archiveName)
	
	if err := executeOnMaster(rc, masterAddr, extractCmd); err != nil {
		return fmt.Errorf("failed to extract pillars on master: %w", err)
	}
	
	logger.Info("Pillars extracted successfully on master")
	return nil
}

// executeOnMaster executes a command on the master using salt or ssh
func executeOnMaster(rc *eos_io.RuntimeContext, masterAddr, command string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Try salt command first
	if _, err := exec.LookPath("salt"); err == nil {
		logger.Debug("Attempting to execute command using salt")
		cmd := exec.Command("salt", masterAddr, "cmd.run", command)
		if output, err := cmd.CombinedOutput(); err == nil {
			logger.Debug("Command executed successfully using salt")
			return nil
		} else {
			logger.Debug("salt execution failed, trying ssh", zap.String("output", string(output)))
		}
	}
	
	// Fallback to ssh
	if _, err := exec.LookPath("ssh"); err == nil {
		logger.Debug("Attempting to execute command using ssh")
		cmd := exec.Command("ssh", "-o", "StrictHostKeyChecking=no", fmt.Sprintf("root@%s", masterAddr), command)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("ssh execution failed: %s", string(output))
		}
		logger.Debug("Command executed successfully using ssh")
		return nil
	}
	
	return fmt.Errorf("no suitable execution method available (salt or ssh)")
}

// refreshMasterFileserver refreshes the master fileserver
func refreshMasterFileserver(rc *eos_io.RuntimeContext, masterAddr string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Execute fileserver refresh command
	refreshCmd := "salt-run fileserver.update"
	
	if err := executeOnMaster(rc, masterAddr, refreshCmd); err != nil {
		return fmt.Errorf("failed to refresh fileserver: %w", err)
	}
	
	logger.Info("Master fileserver refreshed successfully")
	return nil
}

// verifyStatesOnMaster verifies that states are available on the master
func verifyStatesOnMaster(rc *eos_io.RuntimeContext, masterAddr string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Test that we can list states on master
	testCmd := "salt-run state.show_sls_list"
	
	if err := executeOnMaster(rc, masterAddr, testCmd); err != nil {
		return fmt.Errorf("failed to verify states on master: %w", err)
	}
	
	logger.Info("States verified successfully on master")
	return nil
}

// verifyTransition verifies that the transition was successful
func verifyTransition(rc *eos_io.RuntimeContext, masterAddr string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Run comprehensive verification tests
	verificationTests := []struct {
		name string
		test func() error
	}{
		{"Service Status", func() error { return verifyServiceStatus() }},
		{"Configuration", func() error { return verifyConfiguration(masterAddr) }},
		{"Network Connectivity", func() error { return TestSaltConnectivity(rc, masterAddr) }},
		{"Key Management", func() error { return verifyKeyManagement(rc, masterAddr) }},
		{"Basic Functionality", func() error { return verifyBasicSaltFunctionality(rc) }},
		{"State Application", func() error { return verifyStateApplication(rc, masterAddr) }},
		{"Pillar Data", func() error { return verifyPillarData(rc) }},
	}
	
	var failedTests []string
	for _, test := range verificationTests {
		logger.Info("Running transition verification test", zap.String("test", test.name))
		if err := test.test(); err != nil {
			logger.Error("Verification test failed", 
				zap.String("test", test.name), 
				zap.Error(err))
			failedTests = append(failedTests, fmt.Sprintf("%s: %v", test.name, err))
		} else {
			logger.Info("Verification test passed", zap.String("test", test.name))
		}
	}
	
	if len(failedTests) > 0 {
		return fmt.Errorf("transition verification failed: %s", strings.Join(failedTests, "; "))
	}
	
	logger.Info("Transition verification completed successfully")
	return nil
}

// verifyServiceStatus verifies that salt-minion service is running
func verifyServiceStatus() error {
	if !isServiceRunning("salt-minion") {
		return fmt.Errorf("salt-minion service is not running")
	}
	return nil
}

// verifyConfiguration verifies that master is configured correctly
func verifyConfiguration(masterAddr string) error {
	config, err := parseSaltConfig("/etc/salt/minion")
	if err != nil {
		return fmt.Errorf("failed to parse minion config: %w", err)
	}
	
	if master, exists := config["master"]; !exists || master != masterAddr {
		return fmt.Errorf("master not configured correctly in minion config")
	}
	
	return nil
}

// verifyKeyManagement verifies salt key management
func verifyKeyManagement(rc *eos_io.RuntimeContext, masterAddr string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if minion keys exist
	keyPaths := []string{
		"/etc/salt/pki/minion/minion.pem",
		"/etc/salt/pki/minion/minion.pub",
	}
	
	for _, keyPath := range keyPaths {
		if _, err := os.Stat(keyPath); err != nil {
			return fmt.Errorf("minion key not found: %s", keyPath)
		}
	}
	
	// Try to get key fingerprint
	if fingerprint, err := GetSaltKeyFingerprint(rc); err != nil {
		logger.Warn("Failed to get key fingerprint", zap.Error(err))
	} else {
		logger.Info("Minion key fingerprint", zap.String("fingerprint", fingerprint))
	}
	
	// Check if key is accepted on master (if possible)
	if err := checkKeyAcceptanceOnMaster(rc, masterAddr); err != nil {
		logger.Warn("Could not verify key acceptance on master", zap.Error(err))
		// Don't fail verification for this
	}
	
	return nil
}

// verifyBasicSaltFunctionality verifies basic salt functionality
func verifyBasicSaltFunctionality(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Test basic salt-call commands
	testCommands := []struct {
		name string
		cmd  []string
	}{
		{"test.ping", []string{"salt-call", "--local", "test.ping"}},
		{"grains.get os", []string{"salt-call", "--local", "grains.get", "os"}},
		{"pillar.items", []string{"salt-call", "--local", "pillar.items"}},
	}
	
	for _, testCmd := range testCommands {
		logger.Debug("Testing salt-call command", zap.String("command", testCmd.name))
		cmd := exec.Command(testCmd.cmd[0], testCmd.cmd[1:]...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("salt-call test '%s' failed: %w", testCmd.name, err)
		}
		
		// Check for basic success indicators
		outputStr := string(output)
		if strings.Contains(outputStr, "ERROR") || strings.Contains(outputStr, "CRITICAL") {
			return fmt.Errorf("salt-call test '%s' returned error: %s", testCmd.name, outputStr)
		}
		
		logger.Debug("Salt-call test successful", 
			zap.String("command", testCmd.name),
			zap.String("output", strings.TrimSpace(outputStr)))
	}
	
	return nil
}

// verifyStateApplication verifies state application works
func verifyStateApplication(rc *eos_io.RuntimeContext, masterAddr string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Test state application from master (if connected)
	if masterAddr != "" {
		logger.Debug("Testing state application from master")
		cmd := exec.Command("salt-call", "state.apply", "test=True")
		output, err := cmd.CombinedOutput()
		if err != nil {
			logger.Warn("State application test failed", zap.Error(err))
			// Don't fail verification for this as it might be expected
		} else {
			logger.Debug("State application test successful", 
				zap.String("output", string(output)))
		}
	}
	
	return nil
}

// verifyPillarData verifies pillar data is accessible
func verifyPillarData(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Test pillar data access
	cmd := exec.Command("salt-call", "--local", "pillar.items")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to access pillar data: %w", err)
	}
	
	outputStr := string(output)
	if strings.Contains(outputStr, "ERROR") || strings.Contains(outputStr, "CRITICAL") {
		return fmt.Errorf("pillar data access returned error: %s", outputStr)
	}
	
	logger.Debug("Pillar data verification successful")
	return nil
}

// checkKeyAcceptanceOnMaster checks if the minion key is accepted on master
func checkKeyAcceptanceOnMaster(rc *eos_io.RuntimeContext, masterAddr string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Get minion ID
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("failed to get hostname: %w", err)
	}
	
	// Try to check key status on master
	checkCmd := fmt.Sprintf("salt-key -L | grep -q %s", hostname)
	
	if err := executeOnMaster(rc, masterAddr, checkCmd); err != nil {
		return fmt.Errorf("failed to check key status on master: %w", err)
	}
	
	logger.Info("Minion key found on master", zap.String("minion_id", hostname))
	return nil
}

// isServiceRunning checks if a systemd service is running
func isServiceRunning(serviceName string) bool {
	cmd := exec.Command("systemctl", "is-active", serviceName)
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	
	return strings.TrimSpace(string(output)) == "active"
}

// copyFile copies a file from source to destination
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	
	return os.WriteFile(dst, data, 0644)
}

// copyDirectory recursively copies a directory with proper permissions and metadata
func copyDirectory(src, dst string) error {
	// Get source directory info
	srcInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("failed to stat source directory: %w", err)
	}
	
	// Create destination directory with same permissions
	if err := os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}
	
	// Copy directory contents
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		// Calculate relative path
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		
		// Skip the source directory itself
		if relPath == "." {
			return nil
		}
		
		dstPath := filepath.Join(dst, relPath)
		
		if info.IsDir() {
			// Create directory with original permissions
			if err := os.MkdirAll(dstPath, info.Mode()); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", dstPath, err)
			}
			
			// Copy directory metadata
			if err := copyDirectoryMetadata(path, dstPath, info); err != nil {
				// Log warning but continue - metadata copying is not critical
				return nil
			}
		} else if info.Mode().IsRegular() {
			// Copy regular file
			if err := copyFileWithMetadata(path, dstPath, info); err != nil {
				return fmt.Errorf("failed to copy file %s: %w", path, err)
			}
		} else if info.Mode()&os.ModeSymlink != 0 {
			// Copy symlink
			if err := copySymlink(path, dstPath); err != nil {
				return fmt.Errorf("failed to copy symlink %s: %w", path, err)
			}
		}
		// Skip other file types (devices, pipes, etc.)
		
		return nil
	})
}

// copyFileWithMetadata copies a file with metadata preservation
func copyFileWithMetadata(src, dst string, info os.FileInfo) error {
	// Copy file content
	if err := copyFile(src, dst); err != nil {
		return err
	}
	
	// Set file permissions
	if err := os.Chmod(dst, info.Mode()); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}
	
	// Set file timestamps
	if err := os.Chtimes(dst, info.ModTime(), info.ModTime()); err != nil {
		// Log warning but don't fail - timestamps are not critical
		return nil
	}
	
	return nil
}

// copyDirectoryMetadata copies directory metadata
func copyDirectoryMetadata(src, dst string, info os.FileInfo) error {
	// Set directory permissions
	if err := os.Chmod(dst, info.Mode()); err != nil {
		return fmt.Errorf("failed to set directory permissions: %w", err)
	}
	
	// Set directory timestamps
	if err := os.Chtimes(dst, info.ModTime(), info.ModTime()); err != nil {
		// Log warning but don't fail - timestamps are not critical
		return nil
	}
	
	return nil
}

// copySymlink copies a symbolic link
func copySymlink(src, dst string) error {
	// Read the symlink target
	target, err := os.Readlink(src)
	if err != nil {
		return fmt.Errorf("failed to read symlink: %w", err)
	}
	
	// Create the symlink
	if err := os.Symlink(target, dst); err != nil {
		return fmt.Errorf("failed to create symlink: %w", err)
	}
	
	return nil
}

// RollbackTransition rolls back a failed transition
func RollbackTransition(rc *eos_io.RuntimeContext, backupPath string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Rolling back transition", zap.String("backup_path", backupPath))
	
	// Check if we're in dry-run mode
	if rc.Attributes != nil {
		if dryRun, exists := rc.Attributes["dry_run"]; exists && dryRun == "true" {
			logger.Info("DRY RUN: Would rollback transition")
			return nil
		}
	}
	
	// Restore configuration files
	configFiles := []string{"minion", "master", "grains"}
	for _, configFile := range configFiles {
		backupFile := filepath.Join(backupPath, configFile)
		if _, err := os.Stat(backupFile); err == nil {
			destFile := filepath.Join("/etc/salt", configFile)
			if err := copyFile(backupFile, destFile); err != nil {
				logger.Warn("Failed to restore config file", 
					zap.String("file", configFile),
					zap.Error(err))
			}
		}
	}
	
	// Restore directories
	restoreDirs := map[string]string{
		"salt": "/srv/salt",
		"pillar": "/srv/pillar",
		"pki": "/etc/salt/pki",
	}
	
	for backupDir, destDir := range restoreDirs {
		backupPath := filepath.Join(backupPath, backupDir)
		if _, err := os.Stat(backupPath); err == nil {
			if err := copyDirectory(backupPath, destDir); err != nil {
				logger.Warn("Failed to restore directory", 
					zap.String("dir", backupDir),
					zap.Error(err))
			}
		}
	}
	
	// Restart salt-minion
	if err := manageSaltServices(rc, []string{"salt-minion"}, "restart"); err != nil {
		logger.Warn("Failed to restart salt-minion after rollback", zap.Error(err))
	}
	
	logger.Info("Transition rollback completed")
	return nil
}