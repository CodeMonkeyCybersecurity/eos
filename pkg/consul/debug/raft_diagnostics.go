// pkg/consul/debug/raft_diagnostics.go
//
// Comprehensive Raft state diagnostics for Consul cluster debugging.
// Provides deep inspection of Raft database location, ACL bootstrap state,
// and data directory configuration mismatches.
//
// Last Updated: 2025-01-25

package debug

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	consulapi "github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RaftDiagnosticConfig holds configuration for Raft diagnostics
type RaftDiagnosticConfig struct {
	RunAll           bool // Run all checks (default if no specific flags)
	ShowPeers        bool // Show Raft cluster peer list
	ShowDataDir      bool // Show data directory from all sources
	ShowResetState   bool // Show ACL bootstrap reset state
	SimulateReset    bool // Simulate reset file write (dry-run)
	WatchResetFile   bool // Monitor reset file for 30s
	ShowResetHistory bool // Show last 10 reset attempts
}

// RaftDiagnosticResults holds the results of Raft diagnostics
type RaftDiagnosticResults struct {
	Checks        []DiagnosticResult
	CriticalCount int
	WarningCount  int
	InfoCount     int
}

// RunRaftDiagnostics performs comprehensive Raft state diagnostics
// Now accepts authenticated Consul client for ACL-protected operations
func RunRaftDiagnostics(rc *eos_io.RuntimeContext, config *RaftDiagnosticConfig) (*RaftDiagnosticResults, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Running Consul Raft diagnostics")

	results := &RaftDiagnosticResults{
		Checks: []DiagnosticResult{},
	}

	// Get authenticated Consul client for ACL-protected operations
	consulClient, consulClientErr := consul.GetAuthenticatedConsulClientForDiagnostics(rc, "")
	if consulClientErr != nil {
		logger.Warn("Authenticated Consul client not available, some checks may fail",
			zap.Error(consulClientErr),
			zap.String("remediation", "Run: eos update consul --bootstrap-token"))
	}

	// Determine which checks to run
	runAll := config.RunAll

	// ASSESS - Raft database location (filesystem scan)
	if runAll || config.ShowDataDir {
		raftDBResult := findAllRaftDatabases(rc)
		results.Checks = append(results.Checks, raftDBResult)
	}

	// ASSESS - Data directory from running process
	if runAll || config.ShowDataDir {
		processDataDirResult := extractDataDirFromProcess(rc)
		results.Checks = append(results.Checks, processDataDirResult)
	}

	// ASSESS - Data directory from configuration
	if runAll || config.ShowDataDir {
		configDataDirResult := extractDataDirFromConfig(rc)
		results.Checks = append(results.Checks, configDataDirResult)
	}

	// ASSESS - Raft cluster peers and leader
	if runAll || config.ShowPeers {
		raftPeersResult := checkRaftClusterPeers(rc)
		results.Checks = append(results.Checks, raftPeersResult)
	}

	// ASSESS - ACL bootstrap reset state (now with authenticated client)
	if runAll || config.ShowResetState {
		resetStateResult := checkACLBootstrapResetState(rc, consulClient, consulClientErr)
		results.Checks = append(results.Checks, resetStateResult)
	}

	// INTERVENE - Simulate reset file write (dry-run, now with authenticated client)
	if config.SimulateReset {
		simulateResult := simulateResetFileWrite(rc, consulClient, consulClientErr)
		results.Checks = append(results.Checks, simulateResult)
	}

	// MONITOR - Watch reset file
	if config.WatchResetFile {
		watchResult := watchResetFile(rc)
		results.Checks = append(results.Checks, watchResult)
	}

	// ASSESS - Reset attempt history
	if runAll || config.ShowResetHistory {
		historyResult := showResetAttemptHistory(rc)
		results.Checks = append(results.Checks, historyResult)
	}

	// ASSESS - Raft log inspection (advanced - shows raw Raft state)
	if runAll {
		raftInspectResult := inspectRaftLog(rc)
		results.Checks = append(results.Checks, raftInspectResult)
	}

	// EVALUATE - Count issues by severity
	for _, check := range results.Checks {
		if !check.Success {
			switch check.Severity {
			case SeverityCritical:
				results.CriticalCount++
			case SeverityWarning:
				results.WarningCount++
			case SeverityInfo:
				results.InfoCount++
			}
		}
	}

	// Display results
	displayRaftResults(rc, results)

	return results, nil
}

// findAllRaftDatabases scans the filesystem for ALL raft.db files
func findAllRaftDatabases(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Scanning filesystem for all Raft databases")

	result := DiagnosticResult{
		CheckName: "Raft Database Location Scan",
		Success:   true,
		Details:   []string{},
	}

	result.Details = append(result.Details, "=== Filesystem Scan for raft.db ===")
	result.Details = append(result.Details, "")

	// ASSESS - Use find command to locate all raft.db files
	cmd := execute.Options{
		Command: "find",
		Args:    []string{"/", "-name", "raft.db", "-type", "f"},
		Capture: true,
		Timeout: 30000, // 30 seconds max
	}

	output, err := execute.Run(rc.Ctx, cmd)
	if err != nil {
		result.Details = append(result.Details, "⚠ Filesystem scan failed or timed out")
		result.Details = append(result.Details, fmt.Sprintf("  Error: %v", err))
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "Falling back to known locations...")
		result.Details = append(result.Details, "")

		// Fallback: check known locations
		knownPaths := []string{
			"/opt/consul/raft/raft.db",
			"/var/lib/consul/raft/raft.db",
			"/data/consul/raft/raft.db",
		}

		foundAny := false
		for _, path := range knownPaths {
			if info, err := os.Stat(path); err == nil {
				foundAny = true
				result.Details = append(result.Details, fmt.Sprintf("✓ Found: %s", path))
				result.Details = append(result.Details, fmt.Sprintf("  Size: %d bytes", info.Size()))
				result.Details = append(result.Details, fmt.Sprintf("  Modified: %s", info.ModTime().Format("2006-01-02 15:04:05")))
				result.Details = append(result.Details, "")
			}
		}

		if !foundAny {
			result.Success = false
			result.Severity = SeverityCritical
			result.Message = "No raft.db found anywhere (Consul never started successfully)"
			result.Details = append(result.Details, "✗ No raft.db found in known locations")
			result.Details = append(result.Details, "")
			result.Details = append(result.Details, "IMPACT:")
			result.Details = append(result.Details, "  - Consul has never successfully initialized Raft")
			result.Details = append(result.Details, "  - Cannot perform ACL operations without Raft")
			result.Details = append(result.Details, "")
			result.Details = append(result.Details, "REMEDIATION:")
			result.Details = append(result.Details, "  1. Check Consul is running: systemctl status consul")
			result.Details = append(result.Details, "  2. Check Consul logs: journalctl -u consul -n 100")
			result.Details = append(result.Details, "  3. Fix startup issues, Consul will create raft.db")
			return result
		}

		result.Message = "Found raft.db in known locations (full scan failed)"
		return result
	}

	// Parse find output
	lines := strings.Split(output, "\n")
	raftPaths := []string{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && strings.HasSuffix(line, "raft.db") {
			raftPaths = append(raftPaths, line)
		}
	}

	if len(raftPaths) == 0 {
		result.Success = false
		result.Severity = SeverityCritical
		result.Message = "No raft.db found anywhere on filesystem"
		result.Details = append(result.Details, "✗ Filesystem scan found NO raft.db files")
		result.Details = append(result.Details, "  Scanned entire filesystem with: find / -name raft.db")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "CRITICAL: Consul has never successfully started")
		return result
	}

	result.Details = append(result.Details, fmt.Sprintf("Found %d raft.db file(s):", len(raftPaths)))
	result.Details = append(result.Details, "")

	// Get details for each raft.db
	var newestPath string
	var newestMtime time.Time

	for _, path := range raftPaths {
		info, err := os.Stat(path)
		if err != nil {
			result.Details = append(result.Details, fmt.Sprintf("✗ %s (cannot stat)", path))
			continue
		}

		age := time.Since(info.ModTime())
		status := ""
		if age.Hours() < 1 {
			status = "ACTIVE (modified < 1h ago)"
			if newestMtime.IsZero() || info.ModTime().After(newestMtime) {
				newestPath = path
				newestMtime = info.ModTime()
			}
		} else if age.Hours() < 24 {
			status = fmt.Sprintf("Recent (%.1fh ago)", age.Hours())
		} else {
			status = fmt.Sprintf("STALE (%.0fh ago)", age.Hours())
		}

		result.Details = append(result.Details, fmt.Sprintf("  %s", path))
		result.Details = append(result.Details, fmt.Sprintf("    Size: %d bytes", info.Size()))
		result.Details = append(result.Details, fmt.Sprintf("    Modified: %s (%s)", info.ModTime().Format("2006-01-02 15:04:05"), status))
		result.Details = append(result.Details, "")
	}

	if len(raftPaths) > 1 {
		result.Details = append(result.Details, "⚠ WARNING: Multiple raft.db files found")
		result.Details = append(result.Details, "  This indicates stale installations or data directory changes")
		result.Details = append(result.Details, "")
		result.Success = false
		result.Severity = SeverityWarning
	}

	if newestPath != "" {
		result.Details = append(result.Details, "=== ACTIVE Raft Database ===")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, fmt.Sprintf("✓ Active raft.db: %s", newestPath))

		// Extract data directory (raft.db is inside raft/ subdirectory)
		dataDir := filepath.Dir(filepath.Dir(newestPath))
		result.Details = append(result.Details, fmt.Sprintf("  Data directory: %s", dataDir))
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "CRITICAL: ACL reset file MUST be written to:")
		result.Details = append(result.Details, fmt.Sprintf("  %s/acl-bootstrap-reset", dataDir))
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "If Eos config says different data_dir, Consul WON'T see reset file!")
	}

	result.Message = fmt.Sprintf("Found %d raft.db file(s) on filesystem", len(raftPaths))
	return result
}

// extractDataDirFromProcess extracts data directory from running Consul process
func extractDataDirFromProcess(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Extracting data directory from running Consul process")

	result := DiagnosticResult{
		CheckName: "Process Data Directory",
		Success:   true,
		Details:   []string{},
	}

	result.Details = append(result.Details, "=== Running Consul Process Inspection ===")
	result.Details = append(result.Details, "")

	// ASSESS - Get full process command line
	cmd := execute.Options{
		Command: "ps",
		Args:    []string{"aux"},
		Capture: true,
	}

	output, err := execute.Run(rc.Ctx, cmd)
	if err != nil {
		result.Success = false
		result.Message = "Cannot inspect running processes"
		result.Details = append(result.Details, fmt.Sprintf("Error: %v", err))
		return result
	}

	// Find Consul process
	lines := strings.Split(output, "\n")
	var consulCmdLine string

	for _, line := range lines {
		if strings.Contains(line, "consul agent") && !strings.Contains(line, "grep") {
			consulCmdLine = line
			break
		}
	}

	if consulCmdLine == "" {
		result.Success = false
		result.Severity = SeverityCritical
		result.Message = "Consul process not running"
		result.Details = append(result.Details, "✗ No 'consul agent' process found")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "CRITICAL: Consul is NOT RUNNING")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "REMEDIATION:")
		result.Details = append(result.Details, "  sudo systemctl start consul")
		return result
	}

	result.Details = append(result.Details, "✓ Consul process found:")
	result.Details = append(result.Details, "  "+consulCmdLine)
	result.Details = append(result.Details, "")

	// Extract -data-dir argument
	dataDir := ""
	re := regexp.MustCompile(`-data-dir[= ]([^\s]+)`)
	matches := re.FindStringSubmatch(consulCmdLine)

	if len(matches) >= 2 {
		dataDir = strings.Trim(matches[1], `"'`)
		result.Details = append(result.Details, "✓ Data directory from process args:")
		result.Details = append(result.Details, fmt.Sprintf("  %s", dataDir))

		// Verify directory exists
		if info, err := os.Stat(dataDir); err == nil {
			if info.IsDir() {
				result.Details = append(result.Details, "  ✓ Directory exists")

				// Check for raft.db
				raftPath := filepath.Join(dataDir, "raft", "raft.db")
				if _, err := os.Stat(raftPath); err == nil {
					result.Details = append(result.Details, "  ✓ Contains raft/raft.db")
				} else {
					result.Details = append(result.Details, "  ✗ Does NOT contain raft/raft.db")
					result.Success = false
					result.Severity = SeverityWarning
				}
			} else {
				result.Details = append(result.Details, "  ✗ Path exists but is NOT a directory")
				result.Success = false
				result.Severity = SeverityCritical
			}
		} else {
			result.Details = append(result.Details, "  ✗ Directory does NOT exist")
			result.Success = false
			result.Severity = SeverityCritical
		}
	} else {
		result.Details = append(result.Details, "⚠ No -data-dir flag found in process args")
		result.Details = append(result.Details, "  Consul may be using config file or defaults")
	}

	result.Details = append(result.Details, "")

	// Use lsof to see what files Consul actually has open
	result.Details = append(result.Details, "=== Open Files (lsof) ===")
	result.Details = append(result.Details, "")

	// Get Consul PID
	pidCmd := execute.Options{
		Command: "pgrep",
		Args:    []string{"consul"},
		Capture: true,
	}

	pidOutput, pidErr := execute.Run(rc.Ctx, pidCmd)
	if pidErr == nil && strings.TrimSpace(pidOutput) != "" {
		pid := strings.TrimSpace(strings.Split(pidOutput, "\n")[0])

		lsofCmd := execute.Options{
			Command: "lsof",
			Args:    []string{"-p", pid},
			Capture: true,
		}

		lsofOutput, lsofErr := execute.Run(rc.Ctx, lsofCmd)
		if lsofErr == nil {
			// Find raft-related files
			lsofLines := strings.Split(lsofOutput, "\n")
			foundRaft := false

			for _, line := range lsofLines {
				if strings.Contains(line, "raft") {
					if !foundRaft {
						result.Details = append(result.Details, "Raft-related open files:")
						foundRaft = true
					}
					result.Details = append(result.Details, "  "+strings.TrimSpace(line))
				}
			}

			if foundRaft {
				result.Details = append(result.Details, "")
				result.Details = append(result.Details, "✓ This proves Consul is ACTUALLY using these paths")
			} else {
				result.Details = append(result.Details, "⚠ No raft-related files open")
				result.Details = append(result.Details, "  Consul may not have initialized Raft yet")
			}
		}
	}

	result.Details = append(result.Details, "")
	result.Message = "Extracted data directory from running process"
	return result
}

// extractDataDirFromConfig extracts data directory from Consul config files
func extractDataDirFromConfig(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Extracting data directory from Consul configuration")

	result := DiagnosticResult{
		CheckName: "Config File Data Directory",
		Success:   true,
		Details:   []string{},
	}

	result.Details = append(result.Details, "=== Consul Configuration Files ===")
	result.Details = append(result.Details, "")

	configPath := consul.ConsulConfigFile

	// Check main config file
	if _, err := os.Stat(configPath); err == nil {
		result.Details = append(result.Details, fmt.Sprintf("✓ Config file exists: %s", configPath))

		content, err := os.ReadFile(configPath)
		if err != nil {
			result.Details = append(result.Details, fmt.Sprintf("  ✗ Cannot read file: %v", err))
			result.Success = false
			result.Severity = SeverityWarning
		} else {
			configStr := string(content)

			// Extract data_dir
			re := regexp.MustCompile(`data_dir\s*=\s*"([^"]+)"`)
			matches := re.FindStringSubmatch(configStr)

			if len(matches) >= 2 {
				dataDir := matches[1]
				result.Details = append(result.Details, "  ✓ data_dir configured:")
				result.Details = append(result.Details, fmt.Sprintf("    %s", dataDir))

				// Verify
				if info, err := os.Stat(dataDir); err == nil && info.IsDir() {
					result.Details = append(result.Details, "    ✓ Directory exists")
				} else {
					result.Details = append(result.Details, "    ✗ Directory does NOT exist")
					result.Success = false
					result.Severity = SeverityCritical
				}
			} else {
				result.Details = append(result.Details, "  ⚠ No data_dir found in config")
				result.Details = append(result.Details, "    Consul will use default (/opt/consul or /var/lib/consul)")
			}
		}
	} else {
		result.Details = append(result.Details, fmt.Sprintf("✗ Config file NOT found: %s", configPath))
		result.Success = false
		result.Severity = SeverityCritical
	}

	result.Details = append(result.Details, "")
	result.Message = "Extracted data directory from configuration"
	return result
}

// checkRaftClusterPeers shows Raft cluster peer list and leader
func checkRaftClusterPeers(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking Raft cluster peers and leader")

	result := DiagnosticResult{
		CheckName: "Raft Cluster Peers",
		Success:   true,
		Details:   []string{},
	}

	result.Details = append(result.Details, "=== Raft Cluster Peer List ===")
	result.Details = append(result.Details, "")

	cmd := execute.Options{
		Command: "consul",
		Args:    []string{"operator", "raft", "list-peers"},
		Capture: true,
	}

	output, err := execute.Run(rc.Ctx, cmd)
	if err != nil {
		result.Details = append(result.Details, "✗ Cannot query Raft peers (ACL token required)")
		result.Details = append(result.Details, fmt.Sprintf("  Error: %v", err))
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "This is expected when ACLs are enabled and no token provided")
		result.Success = false
		result.Severity = SeverityInfo
		result.Message = "Raft peer list unavailable (ACL token required)"
		return result
	}

	result.Details = append(result.Details, output)
	result.Details = append(result.Details, "")
	result.Message = "Raft cluster peers retrieved successfully"
	return result
}

// checkACLBootstrapResetState shows current ACL bootstrap reset state
// checkACLBootstrapResetState checks ACL bootstrap reset state
// Accepts authenticated Consul client (bootstrap check works without auth, but consistency is better)
func checkACLBootstrapResetState(rc *eos_io.RuntimeContext, consulClient *consulapi.Client, clientErr error) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking ACL bootstrap reset state")

	result := DiagnosticResult{
		CheckName: "ACL Bootstrap Reset State",
		Success:   true,
		Details:   []string{},
	}

	result.Details = append(result.Details, "=== ACL Bootstrap Reset State ===")
	result.Details = append(result.Details, "")

	// Use the provided client (bootstrap check doesn't strictly require auth, but better to use authenticated client)
	if consulClient == nil || clientErr != nil {
		result.Success = false
		result.Severity = SeverityInfo // INFO: Expected if client unavailable
		result.Message = "Cannot check ACL bootstrap state - client not available"
		if clientErr != nil {
			result.Details = append(result.Details, fmt.Sprintf("Client error: %v", clientErr))
		}
		return result
	}

	_, _, bootstrapErr := consulClient.ACL().Bootstrap()

	if bootstrapErr == nil {
		result.Details = append(result.Details, "✓ ACLs have NEVER been bootstrapped")
		result.Details = append(result.Details, "  Bootstrap succeeded on first try")
		result.Details = append(result.Details, "  No reset needed")
		result.Message = "ACLs not bootstrapped yet"
		return result
	}

	// Parse error for reset index
	errorMsg := bootstrapErr.Error()
	result.Details = append(result.Details, "✗ ACLs already bootstrapped")
	result.Details = append(result.Details, "")
	result.Details = append(result.Details, "Bootstrap error:")
	result.Details = append(result.Details, "  "+errorMsg)
	result.Details = append(result.Details, "")

	re := regexp.MustCompile(`reset index:\s*(\d+)`)
	matches := re.FindStringSubmatch(errorMsg)

	if len(matches) >= 2 {
		var lastConsumedIndex int
		fmt.Sscanf(matches[1], "%d", &lastConsumedIndex)

		nextRequiredIndex := lastConsumedIndex + 1

		result.Details = append(result.Details, "=== Reset Index Analysis ===")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, fmt.Sprintf("Last CONSUMED reset index: %d", lastConsumedIndex))
		result.Details = append(result.Details, fmt.Sprintf("NEXT REQUIRED reset index:  %d ← USE THIS", nextRequiredIndex))
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "To reset ACL bootstrap:")
		result.Details = append(result.Details, fmt.Sprintf("  echo '%d' > /path/to/data_dir/acl-bootstrap-reset", nextRequiredIndex))
		result.Details = append(result.Details, "  systemctl restart consul")
		result.Details = append(result.Details, "  consul acl bootstrap")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "OR use:")
		result.Details = append(result.Details, "  sudo eos update consul --bootstrap-token")
	}

	result.Details = append(result.Details, "")
	result.Message = "ACL bootstrap state retrieved"
	return result
}

// simulateResetFileWrite simulates ACL reset file write (dry-run)
// Accepts authenticated Consul client for bootstrap check
func simulateResetFileWrite(rc *eos_io.RuntimeContext, consulClient *consulapi.Client, clientErr error) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Simulating ACL reset file write (dry-run)")

	result := DiagnosticResult{
		CheckName: "ACL Reset File Write Simulation",
		Success:   true,
		Details:   []string{},
	}

	result.Details = append(result.Details, "=== DRY-RUN: ACL Reset File Write Simulation ===")
	result.Details = append(result.Details, "")
	result.Details = append(result.Details, "This is a DRY-RUN - NO files will be written")
	result.Details = append(result.Details, "")

	// Use the provided client for bootstrap check
	if consulClient == nil || clientErr != nil {
		result.Success = false
		result.Severity = SeverityInfo
		result.Message = "Cannot simulate reset - client not available"
		if clientErr != nil {
			result.Details = append(result.Details, fmt.Sprintf("Client error: %v", clientErr))
		}
		return result
	}

	// Get reset index
	_, _, bootstrapErr := consulClient.ACL().Bootstrap()

	var nextIndex int
	if bootstrapErr != nil {
		re := regexp.MustCompile(`reset index:\s*(\d+)`)
		matches := re.FindStringSubmatch(bootstrapErr.Error())
		if len(matches) >= 2 {
			var lastConsumed int
			fmt.Sscanf(matches[1], "%d", &lastConsumed)
			nextIndex = lastConsumed + 1
		}
	}

	// Get data directories from all sources
	configPath := consul.ConsulConfigFile
	var configDataDir string

	if content, err := os.ReadFile(configPath); err == nil {
		re := regexp.MustCompile(`data_dir\s*=\s*"([^"]+)"`)
		if matches := re.FindStringSubmatch(string(content)); len(matches) >= 2 {
			configDataDir = matches[1]
		}
	}

	result.Details = append(result.Details, "=== What Would Be Written ===")
	result.Details = append(result.Details, "")

	if nextIndex > 0 {
		result.Details = append(result.Details, fmt.Sprintf("Reset index to write: %d", nextIndex))
	} else {
		result.Details = append(result.Details, "Reset index: (ACLs not bootstrapped yet)")
	}

	result.Details = append(result.Details, "")

	if configDataDir != "" {
		resetFile := filepath.Join(configDataDir, "acl-bootstrap-reset")
		result.Details = append(result.Details, "File path (from CONFIG):")
		result.Details = append(result.Details, fmt.Sprintf("  %s", resetFile))

		if _, err := os.Stat(configDataDir); err == nil {
			result.Details = append(result.Details, "  ✓ Directory exists")
		} else {
			result.Details = append(result.Details, "  ✗ Directory does NOT exist - WRITE WOULD FAIL")
			result.Success = false
			result.Severity = SeverityCritical
		}
	} else {
		result.Details = append(result.Details, "⚠ No data_dir in config - would use default")
	}

	result.Details = append(result.Details, "")
	result.Details = append(result.Details, "VERIFICATION:")
	result.Details = append(result.Details, "  Run 'sudo eos debug raft --show-datadir' to verify paths match")
	result.Details = append(result.Details, "")

	result.Message = "Reset file write simulation completed (dry-run)"
	return result
}

// watchResetFile monitors acl-bootstrap-reset file for 30 seconds
func watchResetFile(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Monitoring acl-bootstrap-reset file for 30 seconds")

	result := DiagnosticResult{
		CheckName: "ACL Reset File Monitor",
		Success:   true,
		Details:   []string{},
	}

	result.Details = append(result.Details, "=== Monitoring acl-bootstrap-reset File ===")
	result.Details = append(result.Details, "")
	result.Details = append(result.Details, "Watching for file creation/modification for 30 seconds...")
	result.Details = append(result.Details, "")

	// TODO: Implement inotify-based file watching
	// For now, simple polling

	result.Details = append(result.Details, "⚠ File monitoring not yet implemented")
	result.Details = append(result.Details, "  This feature requires inotify integration")
	result.Success = false
	result.Severity = SeverityInfo
	result.Message = "File monitoring not yet implemented"

	return result
}

// showResetAttemptHistory shows last 10 ACL reset attempts from logs
func showResetAttemptHistory(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Showing ACL bootstrap reset attempt history")

	result := DiagnosticResult{
		CheckName: "ACL Reset Attempt History",
		Success:   true,
		Details:   []string{},
	}

	result.Details = append(result.Details, "=== ACL Bootstrap Reset Attempt History ===")
	result.Details = append(result.Details, "")

	cmd := execute.Options{
		Command: "journalctl",
		Args:    []string{"-u", "consul", "--since", "1 hour ago", "--no-pager"},
		Capture: true,
	}

	output, err := execute.Run(rc.Ctx, cmd)
	if err != nil {
		result.Details = append(result.Details, "✗ Cannot access journal logs")
		result.Details = append(result.Details, fmt.Sprintf("  Error: %v", err))
		result.Success = false
		result.Message = "Cannot access logs"
		return result
	}

	// Search for reset-related log entries
	lines := strings.Split(output, "\n")
	resetLines := []string{}

	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), "bootstrap") ||
			strings.Contains(strings.ToLower(line), "reset") ||
			strings.Contains(strings.ToLower(line), "acl") {
			resetLines = append(resetLines, line)
		}
	}

	if len(resetLines) == 0 {
		result.Details = append(result.Details, "No ACL-related log entries in the last hour")
	} else {
		result.Details = append(result.Details, fmt.Sprintf("Found %d ACL-related log entries:", len(resetLines)))
		result.Details = append(result.Details, "")

		// Show last 10
		displayCount := len(resetLines)
		if displayCount > 10 {
			displayCount = 10
		}

		for i := len(resetLines) - displayCount; i < len(resetLines); i++ {
			result.Details = append(result.Details, resetLines[i])
		}
	}

	result.Details = append(result.Details, "")
	result.Message = "Reset attempt history retrieved"
	return result
}

// displayRaftResults shows formatted Raft diagnostic results
func displayRaftResults(rc *eos_io.RuntimeContext, results *RaftDiagnosticResults) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("========================================")
	logger.Info("RAFT DIAGNOSTIC SUMMARY")
	logger.Info("========================================")

	for _, result := range results.Checks {
		if result.Success {
			logger.Info("[PASS] "+result.CheckName,
				zap.String("check", result.CheckName),
				zap.String("message", result.Message),
				zap.Bool("success", true))
			logger.Info("      " + result.Message)
		} else {
			logger.Error("[FAIL] "+result.CheckName,
				zap.String("check", result.CheckName),
				zap.String("message", result.Message),
				zap.Bool("success", false))
			logger.Error("      " + result.Message)
		}

		for _, detail := range result.Details {
			logger.Info("      " + detail)
		}

		logger.Info("")
	}

	logger.Info("========================================")

	// Summary
	if results.CriticalCount > 0 {
		logger.Error("CRITICAL ISSUES FOUND",
			zap.Int("critical", results.CriticalCount),
			zap.Int("warnings", results.WarningCount))
	} else if results.WarningCount > 0 {
		logger.Warn("Warnings found",
			zap.Int("warnings", results.WarningCount))
	} else {
		logger.Info("✓ All Raft diagnostics passed")
	}
}

// inspectRaftLog runs 'consul operator raft inspect' to show raw Raft log state.
// This is CRITICAL for debugging ACL bootstrap issues because it shows:
//   - If ACL reset file was actually consumed by Raft
//   - What reset index entries exist in the Raft log
//   - Last applied index vs last snapshot index
//   - Configuration changes in the log
//
// IMPORTANT: This command requires:
//  1. Consul binary is accessible
//  2. Data directory path is known
//  3. Consul service is stopped (can't inspect while DB is locked)
//
// Returns:
//   - SUCCESS: Raft log inspected successfully
//   - WARNING: Inspect failed (Consul running, DB locked)
//   - CRITICAL: Cannot find raft.db or data directory
func inspectRaftLog(rc *eos_io.RuntimeContext) DiagnosticResult {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Inspecting raw Raft log (consul operator raft inspect)")

	result := DiagnosticResult{
		CheckName: "Raft Log Inspection",
		Success:   true,
		Details:   []string{},
	}

	result.Details = append(result.Details, "=== Raft Log Inspection (Advanced) ===")
	result.Details = append(result.Details, "")

	// ASSESS - Check if Consul binary exists
	consulBinary := consul.GetConsulBinaryPath()
	if _, err := os.Stat(consulBinary); err != nil {
		result.Success = false
		result.Severity = SeverityWarning
		result.Message = "Consul binary not found"
		result.Details = append(result.Details, "✗ Consul binary not found")
		result.Details = append(result.Details, fmt.Sprintf("  Searched: %s", consulBinary))
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "Cannot run 'consul operator raft inspect' without Consul CLI")
		return result
	}

	result.Details = append(result.Details, fmt.Sprintf("✓ Consul binary found: %s", consulBinary))
	result.Details = append(result.Details, "")

	// ASSESS - Find data directory
	configPath := consul.ConsulConfigFile
	var dataDir string

	if content, err := os.ReadFile(configPath); err == nil {
		re := regexp.MustCompile(`data_dir\s*=\s*"([^"]+)"`)
		if matches := re.FindStringSubmatch(string(content)); len(matches) >= 2 {
			dataDir = matches[1]
		}
	}

	if dataDir == "" {
		// Fallback: try to find raft.db
		findCmd := execute.Options{
			Command: "find",
			Args:    []string{"/opt/consul", "/var/lib/consul", "-name", "raft.db", "-type", "f"},
			Capture: true,
			Timeout: 5000, // 5 seconds
		}

		if output, err := execute.Run(rc.Ctx, findCmd); err == nil {
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				if strings.TrimSpace(line) != "" {
					// raft.db is in data_dir/raft/raft.db
					dataDir = filepath.Dir(filepath.Dir(line))
					break
				}
			}
		}
	}

	if dataDir == "" {
		result.Success = false
		result.Severity = SeverityCritical
		result.Message = "Cannot determine Consul data directory"
		result.Details = append(result.Details, "✗ Cannot find Consul data directory")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "REMEDIATION:")
		result.Details = append(result.Details, "  Run: sudo eos debug raft --show-datadir")
		result.Details = append(result.Details, "  Or specify explicitly: consul operator raft inspect -path=/path/to/data_dir")
		return result
	}

	result.Details = append(result.Details, fmt.Sprintf("✓ Data directory: %s", dataDir))
	result.Details = append(result.Details, "")

	// ASSESS - Check if Consul is running (inspect requires stopped service)
	pgrep := execute.Options{
		Command: "pgrep",
		Args:    []string{"consul"},
		Capture: true,
	}

	consulRunning := false
	if output, err := execute.Run(rc.Ctx, pgrep); err == nil && strings.TrimSpace(output) != "" {
		consulRunning = true
	}

	if consulRunning {
		result.Details = append(result.Details, "⚠ WARNING: Consul is currently RUNNING")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "The 'raft inspect' command requires Consul to be STOPPED")
		result.Details = append(result.Details, "because it needs exclusive access to raft.db (BoltDB limitation)")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "SAFE APPROACH:")
		result.Details = append(result.Details, "  1. Stop Consul temporarily:")
		result.Details = append(result.Details, "       sudo systemctl stop consul")
		result.Details = append(result.Details, "  2. Run inspection:")
		result.Details = append(result.Details, fmt.Sprintf("       sudo consul operator raft inspect %s", dataDir))
		result.Details = append(result.Details, "  3. Restart Consul:")
		result.Details = append(result.Details, "       sudo systemctl start consul")
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "Service disruption: ~15 seconds (acceptable for debugging)")
		result.Details = append(result.Details, "")
		result.Success = false
		result.Severity = SeverityInfo // Not an error, just info
		result.Message = "Raft inspection requires Consul to be stopped (currently running)"
		return result
	}

	result.Details = append(result.Details, "✓ Consul is stopped (safe to inspect Raft log)")
	result.Details = append(result.Details, "")

	// INTERVENE - Run raft inspect
	result.Details = append(result.Details, "Running: consul operator raft inspect")
	result.Details = append(result.Details, "")

	inspectCmd := execute.Options{
		Command: consulBinary,
		Args:    []string{"operator", "raft", "inspect", dataDir},
		Capture: true,
		Timeout: 30000, // 30 seconds (raft.db can be large)
	}

	output, err := execute.Run(rc.Ctx, inspectCmd)
	if err != nil {
		result.Success = false
		result.Severity = SeverityWarning
		result.Message = "Raft log inspection failed"
		result.Details = append(result.Details, "✗ Raft inspect command failed")
		result.Details = append(result.Details, fmt.Sprintf("  Error: %v", err))
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "Output (if any):")
		if strings.TrimSpace(output) != "" {
			result.Details = append(result.Details, output)
		}
		return result
	}

	// EVALUATE - Parse output for key information
	result.Details = append(result.Details, "=== Raft Log Contents ===")
	result.Details = append(result.Details, "")

	// Show full output (can be large)
	lines := strings.Split(output, "\n")

	// Extract key lines
	var lastIndex, lastTerm, lastSnapshotIndex int64
	aclResetEntries := []string{}

	for _, line := range lines {
		// Key statistics
		if strings.Contains(line, "index=") && strings.Contains(line, "term=") {
			result.Details = append(result.Details, line)

			// Parse for last index
			if matches := regexp.MustCompile(`index=(\d+)`).FindStringSubmatch(line); len(matches) >= 2 {
				fmt.Sscanf(matches[1], "%d", &lastIndex)
			}
			if matches := regexp.MustCompile(`term=(\d+)`).FindStringSubmatch(line); len(matches) >= 2 {
				fmt.Sscanf(matches[1], "%d", &lastTerm)
			}
		}

		// ACL-related entries
		if strings.Contains(strings.ToLower(line), "acl") ||
			strings.Contains(strings.ToLower(line), "bootstrap") {
			aclResetEntries = append(aclResetEntries, line)
		}

		// Snapshot info
		if strings.Contains(line, "snapshot") {
			if matches := regexp.MustCompile(`index=(\d+)`).FindStringSubmatch(line); len(matches) >= 2 {
				fmt.Sscanf(matches[1], "%d", &lastSnapshotIndex)
			}
		}

		// Limit output to prevent spam (show first 50 lines + summary)
		if len(result.Details) < 100 {
			result.Details = append(result.Details, line)
		}
	}

	if len(lines) > 100 {
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, fmt.Sprintf("... (output truncated, showing first 100 lines of %d total)", len(lines)))
	}

	result.Details = append(result.Details, "")
	result.Details = append(result.Details, "=== Raft Log Summary ===")
	result.Details = append(result.Details, "")

	if lastIndex > 0 {
		result.Details = append(result.Details, fmt.Sprintf("Last applied index: %d", lastIndex))
		result.Details = append(result.Details, fmt.Sprintf("Last term: %d", lastTerm))
	}

	if lastSnapshotIndex > 0 {
		result.Details = append(result.Details, fmt.Sprintf("Last snapshot index: %d", lastSnapshotIndex))
	}

	result.Details = append(result.Details, "")

	if len(aclResetEntries) > 0 {
		result.Details = append(result.Details, fmt.Sprintf("✓ Found %d ACL-related entries in Raft log:", len(aclResetEntries)))
		for _, entry := range aclResetEntries {
			result.Details = append(result.Details, "  "+entry)
		}
		result.Details = append(result.Details, "")
		result.Details = append(result.Details, "This proves ACL operations were written to Raft log")
	} else {
		result.Details = append(result.Details, "⚠ No ACL-related entries found in Raft log")
		result.Details = append(result.Details, "  This could mean:")
		result.Details = append(result.Details, "    - ACLs have never been bootstrapped")
		result.Details = append(result.Details, "    - ACL entries are in a snapshot (not in log)")
		result.Details = append(result.Details, "    - Log has been compacted")
	}

	result.Details = append(result.Details, "")
	result.Message = "Raft log inspected successfully"

	return result
}
