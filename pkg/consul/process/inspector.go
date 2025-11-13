// pkg/consul/process/inspector.go
//
// Process inspection utilities for Consul data directory discovery.
//
// This package extracts Consul configuration from running processes and systemd
// service files without requiring Consul API authentication. Used for ACL
// bootstrap token recovery when API access is unavailable.
//
// Last Updated: 2025-10-25

package process

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GetDataDirFromRunningProcess attempts to extract the data directory from a running Consul process.
//
// This function inspects the running Consul process command line arguments to extract
// the -data-dir flag value. It does NOT require Consul API access or authentication.
//
// Algorithm:
//  1. Find Consul process via `ps aux | grep consul`
//  2. Extract command line arguments
//  3. Look for -data-dir or --data-dir flag
//  4. Handle both forms: -data-dir=/path and -data-dir /path
//  5. If process inspection fails, try systemd service file
//
// Parameters:
//   - rc: Runtime context for logging
//
// Returns:
//   - string: Data directory path from process args
//   - error: If no Consul process found or data-dir not in args
//
// Example:
//
//	dataDir, err := process.GetDataDirFromRunningProcess(rc)
//	if err != nil {
//	    logger.Debug("Process inspection failed", zap.Error(err))
//	    // Fall back to other detection methods
//	}
func GetDataDirFromRunningProcess(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Attempting to extract data_dir from running Consul process")

	// Try to get data dir from process list
	dataDir, err := getDataDirFromPsAux(rc)
	if err == nil {
		logger.Info("Data directory extracted from running process",
			zap.String("data_dir", dataDir))
		return dataDir, nil
	}

	logger.Debug("ps aux inspection failed", zap.Error(err))

	// Fall back to systemd service file
	dataDir, err = getDataDirFromSystemdService(rc)
	if err == nil {
		logger.Info("Data directory extracted from systemd service file",
			zap.String("data_dir", dataDir))
		return dataDir, nil
	}

	logger.Debug("systemd service inspection failed", zap.Error(err))

	return "", fmt.Errorf("failed to extract data_dir from running process or systemd service: %w", err)
}

// getDataDirFromPsAux inspects running processes to find Consul and extract data-dir.
func getDataDirFromPsAux(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Get process list
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ps",
		Args:    []string{"aux"},
		Capture: true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to execute ps aux: %w\nOutput: %s", err, output)
	}

	logger.Debug("Process list retrieved", zap.Int("output_length", len(output)))

	// Find lines containing "consul" command
	lines := strings.Split(output, "\n")
	var consulCmdLine string

	for _, line := range lines {
		// Skip grep itself
		if strings.Contains(line, "grep") {
			continue
		}

		// Look for consul binary in the command
		if strings.Contains(line, "consul") && (strings.Contains(line, "/consul") || strings.Contains(line, "consul agent")) {
			consulCmdLine = line
			logger.Debug("Found Consul process", zap.String("line", line))
			break
		}
	}

	if consulCmdLine == "" {
		return "", fmt.Errorf("no running Consul process found in ps aux output")
	}

	// Extract data-dir from command line
	return extractDataDirFromCommandLine(consulCmdLine)
}

// getDataDirFromSystemdService inspects the systemd service file for Consul.
func getDataDirFromSystemdService(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Checking systemd service file for data-dir")

	// Get systemd service file contents
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"cat", "consul"},
		Capture: true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to read systemd service: %w\nOutput: %s", err, output)
	}

	logger.Debug("Systemd service file retrieved", zap.Int("output_length", len(output)))

	// Find ExecStart line
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "ExecStart=") {
			logger.Debug("Found ExecStart line", zap.String("line", line))
			return extractDataDirFromCommandLine(line)
		}
	}

	return "", fmt.Errorf("ExecStart not found in systemd service file")
}

// extractDataDirFromCommandLine extracts the data-dir value from a command line string.
//
// Handles multiple formats:
//   - -data-dir=/path/to/dir
//   - -data-dir /path/to/dir
//   - --data-dir=/path/to/dir
//   - --data-dir /path/to/dir
func extractDataDirFromCommandLine(cmdLine string) (string, error) {
	// Pattern 1: -data-dir=/path or --data-dir=/path
	re1 := regexp.MustCompile(`-{1,2}data-dir=([^\s]+)`)
	matches := re1.FindStringSubmatch(cmdLine)
	if len(matches) >= 2 {
		dataDir := strings.TrimSpace(matches[1])
		return dataDir, nil
	}

	// Pattern 2: -data-dir /path or --data-dir /path (with space)
	re2 := regexp.MustCompile(`-{1,2}data-dir\s+([^\s]+)`)
	matches = re2.FindStringSubmatch(cmdLine)
	if len(matches) >= 2 {
		dataDir := strings.TrimSpace(matches[1])
		return dataDir, nil
	}

	// Pattern 3: Check for -config-dir flag (data-dir might be in config file)
	// This is less reliable, but note it in the error
	if strings.Contains(cmdLine, "-config-dir") {
		return "", fmt.Errorf("found -config-dir but no -data-dir in command line (data-dir may be in config file)")
	}

	return "", fmt.Errorf("data-dir flag not found in command line: %s", cmdLine)
}
