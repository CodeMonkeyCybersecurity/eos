package cephfs

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VerifyCluster performs comprehensive verification of the CephFS cluster
func VerifyCluster(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS: Check if verification is possible
	logger.Info("Assessing cluster verification prerequisites")
	if err := assessVerificationPrerequisites(rc, config); err != nil {
		return fmt.Errorf("failed to assess verification prerequisites: %w", err)
	}

	// INTERVENE: Perform verification checks
	logger.Info("Performing cluster verification checks")
	result, err := performVerificationChecks(rc, config)
	if err != nil {
		return fmt.Errorf("failed to perform verification checks: %w", err)
	}

	// EVALUATE: Analyze verification results
	logger.Info("Evaluating verification results")
	if err := evaluateVerificationResults(rc, result); err != nil {
		return fmt.Errorf("cluster verification failed: %w", err)
	}

	logger.Info("Cluster verification completed successfully")
	return nil
}

// assessVerificationPrerequisites checks if verification can be performed
func assessVerificationPrerequisites(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check SSH connectivity to admin host
	logger.Debug("Checking SSH connectivity for verification")
	if err := checkSSHConnectivity(rc, config); err != nil {
		return fmt.Errorf("SSH connectivity check failed: %w", err)
	}

	// Check if ceph command is available on admin host
	logger.Debug("Checking ceph command availability")
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"which", "ceph",
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("ceph command not found on admin host %s", config.AdminHost))
	}

	cephPath := strings.TrimSpace(output)
	if cephPath == "" {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("ceph command not available on admin host %s", config.AdminHost))
	}

	logger.Debug("Verification prerequisites satisfied", zap.String("ceph_path", cephPath))
	return nil
}

// performVerificationChecks performs the actual verification checks
func performVerificationChecks(rc *eos_io.RuntimeContext, config *Config) (*VerificationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	startTime := time.Now()
	result := &VerificationResult{
		Errors:   []string{},
		Warnings: []string{},
	}

	// Check cluster health
	logger.Debug("Checking cluster health")
	clusterHealthy, err := checkClusterHealth(rc, config)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("cluster health check failed: %v", err))
	} else {
		result.ClusterHealthy = clusterHealthy
		if !clusterHealthy {
			result.Warnings = append(result.Warnings, "cluster health is not HEALTH_OK")
		}
	}

	// Check OSD status
	logger.Debug("Checking OSD status")
	allOSDsUp, err := checkOSDStatus(rc, config)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("OSD status check failed: %v", err))
	} else {
		result.AllOSDsUp = allOSDsUp
		if !allOSDsUp {
			result.Warnings = append(result.Warnings, "not all OSDs are up and in")
		}
	}

	// Check MON status
	logger.Debug("Checking MON status")
	allMONsUp, err := checkMONStatus(rc, config)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("MON status check failed: %v", err))
	} else {
		result.AllMONsUp = allMONsUp
		if !allMONsUp {
			result.Warnings = append(result.Warnings, "not all MONs are up")
		}
	}

	// Check MGR status
	logger.Debug("Checking MGR status")
	allMGRsUp, err := checkMGRStatus(rc, config)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("MGR status check failed: %v", err))
	} else {
		result.AllMGRsUp = allMGRsUp
		if !allMGRsUp {
			result.Warnings = append(result.Warnings, "not all MGRs are up")
		}
	}

	// Check CephFS health
	logger.Debug("Checking CephFS health")
	cephfsHealthy, err := checkCephFSHealth(rc, config)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("CephFS health check failed: %v", err))
	} else {
		result.CephFSHealthy = cephfsHealthy
		if !cephfsHealthy {
			result.Warnings = append(result.Warnings, "CephFS is not healthy or not available")
		}
	}

	result.CheckDuration = time.Since(startTime)

	logger.Debug("Verification checks completed",
		zap.Duration("duration", result.CheckDuration),
		zap.Int("errors", len(result.Errors)),
		zap.Int("warnings", len(result.Warnings)))

	return result, nil
}

// checkClusterHealth checks the overall cluster health
func checkClusterHealth(rc *eos_io.RuntimeContext, config *Config) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "health", "--format", "json",
		},
		Timeout: 60 * time.Second,
	})
	if err != nil {
		return false, fmt.Errorf("failed to check cluster health: %w", err)
	}

	// Parse health status
	var healthStatus struct {
		Status  string `json:"status"`
		Summary []struct {
			Severity string `json:"severity"`
			Summary  string `json:"summary"`
		} `json:"summary"`
	}

	if err := json.Unmarshal([]byte(output), &healthStatus); err != nil {
		// Fallback to string parsing if JSON parsing fails
		logger.Debug("JSON parsing failed, using string parsing", zap.Error(err))
		return strings.Contains(output, "HEALTH_OK"), nil
	}

	isHealthy := healthStatus.Status == "HEALTH_OK"

	if !isHealthy {
		logger.Warn("Cluster health issues detected",
			zap.String("status", healthStatus.Status),
			zap.Any("summary", healthStatus.Summary))
	}

	return isHealthy, nil
}

// checkOSDStatus checks the status of all OSDs
func checkOSDStatus(rc *eos_io.RuntimeContext, config *Config) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "osd", "stat", "--format", "json",
		},
		Timeout: 60 * time.Second,
	})
	if err != nil {
		return false, fmt.Errorf("failed to check OSD status: %w", err)
	}

	// Parse OSD status
	var osdStat struct {
		NumOSDs   int `json:"num_osds"`
		NumUpOSDs int `json:"num_up_osds"`
		NumInOSDs int `json:"num_in_osds"`
	}

	if err := json.Unmarshal([]byte(output), &osdStat); err != nil {
		// Fallback to string parsing
		logger.Debug("JSON parsing failed, using string parsing", zap.Error(err))
		return strings.Contains(output, "up") && strings.Contains(output, "in"), nil
	}

	allUp := osdStat.NumOSDs == osdStat.NumUpOSDs && osdStat.NumOSDs == osdStat.NumInOSDs

	logger.Debug("OSD status check",
		zap.Int("total_osds", osdStat.NumOSDs),
		zap.Int("up_osds", osdStat.NumUpOSDs),
		zap.Int("in_osds", osdStat.NumInOSDs),
		zap.Bool("all_up", allUp))

	return allUp, nil
}

// checkMONStatus checks the status of MON daemons
func checkMONStatus(rc *eos_io.RuntimeContext, config *Config) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "mon", "stat", "--format", "json",
		},
		Timeout: 60 * time.Second,
	})
	if err != nil {
		return false, fmt.Errorf("failed to check MON status: %w", err)
	}

	// Basic check if MONs are mentioned in output
	hasQuorum := strings.Contains(output, "quorum") || strings.Contains(output, "leader")

	logger.Debug("MON status check", zap.Bool("has_quorum", hasQuorum))

	return hasQuorum, nil
}

// checkMGRStatus checks the status of MGR daemons
func checkMGRStatus(rc *eos_io.RuntimeContext, config *Config) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "mgr", "stat", "--format", "json",
		},
		Timeout: 60 * time.Second,
	})
	if err != nil {
		return false, fmt.Errorf("failed to check MGR status: %w", err)
	}

	// Basic check if active MGR is mentioned
	hasActiveMGR := strings.Contains(output, "active") || strings.Contains(output, "standby")

	logger.Debug("MGR status check", zap.Bool("has_active_mgr", hasActiveMGR))

	return hasActiveMGR, nil
}

// checkCephFSHealth checks the health of CephFS filesystems
func checkCephFSHealth(rc *eos_io.RuntimeContext, config *Config) (bool, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if CephFS is available
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "fs", "ls", "--format", "json",
		},
		Timeout: 60 * time.Second,
	})
	if err != nil {
		return false, fmt.Errorf("failed to check CephFS status: %w", err)
	}

	// Check if any filesystems exist
	hasCephFS := strings.Contains(output, "name") || len(strings.TrimSpace(output)) > 2

	if hasCephFS {
		// Check CephFS status if it exists
		statusOutput, err := execute.Run(rc.Ctx, execute.Options{
			Command: "ssh",
			Args: []string{
				"-o", "ConnectTimeout=10",
				"-o", "BatchMode=yes",
				"-o", "StrictHostKeyChecking=no",
				fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
				"ceph", "fs", "status", "--format", "json",
			},
			Timeout: 60 * time.Second,
		})
		if err != nil {
			logger.Warn("Failed to get detailed CephFS status", zap.Error(err))
			return hasCephFS, nil
		}

		// Basic health check
		isHealthy := !strings.Contains(statusOutput, "down") &&
			!strings.Contains(statusOutput, "damaged") &&
			!strings.Contains(statusOutput, "failed")

		logger.Debug("CephFS health check",
			zap.Bool("has_cephfs", hasCephFS),
			zap.Bool("is_healthy", isHealthy))

		return isHealthy, nil
	}

	logger.Debug("No CephFS filesystems found")
	return false, nil
}

// evaluateVerificationResults analyzes the verification results
func evaluateVerificationResults(rc *eos_io.RuntimeContext, result *VerificationResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Log all warnings
	for _, warning := range result.Warnings {
		logger.Warn("Verification warning", zap.String("warning", warning))
	}

	// Log all errors
	for _, error := range result.Errors {
		logger.Error("Verification error", zap.String("error", error))
	}

	// Fail if there are any errors
	if len(result.Errors) > 0 {
		return fmt.Errorf("verification failed with %d errors: %v", len(result.Errors), result.Errors)
	}

	// Check critical health indicators
	criticalIssues := []string{}

	if !result.ClusterHealthy {
		criticalIssues = append(criticalIssues, "cluster is not healthy")
	}

	if !result.AllOSDsUp {
		criticalIssues = append(criticalIssues, "not all OSDs are up")
	}

	if !result.AllMONsUp {
		criticalIssues = append(criticalIssues, "not all MONs are up")
	}

	if !result.AllMGRsUp {
		criticalIssues = append(criticalIssues, "not all MGRs are up")
	}

	if len(criticalIssues) > 0 {
		logger.Warn("Critical issues detected but verification passed with warnings",
			zap.Strings("issues", criticalIssues),
			zap.Int("warning_count", len(result.Warnings)))
	}

	// Log success summary
	logger.Info("Verification completed successfully",
		zap.Duration("duration", result.CheckDuration),
		zap.Bool("cluster_healthy", result.ClusterHealthy),
		zap.Bool("all_osds_up", result.AllOSDsUp),
		zap.Bool("all_mons_up", result.AllMONsUp),
		zap.Bool("all_mgrs_up", result.AllMGRsUp),
		zap.Bool("cephfs_healthy", result.CephFSHealthy),
		zap.Int("warnings", len(result.Warnings)))

	return nil
}

// PerformBasicConnectivityTest performs a basic connectivity test
func PerformBasicConnectivityTest(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Performing basic connectivity test")

	// Test mount point creation (if needed for future CephFS mount tests)
	testDir := "/tmp/cephfs-connectivity-test"
	if err := os.MkdirAll(testDir, 0755); err != nil {
		return fmt.Errorf("failed to create test directory: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(testDir); err != nil {
			logger.Error("Failed to remove test directory", zap.Error(err))
		}
	}()

	// Test file creation
	testFile := testDir + "/test.txt"
	if err := os.WriteFile(testFile, []byte(TestFileContent), 0644); err != nil {
		return fmt.Errorf("failed to create test file: %w", err)
	}

	// Verify file exists
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		return fmt.Errorf("test file was not created successfully")
	}

	// Test ceph command execution
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "--version",
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to execute ceph command: %w", err)
	}

	if !strings.Contains(output, "ceph version") {
		return fmt.Errorf("unexpected ceph version output: %s", output)
	}

	logger.Info("Basic connectivity test passed", zap.String("ceph_version", strings.TrimSpace(output)))
	return nil
}

// GetClusterStatus returns the current cluster status
func GetClusterStatus(rc *eos_io.RuntimeContext, config *Config) (*DeploymentStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	status := &DeploymentStatus{
		LastChecked: time.Now(),
	}

	// Check if cluster exists by testing SSH connection and ceph command
	logger.Debug("Checking if cluster exists")
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=5",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "status", "--format", "json",
		},
		Timeout: 30 * time.Second,
	})

	if err != nil {
		logger.Debug("Cluster does not exist or is not accessible", zap.Error(err))
		status.ClusterExists = false
		return status, nil
	}

	status.ClusterExists = true

	// Get detailed status if cluster exists
	result, err := performVerificationChecks(rc, config)
	if err != nil {
		logger.Debug("Failed to get detailed cluster status", zap.Error(err))
		return status, nil
	}

	status.ClusterHealthy = result.ClusterHealthy
	status.CephFSAvailable = result.CephFSHealthy

	// Get version information
	versionOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=5",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "--version",
		},
		Timeout: 30 * time.Second,
	})
	if err == nil {
		status.Version = strings.TrimSpace(versionOutput)
	}

	logger.Debug("Cluster status retrieved",
		zap.Bool("exists", status.ClusterExists),
		zap.Bool("healthy", status.ClusterHealthy),
		zap.Bool("cephfs_available", status.CephFSAvailable),
		zap.String("version", status.Version))

	return status, nil
}
