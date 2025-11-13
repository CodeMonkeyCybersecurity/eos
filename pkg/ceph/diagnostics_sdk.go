//go:build !darwin
// +build !darwin

// pkg/ceph/diagnostics_sdk.go
// SDK-based Ceph diagnostics using native RADOS API
// Enabled by default on Linux, disabled on Mac

package ceph

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ceph/go-ceph/rados"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ClusterHealthSDK represents cluster health from native API
type ClusterHealthSDK struct {
	TotalBytes uint64
	UsedBytes  uint64
	AvailBytes uint64
	NumOSDs    int
	NumPGs     int
	Healthy    bool
}

// MonitorQuorumSDK represents monitor quorum information
type MonitorQuorumSDK struct {
	InQuorum     []string
	MonmapEpoch  uint64
	QuorumLeader string
}

// CheckClusterHealthSDK uses native RADOS API for cluster health
// This is MUCH faster than shell commands (microseconds vs milliseconds)
func CheckClusterHealthSDK(logger otelzap.LoggerWithCtx, verbose bool) (*ClusterHealthSDK, error) {
	logger.Debug("Attempting SDK-based cluster health check")

	// Create connection
	conn, err := rados.NewConn()
	if err != nil {
		logger.Debug("Failed to create RADOS connection", zap.Error(err))
		return nil, fmt.Errorf("failed to create connection: %w", err)
	}
	defer conn.Shutdown()

	// Read default config (/etc/ceph/ceph.conf)
	if err := conn.ReadDefaultConfigFile(); err != nil {
		logger.Debug("Failed to read ceph.conf", zap.Error(err))
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	// Connect with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Connect in goroutine to respect timeout
	errChan := make(chan error, 1)
	go func() {
		errChan <- conn.Connect()
	}()

	select {
	case err := <-errChan:
		if err != nil {
			logger.Debug("Failed to connect to cluster", zap.Error(err))
			return nil, fmt.Errorf("failed to connect: %w", err)
		}
	case <-ctx.Done():
		return nil, fmt.Errorf("connection timeout after 5s")
	}

	logger.Debug("✓ Connected to cluster via RADOS API")

	// Get cluster statistics
	stat, err := conn.GetClusterStats()
	if err != nil {
		logger.Debug("Failed to get cluster stats", zap.Error(err))
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}

	health := &ClusterHealthSDK{
		TotalBytes: stat.Kb * 1024,
		UsedBytes:  stat.Kb_used * 1024,
		AvailBytes: stat.Kb_avail * 1024,
	}

	// Get OSD count by running monitor command
	cmd := []byte(`{"prefix": "osd stat", "format": "json"}`)
	buf, _, err := conn.MonCommand(cmd)
	if err == nil {
		var osdStat map[string]interface{}
		if err := json.Unmarshal(buf, &osdStat); err == nil {
			if numOSDs, ok := osdStat["num_osds"].(float64); ok {
				health.NumOSDs = int(numOSDs)
			}
		}
	}

	// Get PG count
	cmd = []byte(`{"prefix": "pg stat", "format": "json"}`)
	buf, _, err = conn.MonCommand(cmd)
	if err == nil {
		var pgStat map[string]interface{}
		if err := json.Unmarshal(buf, &pgStat); err == nil {
			if numPGs, ok := pgStat["num_pgs"].(float64); ok {
				health.NumPGs = int(numPGs)
			}
		}
	}

	// Check overall health status
	cmd = []byte(`{"prefix": "health", "format": "json"}`)
	buf, _, err = conn.MonCommand(cmd)
	if err == nil {
		var healthStatus map[string]interface{}
		if err := json.Unmarshal(buf, &healthStatus); err == nil {
			if status, ok := healthStatus["status"].(string); ok {
				health.Healthy = (status == "HEALTH_OK")
			}
		}
	}

	if verbose {
		logger.Info("SDK cluster stats",
			zap.Uint64("total_bytes", health.TotalBytes),
			zap.Uint64("used_bytes", health.UsedBytes),
			zap.Uint64("avail_bytes", health.AvailBytes),
			zap.Int("num_osds", health.NumOSDs),
			zap.Int("num_pgs", health.NumPGs),
			zap.Bool("healthy", health.Healthy))
	}

	return health, nil
}

// CheckMonitorQuorumSDK checks monitor quorum via native API
func CheckMonitorQuorumSDK(logger otelzap.LoggerWithCtx, verbose bool) (*MonitorQuorumSDK, error) {
	logger.Debug("Attempting SDK-based monitor quorum check")

	conn, err := rados.NewConn()
	if err != nil {
		return nil, fmt.Errorf("failed to create connection: %w", err)
	}
	defer conn.Shutdown()

	if err := conn.ReadDefaultConfigFile(); err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- conn.Connect()
	}()

	select {
	case err := <-errChan:
		if err != nil {
			return nil, fmt.Errorf("failed to connect: %w", err)
		}
	case <-ctx.Done():
		return nil, fmt.Errorf("connection timeout")
	}

	// Get quorum status
	cmd := []byte(`{"prefix": "quorum_status", "format": "json"}`)
	buf, _, err := conn.MonCommand(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to get quorum status: %w", err)
	}

	var quorumStatus map[string]interface{}
	if err := json.Unmarshal(buf, &quorumStatus); err != nil {
		return nil, fmt.Errorf("failed to parse quorum status: %w", err)
	}

	quorum := &MonitorQuorumSDK{
		InQuorum: []string{},
	}

	// Parse quorum members
	if quorumList, ok := quorumStatus["quorum"].([]interface{}); ok {
		for _, q := range quorumList {
			if qInt, ok := q.(float64); ok {
				quorum.InQuorum = append(quorum.InQuorum, fmt.Sprintf("mon.%d", int(qInt)))
			}
		}
	}

	// Get monmap epoch
	if epoch, ok := quorumStatus["election_epoch"].(float64); ok {
		quorum.MonmapEpoch = uint64(epoch)
	}

	// Get quorum leader
	if leader, ok := quorumStatus["quorum_leader_name"].(string); ok {
		quorum.QuorumLeader = leader
	}

	if verbose {
		logger.Info("SDK monitor quorum",
			zap.Strings("in_quorum", quorum.InQuorum),
			zap.Uint64("monmap_epoch", quorum.MonmapEpoch),
			zap.String("leader", quorum.QuorumLeader))
	}

	return quorum, nil
}

// SDKAvailable returns true if SDK diagnostics can be used
func SDKAvailable() bool {
	// This function only exists when built with linux && cgo tags
	return true
}

// CheckConnectivitySDK tests cluster connectivity using SDK
func CheckConnectivitySDK(logger otelzap.LoggerWithCtx, verbose bool) DiagnosticResult {
	logger.Info("Attempting to connect to Ceph cluster via SDK...")

	result := DiagnosticResult{
		CheckName: "Connectivity (SDK)",
		Passed:    false,
		Issues:    []Issue{},
	}

	// Try to get cluster health via SDK
	health, err := CheckClusterHealthSDK(logger, verbose)
	if err != nil {
		logger.Error("❌ Cannot connect to cluster via SDK", zap.Error(err))
		logger.Info("  → Falling back to shell command check")

		// Fallback to shell-based check
		return CheckConnectivity(logger)
	}

	logger.Info("✓ Connected to cluster successfully via SDK")
	if verbose {
		logger.Info(fmt.Sprintf("  Cluster stats: Total=%d bytes, Used=%d bytes, Avail=%d bytes",
			health.TotalBytes, health.UsedBytes, health.AvailBytes))
	}

	result.Passed = true
	result.Details = "Cluster is reachable via RADOS API"
	return result
}

// CheckHealthSDK checks cluster health using SDK
func CheckHealthSDK(logger otelzap.LoggerWithCtx, verbose bool) DiagnosticResult {
	logger.Info("Checking cluster health via SDK...")

	result := DiagnosticResult{
		CheckName: "Cluster Health (SDK)",
		Passed:    false,
		Issues:    []Issue{},
	}

	health, err := CheckClusterHealthSDK(logger, verbose)
	if err != nil {
		logger.Warn("SDK health check failed, falling back to shell", zap.Error(err))
		return CheckHealth(logger, verbose)
	}

	if health.Healthy {
		logger.Info("✓ Cluster is HEALTHY")
		result.Passed = true
		result.Details = fmt.Sprintf("OSDs: %d, PGs: %d, Storage: %d/%d bytes used",
			health.NumOSDs, health.NumPGs, health.UsedBytes, health.TotalBytes)
	} else {
		logger.Warn("  Cluster has health warnings")
		result.Details = "Cluster is not in HEALTH_OK state"
		result.Issues = append(result.Issues, Issue{
			Component:   "cluster",
			Severity:    "warning",
			Description: "Cluster health is not OK",
			Impact:      "Cluster may have degraded performance or availability",
			Remediation: []string{
				"ceph health detail",
				"Check OSD status: ceph osd tree",
				"Check PG status: ceph pg stat",
			},
		})
	}

	if verbose {
		logger.Info(fmt.Sprintf("  Total storage: %d bytes", health.TotalBytes))
		logger.Info(fmt.Sprintf("  Used storage: %d bytes", health.UsedBytes))
		logger.Info(fmt.Sprintf("  Available storage: %d bytes", health.AvailBytes))
		logger.Info(fmt.Sprintf("  OSDs: %d", health.NumOSDs))
		logger.Info(fmt.Sprintf("  PGs: %d", health.NumPGs))
	}

	return result
}

// CheckMonStatusSDK checks monitor status using SDK
func CheckMonStatusSDK(logger otelzap.LoggerWithCtx, verbose bool) DiagnosticResult {
	logger.Info("Checking monitor status via SDK...")

	result := DiagnosticResult{
		CheckName: "Monitor Status (SDK)",
		Passed:    false,
		Issues:    []Issue{},
	}

	quorum, err := CheckMonitorQuorumSDK(logger, verbose)
	if err != nil {
		logger.Warn("SDK monitor check failed, falling back to shell", zap.Error(err))
		return CheckMonStatus(logger)
	}

	if len(quorum.InQuorum) > 0 {
		logger.Info(fmt.Sprintf("✓ Monitor quorum established: %d monitor(s)", len(quorum.InQuorum)))
		if verbose {
			for _, mon := range quorum.InQuorum {
				logger.Info(fmt.Sprintf("  - %s", mon))
			}
			logger.Info(fmt.Sprintf("  Leader: %s", quorum.QuorumLeader))
			logger.Info(fmt.Sprintf("  Monmap epoch: %d", quorum.MonmapEpoch))
		}
		result.Passed = true
		result.Details = fmt.Sprintf("%d monitors in quorum, leader: %s",
			len(quorum.InQuorum), quorum.QuorumLeader)
	} else {
		logger.Error("❌ No monitors in quorum!")
		result.Issues = append(result.Issues, Issue{
			Component:   "ceph-mon",
			Severity:    "critical",
			Description: "No monitors in quorum",
			Impact:      "Cluster cannot make decisions or accept writes",
			Remediation: []string{
				"Check monitor processes: ps aux | grep ceph-mon",
				"Check monitor logs: journalctl -u ceph-mon@* -n 50",
				"Verify monitor addresses: ceph mon dump",
			},
		})
	}

	return result
}
