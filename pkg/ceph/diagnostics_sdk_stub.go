//go:build darwin
// +build darwin

// pkg/ceph/diagnostics_sdk_stub.go
// Stub implementation for Mac (Darwin) platform
// This allows the code to compile on Mac without Ceph libraries
// On Linux, the real SDK implementation is used by default

package ceph

import (
	"fmt"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
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

// CheckClusterHealthSDK stub for non-Linux platforms
func CheckClusterHealthSDK(logger otelzap.LoggerWithCtx, verbose bool) (*ClusterHealthSDK, error) {
	return nil, fmt.Errorf("SDK diagnostics not available on this platform (requires Linux with CGO)")
}

// CheckMonitorQuorumSDK stub for non-Linux platforms
func CheckMonitorQuorumSDK(logger otelzap.LoggerWithCtx, verbose bool) (*MonitorQuorumSDK, error) {
	return nil, fmt.Errorf("SDK diagnostics not available on this platform (requires Linux with CGO)")
}

// SDKAvailable returns false on non-Linux platforms
func SDKAvailable() bool {
	return false
}

// CheckConnectivitySDK stub - not available on this platform
func CheckConnectivitySDK(logger otelzap.LoggerWithCtx, verbose bool) DiagnosticResult {
	// Should never be called due to SDKAvailable() check, but provide fallback
	return CheckConnectivity(logger)
}

// CheckHealthSDK stub - not available on this platform
func CheckHealthSDK(logger otelzap.LoggerWithCtx, verbose bool) DiagnosticResult {
	// Should never be called due to SDKAvailable() check, but provide fallback
	return CheckHealth(logger, verbose)
}

// CheckMonStatusSDK stub - not available on this platform
func CheckMonStatusSDK(logger otelzap.LoggerWithCtx, verbose bool) DiagnosticResult {
	// Should never be called due to SDKAvailable() check, but provide fallback
	return CheckMonStatus(logger)
}
