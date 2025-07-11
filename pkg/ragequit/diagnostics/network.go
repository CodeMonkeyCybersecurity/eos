package diagnostics

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit/system"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NetworkDiagnostics runs network diagnostics
// Migrated from cmd/ragequit/ragequit.go networkDiagnostics
func NetworkDiagnostics(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Prepare for network diagnostics
	logger.Info("Assessing network diagnostics requirements")
	
	homeDir := system.GetHomeDir()
	outputFile := filepath.Join(homeDir, "ragequit-network.txt")
	
	var output strings.Builder
	output.WriteString("=== Network Diagnostics ===\n")
	output.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format(time.RFC3339)))
	
	// INTERVENE - Collect network information
	logger.Debug("Collecting network information")
	
	// Network listeners
	output.WriteString("\n--- Network Listeners ---\n")
	if netListeners := system.RunCommandWithTimeout("ss", []string{"-tlnp"}, 5*time.Second); netListeners != "" {
		output.WriteString(netListeners)
		output.WriteString("\n")
	} else if netListeners := system.RunCommandWithTimeout("netstat", []string{"-tlnp"}, 5*time.Second); netListeners != "" {
		output.WriteString(netListeners)
		output.WriteString("\n")
	}
	
	// Network interfaces
	output.WriteString("\n--- Network Interfaces ---\n")
	if netInterfaces := system.RunCommandWithTimeout("ip", []string{"addr"}, 5*time.Second); netInterfaces != "" {
		output.WriteString(netInterfaces)
		output.WriteString("\n")
	} else if netInterfaces := system.RunCommandWithTimeout("ifconfig", []string{"-a"}, 5*time.Second); netInterfaces != "" {
		output.WriteString(netInterfaces)
		output.WriteString("\n")
	}
	
	// Routing table
	output.WriteString("\n--- Routing Table ---\n")
	if routes := system.RunCommandWithTimeout("ip", []string{"route"}, 5*time.Second); routes != "" {
		output.WriteString(routes)
		output.WriteString("\n")
	} else if routes := system.RunCommandWithTimeout("route", []string{"-n"}, 5*time.Second); routes != "" {
		output.WriteString(routes)
		output.WriteString("\n")
	}
	
	// DNS configuration
	output.WriteString("\n--- DNS Configuration ---\n")
	if resolv := system.ReadFile("/etc/resolv.conf"); resolv != "" {
		output.WriteString(resolv)
		output.WriteString("\n")
	}
	
	// Active connections
	output.WriteString("\n--- Active Connections ---\n")
	if activeConns := system.RunCommandWithTimeout("ss", []string{"-anp"}, 5*time.Second); activeConns != "" {
		// Limit output to prevent huge files
		lines := strings.Split(activeConns, "\n")
		if len(lines) > 100 {
			output.WriteString(strings.Join(lines[:100], "\n"))
			output.WriteString("\n... (truncated to first 100 connections)\n")
		} else {
			output.WriteString(activeConns)
		}
		output.WriteString("\n")
	}
	
	// Connection statistics
	output.WriteString("\n--- Connection Statistics ---\n")
	if connStats := system.RunCommandWithTimeout("ss", []string{"-s"}, 5*time.Second); connStats != "" {
		output.WriteString(connStats)
		output.WriteString("\n")
	}
	
	// EVALUATE - Write results
	if err := os.WriteFile(outputFile, []byte(output.String()), 0644); err != nil {
		return fmt.Errorf("failed to write network diagnostics: %w", err)
	}
	
	logger.Info("Network diagnostics completed",
		zap.String("output_file", outputFile))
	
	return nil
}