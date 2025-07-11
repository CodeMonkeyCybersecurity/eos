package enrollment

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ParseEnrollmentFlags parses command line flags into EnrollmentConfig
// Migrated from cmd/self/enroll.go parseEnrollmentFlags
func ParseEnrollmentFlags(cmd *cobra.Command) (*EnrollmentConfig, error) {
	// ASSESS - Extract flag values
	role, _ := cmd.Flags().GetString("role")
	masterAddress, _ := cmd.Flags().GetString("master-address")
	datacenter, _ := cmd.Flags().GetString("datacenter")
	networkMode, _ := cmd.Flags().GetString("network-mode")
	autoDetect, _ := cmd.Flags().GetBool("auto-detect")
	transitionMode, _ := cmd.Flags().GetBool("transition-mode")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	
	// INTERVENE - Create configuration
	config := &EnrollmentConfig{
		Role:           role,
		MasterAddress:  masterAddress,
		Datacenter:     datacenter,
		NetworkMode:    networkMode,
		AutoDetect:     autoDetect,
		TransitionMode: transitionMode,
		DryRun:         dryRun,
	}
	
	// EVALUATE - Return parsed configuration
	return config, nil
}

// ValidateEnrollmentConfig validates the enrollment configuration
// Migrated from cmd/self/enroll.go validateEnrollmentConfig
func ValidateEnrollmentConfig(config *EnrollmentConfig) error {
	// ASSESS - Check required fields
	if config.Datacenter == "" {
		return fmt.Errorf("datacenter is required")
	}
	
	if !config.AutoDetect && config.Role == "" {
		return fmt.Errorf("role is required unless --auto-detect is specified")
	}
	
	// INTERVENE - Validate role-specific requirements
	if config.Role == RoleMinion && config.MasterAddress == "" {
		return fmt.Errorf("master-address is required for minion role")
	}
	
	if config.Role == RoleMaster && config.MasterAddress != "" {
		return fmt.Errorf("master-address should not be specified for master role")
	}
	
	// Validate network mode
	validNetworkModes := []string{NetworkModeDirect, NetworkModeConsul, NetworkModeWireGuard}
	if config.NetworkMode != "" {
		found := false
		for _, mode := range validNetworkModes {
			if config.NetworkMode == mode {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("invalid network-mode: %s (valid options: %v)", config.NetworkMode, validNetworkModes)
		}
	}
	
	// EVALUATE - Configuration is valid
	return nil
}

// DetectRole automatically detects the appropriate role based on system characteristics
// Migrated from cmd/self/enroll.go detectRole
func DetectRole(rc *eos_io.RuntimeContext, info *SystemInfo) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Analyze system characteristics
	logger.Info("🔍 Assessing system characteristics for role detection",
		zap.Int("cpu_cores", info.CPUCores),
		zap.Int("memory_gb", info.MemoryGB),
		zap.Int("disk_gb", info.DiskSpaceGB))
	
	// INTERVENE - Apply role detection heuristics
	logger.Debug("Analyzing system resources for role detection",
		zap.Int("cpu_cores", info.CPUCores),
		zap.Int("memory_gb", info.MemoryGB),
		zap.Int("disk_gb", info.DiskSpaceGB))
	
	// Simple heuristics for role detection
	// TODO: 2025-01-09T22:00:00Z - Implement more sophisticated role detection
	// Could check for:
	// - Existing infrastructure (consul, nomad, etc.)
	// - Network topology
	// - System resources
	// - Environment variables
	// - Configuration files
	
	// High-resource systems default to master
	if info.CPUCores >= 4 && info.MemoryGB >= 8 {
		logger.Info("✅ Detected high-resource system, suggesting master role",
			zap.Int("cpu_cores", info.CPUCores),
			zap.Int("memory_gb", info.MemoryGB))
		return RoleMaster, nil
	}
	
	// EVALUATE - Lower-resource systems default to minion
	logger.Info("📊 Detected standard system, suggesting minion role",
		zap.Int("cpu_cores", info.CPUCores),
		zap.Int("memory_gb", info.MemoryGB))
	return RoleMinion, nil
}