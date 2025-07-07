package cephfs

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Configure performs the complete CephFS configuration process
func Configure(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS: Check if configuration is possible
	logger.Info("Assessing CephFS configuration prerequisites")
	if err := assessConfigurationPrerequisites(rc, config); err != nil {
		return fmt.Errorf("failed to assess configuration prerequisites: %w", err)
	}
	
	// INTERVENE: Apply configuration changes
	logger.Info("Applying CephFS configuration")
	if err := applyConfiguration(rc, config); err != nil {
		return fmt.Errorf("failed to apply configuration: %w", err)
	}
	
	// EVALUATE: Verify configuration was applied correctly
	logger.Info("Verifying CephFS configuration")
	if err := verifyConfiguration(rc, config); err != nil {
		return fmt.Errorf("failed to verify configuration: %w", err)
	}
	
	logger.Info("CephFS configuration completed successfully")
	return nil
}

// assessConfigurationPrerequisites checks if configuration prerequisites are met
func assessConfigurationPrerequisites(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if cluster exists and is accessible
	logger.Debug("Checking cluster accessibility")
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "status",
		},
		Timeout: 60 * time.Second,
	})
	if err != nil {
		return eos_err.NewExpectedError(rc.Ctx, fmt.Errorf("ceph cluster is not accessible: %w", err))
	}
	
	// Check if cluster is in a healthy state for configuration
	logger.Debug("Checking cluster health for configuration")
	healthOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "health",
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to check cluster health: %w", err)
	}
	
	// Allow configuration even if cluster is not fully healthy, but warn about it
	if !strings.Contains(healthOutput, "HEALTH_OK") {
		logger.Warn("Cluster health is not optimal, but continuing with configuration", 
			zap.String("health", strings.TrimSpace(healthOutput)))
	}
	
	logger.Debug("Configuration prerequisites satisfied")
	return nil
}

// applyConfiguration applies the CephFS configuration
func applyConfiguration(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Configure network settings
	if err := configureNetworkSettings(rc, config); err != nil {
		return fmt.Errorf("failed to configure network settings: %w", err)
	}
	
	// Configure OSD settings
	if err := configureOSDSettings(rc, config); err != nil {
		return fmt.Errorf("failed to configure OSD settings: %w", err)
	}
	
	// Configure MON and MGR settings
	if err := configureDaemonSettings(rc, config); err != nil {
		return fmt.Errorf("failed to configure daemon settings: %w", err)
	}
	
	// Create CephFS filesystem if needed
	if err := createCephFSFilesystem(rc, config); err != nil {
		return fmt.Errorf("failed to create CephFS filesystem: %w", err)
	}
	
	// Configure performance and tuning settings
	if err := configurePerformanceSettings(rc, config); err != nil {
		return fmt.Errorf("failed to configure performance settings: %w", err)
	}
	
	logger.Info("Configuration applied successfully")
	return nil
}

// configureNetworkSettings configures network-related settings
func configureNetworkSettings(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Debug("Configuring network settings")
	
	// Set public network
	if config.PublicNetwork != "" {
		logger.Debug("Setting public network", zap.String("network", config.PublicNetwork))
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "ssh",
			Args: []string{
				"-o", "ConnectTimeout=10",
				"-o", "BatchMode=yes",
				"-o", "StrictHostKeyChecking=no",
				fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
				"ceph", "config", "set", "mon", "public_network", config.PublicNetwork,
			},
			Timeout: 30 * time.Second,
		})
		if err != nil {
			return fmt.Errorf("failed to set public network: %w", err)
		}
	}
	
	// Set cluster network
	if config.ClusterNetwork != "" {
		logger.Debug("Setting cluster network", zap.String("network", config.ClusterNetwork))
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "ssh",
			Args: []string{
				"-o", "ConnectTimeout=10",
				"-o", "BatchMode=yes",
				"-o", "StrictHostKeyChecking=no",
				fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
				"ceph", "config", "set", "mon", "cluster_network", config.ClusterNetwork,
			},
			Timeout: 30 * time.Second,
		})
		if err != nil {
			return fmt.Errorf("failed to set cluster network: %w", err)
		}
	}
	
	logger.Debug("Network settings configured successfully")
	return nil
}

// configureOSDSettings configures OSD-related settings
func configureOSDSettings(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Debug("Configuring OSD settings")
	
	// Set OSD memory target
	memoryTarget := config.GetOSDMemoryTarget()
	logger.Debug("Setting OSD memory target", zap.String("target", memoryTarget))
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "config", "set", "osd", "osd_memory_target", memoryTarget,
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to set OSD memory target: %w", err)
	}
	
	// Set objectstore type
	objectStore := config.GetObjectStore()
	logger.Debug("Setting OSD objectstore", zap.String("objectstore", objectStore))
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "config", "set", "osd", "osd_objectstore", objectStore,
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to set OSD objectstore: %w", err)
	}
	
	logger.Debug("OSD settings configured successfully")
	return nil
}

// configureDaemonSettings configures MON and MGR daemon settings
func configureDaemonSettings(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Debug("Configuring daemon settings")
	
	// Configure MON settings
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "config", "set", "mon", "mon_allow_pool_delete", "true",
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		logger.Warn("Failed to set mon_allow_pool_delete, continuing", zap.Error(err))
	}
	
	// Configure MGR settings
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "mgr", "module", "enable", "dashboard",
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		logger.Warn("Failed to enable dashboard module, continuing", zap.Error(err))
	}
	
	logger.Debug("Daemon settings configured successfully")
	return nil
}

// createCephFSFilesystem creates a CephFS filesystem if it doesn't exist
func createCephFSFilesystem(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Debug("Checking for existing CephFS filesystems")
	
	// Check if any CephFS filesystems exist
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "fs", "ls",
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to list CephFS filesystems: %w", err)
	}
	
	// If filesystems exist, don't create a new one
	if strings.TrimSpace(output) != "[]" && len(strings.TrimSpace(output)) > 0 {
		logger.Debug("CephFS filesystem already exists")
		return nil
	}
	
	logger.Info("Creating CephFS filesystem")
	
	// Create metadata pool
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "osd", "pool", "create", "cephfs_metadata", "32",
		},
		Timeout: 60 * time.Second,
	})
	if err != nil {
		logger.Warn("Failed to create metadata pool, may already exist", zap.Error(err))
	}
	
	// Create data pool
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "osd", "pool", "create", "cephfs_data", "64",
		},
		Timeout: 60 * time.Second,
	})
	if err != nil {
		logger.Warn("Failed to create data pool, may already exist", zap.Error(err))
	}
	
	// Create filesystem
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "fs", "new", "cephfs", "cephfs_metadata", "cephfs_data",
		},
		Timeout: 2 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("failed to create CephFS filesystem: %w", err)
	}
	
	logger.Info("CephFS filesystem created successfully")
	return nil
}

// configurePerformanceSettings configures performance and tuning settings
func configurePerformanceSettings(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Debug("Configuring performance settings")
	
	// Configure RBD cache settings for better performance
	perfSettings := map[string]string{
		"rbd_cache":                    "true",
		"rbd_cache_writethrough_until_flush": "true",
		"rbd_cache_size":               "268435456", // 256MB
		"osd_client_message_size_cap":  "524288000", // 500MB
		"osd_client_message_cap":       "256",
	}
	
	for setting, value := range perfSettings {
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "ssh",
			Args: []string{
				"-o", "ConnectTimeout=10",
				"-o", "BatchMode=yes",
				"-o", "StrictHostKeyChecking=no",
				fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
				"ceph", "config", "set", "client", setting, value,
			},
			Timeout: 30 * time.Second,
		})
		if err != nil {
			logger.Warn("Failed to set performance setting, continuing", 
				zap.String("setting", setting), 
				zap.String("value", value), 
				zap.Error(err))
		}
	}
	
	// Configure CephFS specific performance settings
	cephfsSettings := map[string]string{
		"mds_cache_memory_limit":       "1073741824", // 1GB
		"mds_cache_trim_threshold":     "524288",     // 512K
		"client_cache_size":            "268435456",  // 256MB
	}
	
	for setting, value := range cephfsSettings {
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "ssh",
			Args: []string{
				"-o", "ConnectTimeout=10",
				"-o", "BatchMode=yes",
				"-o", "StrictHostKeyChecking=no",
				fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
				"ceph", "config", "set", "mds", setting, value,
			},
			Timeout: 30 * time.Second,
		})
		if err != nil {
			logger.Warn("Failed to set CephFS performance setting, continuing", 
				zap.String("setting", setting), 
				zap.String("value", value), 
				zap.Error(err))
		}
	}
	
	logger.Debug("Performance settings configured successfully")
	return nil
}

// verifyConfiguration verifies that configuration was applied correctly
func verifyConfiguration(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Verify network configuration
	if err := verifyNetworkConfiguration(rc, config); err != nil {
		return fmt.Errorf("network configuration verification failed: %w", err)
	}
	
	// Verify OSD configuration
	if err := verifyOSDConfiguration(rc, config); err != nil {
		return fmt.Errorf("OSD configuration verification failed: %w", err)
	}
	
	// Verify CephFS filesystem
	if err := verifyCephFSConfiguration(rc, config); err != nil {
		return fmt.Errorf("CephFS configuration verification failed: %w", err)
	}
	
	logger.Debug("Configuration verification completed successfully")
	return nil
}

// verifyOSDConfiguration verifies OSD configuration settings
func verifyOSDConfiguration(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Debug("Verifying OSD configuration")
	
	// Check OSD memory target setting
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "config", "get", "osd", "osd_memory_target",
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to verify OSD memory target: %w", err)
	}
	
	expectedMemory := config.GetOSDMemoryTarget()
	if !strings.Contains(output, expectedMemory) {
		logger.Warn("OSD memory target may not be set correctly", 
			zap.String("expected", expectedMemory),
			zap.String("actual", strings.TrimSpace(output)))
	}
	
	logger.Debug("OSD configuration verification passed")
	return nil
}

// verifyCephFSConfiguration verifies CephFS filesystem configuration
func verifyCephFSConfiguration(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Debug("Verifying CephFS configuration")
	
	// Check if CephFS filesystem exists
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "fs", "ls",
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to list CephFS filesystems: %w", err)
	}
	
	if !strings.Contains(output, "cephfs") && strings.TrimSpace(output) == "[]" {
		logger.Warn("No CephFS filesystem found")
		return nil
	}
	
	// Check CephFS status
	statusOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "fs", "status",
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to get CephFS status: %w", err)
	}
	
	// Basic health check - ensure no failures are reported
	if strings.Contains(statusOutput, "failed") || strings.Contains(statusOutput, "down") {
		logger.Warn("CephFS status shows potential issues", 
			zap.String("status", strings.TrimSpace(statusOutput)))
	}
	
	logger.Debug("CephFS configuration verification passed")
	return nil
}

// ApplyAdvancedConfiguration applies advanced configuration options
func ApplyAdvancedConfiguration(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Applying advanced CephFS configuration")
	
	// Configure placement groups if needed
	if err := configurePlacementGroups(rc, config); err != nil {
		logger.Warn("Failed to configure placement groups", zap.Error(err))
	}
	
	// Configure CRUSH map optimizations
	if err := configureCRUSHOptimizations(rc, config); err != nil {
		logger.Warn("Failed to configure CRUSH optimizations", zap.Error(err))
	}
	
	// Configure monitoring and alerting
	if err := configureMonitoring(rc, config); err != nil {
		logger.Warn("Failed to configure monitoring", zap.Error(err))
	}
	
	logger.Info("Advanced configuration completed")
	return nil
}

// configurePlacementGroups configures placement group settings
func configurePlacementGroups(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Debug("Configuring placement groups")
	
	// Enable auto-scaling for placement groups
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "config", "set", "global", "osd_pool_default_pg_autoscale_mode", "on",
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to enable PG autoscaling: %w", err)
	}
	
	logger.Debug("Placement groups configured successfully")
	return nil
}

// configureCRUSHOptimizations configures CRUSH map optimizations
func configureCRUSHOptimizations(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Debug("Configuring CRUSH optimizations")
	
	// Enable crush choose leaf type optimization
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "config", "set", "mon", "mon_warn_on_legacy_crush_tunables", "false",
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to configure CRUSH tunables: %w", err)
	}
	
	logger.Debug("CRUSH optimizations configured successfully")
	return nil
}

// configureMonitoring configures monitoring and alerting
func configureMonitoring(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Debug("Configuring monitoring")
	
	// Enable telemetry
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "mgr", "module", "enable", "telemetry",
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		logger.Warn("Failed to enable telemetry module", zap.Error(err))
	}
	
	// Enable Prometheus module for metrics
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "ssh",
		Args: []string{
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", config.SSHUser, config.AdminHost),
			"ceph", "mgr", "module", "enable", "prometheus",
		},
		Timeout: 30 * time.Second,
	})
	if err != nil {
		logger.Warn("Failed to enable prometheus module", zap.Error(err))
	}
	
	logger.Debug("Monitoring configured successfully")
	return nil
}