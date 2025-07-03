// pkg/backup/docker.go

package backup

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func parseDockerBackupFlags(cmd *cobra.Command) (*container.BackupConfig, error) {
	// Get flags
	backupDir, _ := cmd.Flags().GetString("backup-dir")
	all, _ := cmd.Flags().GetBool("all")
	containers, _ := cmd.Flags().GetBool("containers")
	images, _ := cmd.Flags().GetBool("images")
	volumes, _ := cmd.Flags().GetBool("volumes")
	networks, _ := cmd.Flags().GetBool("networks")
	compose, _ := cmd.Flags().GetBool("compose")
	envVars, _ := cmd.Flags().GetBool("env-vars")
	swarm, _ := cmd.Flags().GetBool("swarm")
	compression, _ := cmd.Flags().GetString("compression")
	parallel, _ := cmd.Flags().GetBool("parallel")
	retention, _ := cmd.Flags().GetInt("retention")
	excludePatterns, _ := cmd.Flags().GetStringSlice("exclude")

	// Set defaults
	if backupDir == "" {
		backupDir = "/opt/backups/docker"
	}

	// If --all is specified, enable all components
	if all {
		containers = true
		images = true
		volumes = true
		networks = true
		compose = true
		envVars = true
		swarm = true
	}

	// If no specific components specified, default to containers and volumes
	if !containers && !images && !volumes && !networks && !compose && !envVars && !swarm {
		containers = true
		volumes = true
		compose = true
	}

	config := &container.BackupConfig{
		BackupDir:         backupDir,
		IncludeContainers: containers,
		IncludeImages:     images,
		IncludeVolumes:    volumes,
		IncludeNetworks:   networks,
		IncludeCompose:    compose,
		IncludeEnvVars:    envVars,
		IncludeSwarm:      swarm,
		CompressionType:   compression,
		Parallel:          parallel,
		Retention:         retention,
		ExcludePatterns:   excludePatterns,
		Metadata: map[string]string{
			"backup_tool": "eos",
			"backup_type": "comprehensive",
		},
	}

	return config, nil
}

func logBackupResults(logger otelzap.LoggerWithCtx, result *container.BackupResult) {
	logger.Info("Docker backup completed",
		zap.Bool("success", result.Success),
		zap.String("backup_path", result.BackupPath),
		zap.Int64("total_size_bytes", result.TotalSize),
		zap.Duration("duration", result.Duration),
		zap.Int("errors_count", len(result.ErrorsEncountered)))

	// Log component results
	for componentType, componentResult := range result.ComponentResults {
		if componentResult.Success {
			logger.Info("Component backup successful",
				zap.String("component", componentType),
				zap.Int("items_backed_up", componentResult.ItemsBackedUp),
				zap.Int64("size_bytes", componentResult.SizeBytes),
				zap.Duration("duration", componentResult.Duration))
		} else {
			logger.Error("Component backup failed",
				zap.String("component", componentType),
				zap.String("error", componentResult.ErrorMessage))
		}
	}

	// Log any errors encountered
	for _, error := range result.ErrorsEncountered {
		logger.Warn("Backup error encountered", zap.String("error", error))
	}

	// Provide user-friendly summary
	sizeGB := float64(result.TotalSize) / (1024 * 1024 * 1024)
	logger.Info("Backup summary",
		zap.String("location", result.BackupPath),
		zap.Float64("size_gb", sizeGB),
		zap.String("duration_human", result.Duration.String()),
		zap.Int("components_successful", countSuccessfulComponents(result)),
		zap.Int("components_total", len(result.ComponentResults)))
}

func countSuccessfulComponents(result *container.BackupResult) int {
	count := 0
	for _, componentResult := range result.ComponentResults {
		if componentResult.Success {
			count++
		}
	}
	return count
}
