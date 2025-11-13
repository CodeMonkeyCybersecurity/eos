package docker

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RunCleanup removes Wazuh Docker deployment
// Migrated from cmd/create/wazuh.go runCleanup
func RunCleanup(rc *eos_io.RuntimeContext, removeData, force bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check what needs to be cleaned
	logger.Info("Assessing cleanup requirements",
		zap.Bool("remove_data", removeData),
		zap.Bool("force", force))

	// Check if docker-compose.yml exists
	if _, err := os.Stat("docker-compose.yml"); os.IsNotExist(err) {
		logger.Info("No Docker deployment found to clean")
		return nil
	}

	// Confirm cleanup if not forced
	if !force {
		logger.Info("terminal prompt: Are you sure you want to remove the Wazuh deployment? (yes/no)")
		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}

		input = strings.TrimSpace(input)
		if input != "yes" {
			logger.Info("Cleanup cancelled by user")
			return nil
		}
	}

	// INTERVENE - Perform cleanup
	logger.Info("Starting cleanup")

	// Stop and remove containers
	logger.Info("Stopping and removing containers")
	downCmd := exec.Command("docker-compose", "down", "-v")
	downCmd.Stdout = os.Stdout
	downCmd.Stderr = os.Stderr
	if err := downCmd.Run(); err != nil {
		logger.Warn("Failed to stop containers", zap.Error(err))
	}

	// Remove data if requested
	if removeData {
		logger.Info("Removing persistent data")

		// Remove Docker volumes
		volumesCmd := exec.Command("docker", "volume", "prune", "-f")
		volumesCmd.Stdout = os.Stdout
		volumesCmd.Stderr = os.Stderr
		if err := volumesCmd.Run(); err != nil {
			logger.Warn("Failed to remove volumes", zap.Error(err))
		}

		// Remove local data directories
		dataDirs := []string{"config", "data", "logs", "certs"}
		for _, dir := range dataDirs {
			if err := os.RemoveAll(dir); err != nil {
				logger.Warn("Failed to remove directory",
					zap.String("directory", dir),
					zap.Error(err))
			} else {
				logger.Debug("Removed directory", zap.String("directory", dir))
			}
		}
	}

	// Remove deployment files
	logger.Info("Removing deployment files")
	if err := os.Remove("docker-compose.yml"); err != nil {
		logger.Warn("Failed to remove docker-compose.yml", zap.Error(err))
	}

	if err := os.Remove("generate-indexer-certs.yml"); err != nil {
		logger.Warn("Failed to remove generate-indexer-certs.yml", zap.Error(err))
	}

	// EVALUATE - Verify cleanup
	logger.Info("Evaluating cleanup results")

	// Check if any containers are still running
	psCmd := exec.Command("docker", "ps", "-a", "--filter", "label=com.docker.compose.project=wazuh")
	if output, err := psCmd.Output(); err == nil && len(output) > 0 {
		logger.Warn("Some containers may still exist")
	}

	logger.Info("Cleanup completed successfully")
	return nil
}
