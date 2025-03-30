// cmd/create/hera.go

package create

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/docker"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateHeraCmd = &cobra.Command{
	Use:   "hera",
	Short: "Deploy Hera (Authentik) for self-service identity & access management",
	Run: func(cmd *cobra.Command, args []string) {
		log := logger.GetLogger()
		log.Info("Starting Hera (Authentik) deployment...")

		if err := deployHera(); err != nil {
			log.Error("Hera deployment failed", zap.Error(err))
			fmt.Println("Hera deployment failed:", err)
			os.Exit(1)
		}

		log.Info("✅ Hera successfully deployed")
		fmt.Println("Hera available at https://hera.domain.com")
	},
}

func deployHera() error {
	log := logger.GetLogger()

	// Ensure Docker is installed
	if err := docker.CheckIfDockerInstalled(); err != nil {
		return fmt.Errorf("docker check failed: %w", err)
	}

	// Ensure Docker Compose is installed
	if err := docker.CheckIfDockerComposeInstalled(); err != nil {
		return fmt.Errorf("docker-compose check failed: %w", err)
	}

	// Create target directory if it doesn't exist
	if err := os.MkdirAll(config.HeraDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", config.HeraDir, err)
	}

	// Copy the compose file if it doesn't exist in the target directory
	if _, err := os.Stat(config.HeraComposeYML); os.IsNotExist(err) {
		// Assume assets directory is relative to the current working directory
		src := filepath.Join("assets", "hera-docker-compose.yml")
		dst := config.HeraComposeYML
		log.Info("Copying compose file", zap.String("from", src), zap.String("to", dst))
		if err := copyFile(src, dst); err != nil {
			return fmt.Errorf("failed to copy compose file: %w", err)
		}
	}

	// Run docker compose up
	log.Info("Running docker compose up...")
	if err := docker.RunCommand("docker", "compose", "-f", config.HeraComposeYML, "up", "-d"); err != nil {
		return fmt.Errorf("failed to run docker compose: %w", err)
	}

	return nil
}

// copyFile copies a file from src to dst.
func copyFile(src, dst string) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("could not stat source file: %w", err)
	}

	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}

	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("could not open source file: %w", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("could not create destination file: %w", err)
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return fmt.Errorf("copy failed: %w", err)
	}

	// Optionally, copy file permissions.
	if err := os.Chmod(dst, sourceFileStat.Mode()); err != nil {
		return fmt.Errorf("chmod failed: %w", err)
	}

	return nil
}

func init() {

	CreateCmd.AddCommand(CreateHeraCmd)

}
