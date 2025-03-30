// cmd/deploy/hera.go

package create

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/docker"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateHeraCmd = &cobra.Command{
	Use:   "hera",
	Short: "Deploy Hera (Authentik) for self-service identity & access management",
	Long: `Deploy Hera (Authentik) to /opt/hera by:
- Copying the Docker Compose file from eos/assets/hera-docker-compose.yml
- Replacing all instances of 'changeme' with a secure, random password
- Ensuring the 'arachne-net' Docker network exists
- Running docker compose up -d
- Showing running containers and service access info`,
	Run: func(cmd *cobra.Command, args []string) {
		log := logger.GetLogger()
		log.Info("🚀 Starting Hera (Authentik) deployment")

		// Ensure installation directory exists
		if _, err := os.Stat(config.HeraDir); os.IsNotExist(err) {
			log.Warn("Hera directory does not exist; creating it", zap.String("path", config.HeraDir))
			if err := os.MkdirAll(config.HeraDir, 0755); err != nil {
				log.Fatal("Failed to create Hera directory", zap.Error(err))
			}
		}

		src := "assets/hera-docker-compose.yml"
		dst := config.HeraComposeYML

		// Read compose file
		data, err := os.ReadFile(src)
		if err != nil {
			log.Fatal("Failed to read Hera Compose file", zap.Error(err))
		}

		// Generate password and inject it
		password, err := utils.GeneratePassword(20)
		if err != nil {
			log.Fatal("Failed to generate password", zap.Error(err))
		}
		newData := strings.ReplaceAll(string(data), "changeme", password)
		log.Info("🔐 Password injected into Compose file", zap.String("password", password))

		// Add 'version: "3.8"' if missing
		if !strings.HasPrefix(newData, "version:") {
			newData = "version: \"3.8\"\n" + newData
			log.Info("Inserted Compose version declaration")
		}

		// Write the processed file
		if err := os.WriteFile(dst, []byte(newData), 0644); err != nil {
			log.Fatal("Failed to write processed Compose file", zap.Error(err))
		}
		log.Info("✅ Compose file prepared", zap.String("path", dst))

		// Ensure external network
		if err := docker.EnsureArachneNetwork(); err != nil {
			log.Fatal("Could not create or verify arachne-net", zap.Error(err))
		}

		// Deploy containers
		log.Info("Running docker compose up -d", zap.String("dir", config.HeraDir))
		if err := execute.ExecuteInDir(config.HeraDir, "docker", "compose", "-f", dst, "up", "-d"); err != nil {
			log.Fatal("Failed to run docker compose", zap.Error(err))
		}

		// Wait for services to come up
		time.Sleep(5 * time.Second)
		if err := docker.CheckDockerContainers(); err != nil {
			log.Warn("Docker containers may not have started cleanly", zap.Error(err))
		}

		// Output info
		fmt.Println("\n🔗 Hera is now deploying.")
		fmt.Printf("Access the Authentik UI at: https://hera.cybermonkey.net.au (or your assigned domain)\n")
		fmt.Printf("Admin credentials are likely seeded inside the UI setup. The injected password: %s\n", password)
		fmt.Println("🎉 Deployment complete — follow the web UI instructions to finish setup.")
	},
}

func init() {
	CreateCmd.AddCommand(CreateHeraCmd)
}
