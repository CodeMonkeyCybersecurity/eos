// cmd/create/hera.go

package create

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consts"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/docker"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var CreateHeraCmd = &cobra.Command{
	Use:   "hera",
	Short: "Deploy Hera (Authentik) for self-service identity & access management",
	Long: `Deploy Hera (Authentik) to /opt/hera by:
- Downloading the latest docker-compose.yml from goauthentik.io
- Generating secrets and writing them to a .env file
- Creating the external Docker network 'arachne-net'
- Running docker compose up -d
- Displaying service status and access URL`,
	Run: func(cmd *cobra.Command, args []string) {
		log := logger.GetLogger()
		log.Info("🚀 Starting Hera (Authentik) deployment")

		// Ensure target directory exists
		if _, err := os.Stat(consts.HeraDir); os.IsNotExist(err) {
			log.Warn("Hera directory does not exist; creating it", zap.String("path", consts.HeraDir))
			if err := os.MkdirAll(consts.HeraDir, 0755); err != nil {
				log.Fatal("Failed to create Hera directory", zap.Error(err))
			}
		}

		// Download the latest docker-compose.yml
		log.Info("📦 Downloading latest docker-compose.yml")
		if err := execute.ExecuteInDir(consts.HeraDir, "wget", "-O", "docker-compose.yml", "https://goauthentik.io/docker-compose.yml"); err != nil {
			log.Fatal("Failed to download docker-compose.yml", zap.Error(err))
		}

		// Generate secrets
		log.Info("🔐 Generating secrets for .env file")
		pgPassCmd := exec.Command("openssl", "rand", "-base64", "36")
		secretKeyCmd := exec.Command("openssl", "rand", "-base64", "60")

		pgPassBytes, err := pgPassCmd.Output()
		if err != nil {
			log.Fatal("Failed to generate PG_PASS", zap.Error(err))
		}
		secretKeyBytes, err := secretKeyCmd.Output()
		if err != nil {
			log.Fatal("Failed to generate AUTHENTIK_SECRET_KEY", zap.Error(err))
		}

		pgPass := strings.TrimSpace(string(pgPassBytes))
		secretKey := strings.TrimSpace(string(secretKeyBytes))

		envContents := []string{
			fmt.Sprintf("PG_PASS=%s", pgPass),
			fmt.Sprintf("AUTHENTIK_SECRET_KEY=%s", secretKey),
			"AUTHENTIK_ERROR_REPORTING__ENABLED=true",
			"COMPOSE_PORT_HTTP=80",
			"COMPOSE_PORT_HTTPS=443",
			"AUTHENTIK_EMAIL__HOST=localhost",
			"AUTHENTIK_EMAIL__PORT=25",
			"AUTHENTIK_EMAIL__USERNAME=",
			"AUTHENTIK_EMAIL__PASSWORD=",
			"AUTHENTIK_EMAIL__USE_TLS=false",
			"AUTHENTIK_EMAIL__USE_SSL=false",
			"AUTHENTIK_EMAIL__TIMEOUT=10",
			"AUTHENTIK_EMAIL__FROM=authentik@localhost",
		}

		envPath := consts.HeraDir + "/.env"
		if err := os.WriteFile(envPath, []byte(strings.Join(envContents, "\n")+"\n"), 0644); err != nil {
			log.Fatal("Failed to write .env file", zap.Error(err))
		}
		log.Info("✅ .env file created", zap.String("path", envPath))

		// Ensure external network
		if err := docker.EnsureArachneNetwork(); err != nil {
			log.Fatal("Could not create or verify arachne-net", zap.Error(err))
		}

		// Pull images and deploy
		log.Info("🐳 Pulling docker images")
		if err := execute.ExecuteInDir(consts.HeraDir, "docker", "compose", "pull"); err != nil {
			log.Fatal("Failed to pull docker images", zap.Error(err))
		}

		log.Info("🚀 Launching Hera via docker compose")
		if err := execute.ExecuteInDir(consts.HeraDir, "docker", "compose", "up", "-d"); err != nil {
			log.Fatal("Failed to run docker compose", zap.Error(err))
		}

		time.Sleep(5 * time.Second)

		log.Info("🔍 Verifying container status")
		if err := docker.CheckDockerContainers(); err != nil {
			log.Warn("Docker containers may not have started cleanly", zap.Error(err))
		}

		fmt.Println("\n🎉 Hera (Authentik) is deploying.")
		fmt.Println("Visit: http://<your-server>:9000/if/flow/initial-setup/")
		fmt.Println("Be sure to include the trailing slash or you may see a 404.")
	},
}

func init() {
	CreateCmd.AddCommand(CreateHeraCmd)
}
