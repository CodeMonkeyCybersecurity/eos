// cmd/create/hera.go

package create

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"

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
- Using a local docker-compose file if available, otherwise downloading the latest from goauthentik.io
- Generating secrets and writing them to a .env file
- Creating the external Docker network 'arachne-net'
- Fixing directory ownership for proper volume permissions
- Running docker compose up -d and displaying service status & access URL`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := logger.GetLogger()
		log.Info("🚀 Starting Hera (Authentik) deployment")

		// Ensure target directory exists
		if _, err := os.Stat(shared.HeraDir); os.IsNotExist(err) {
			log.Warn("Hera directory does not exist; creating it", zap.String("path", shared.HeraDir))
			if err := os.MkdirAll(shared.HeraDir, shared.DirPermStandard); err != nil {
				log.Fatal("Failed to create Hera directory", zap.Error(err))
			}
		}

		// Check for a local docker-compose file in current directory
		var composeFiles []string
		localYml, err := filepath.Glob("docker-compose.yml")
		if err != nil {
			log.Warn("Error globbing docker-compose.yml", zap.Error(err))
		}
		localYaml, err := filepath.Glob("docker-compose.yaml")
		if err != nil {
			log.Warn("Error globbing docker-compose.yaml", zap.Error(err))
		}
		composeFiles = append(composeFiles, localYml...)
		composeFiles = append(composeFiles, localYaml...)

		if len(composeFiles) > 0 {
			// Use local docker-compose file(s)
			for _, file := range composeFiles {
				destFile := filepath.Join(shared.HeraDir, filepath.Base(file))
				log.Info("📂 Copying local docker-compose file", zap.String("source", file), zap.String("destination", destFile))
				if err := system.CopyFile(file, destFile, 0, log); err != nil {
					log.Fatal("Failed to copy docker-compose file", zap.Error(err))
				}
			}
		} else {
			// Download the latest docker-compose.yml from the remote URL
			log.Info("📦 Downloading latest docker-compose.yml")
			if err := execute.ExecuteInDir(shared.HeraDir, "wget", "-O", "docker-compose.yml", "https://goauthentik.io/docker-compose.yml"); err != nil {
				log.Fatal("Failed to download docker-compose.yml", zap.Error(err))
			}
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

		envPath := filepath.Join(shared.HeraDir, ".env")
		if err := os.WriteFile(envPath, []byte(strings.Join(envContents, "\n")+"\n"), 0644); err != nil {
			log.Fatal("Failed to write .env file", zap.Error(err))
		}
		log.Info("✅ .env file created", zap.String("path", envPath))

		// Fix directory ownership so the container can write as needed.
		log.Info("🔧 Fixing ownership of directory", zap.String("path", shared.HeraDir))
		chownCmd := exec.Command("chown", "-R", "472:472", shared.HeraDir)
		chownCmd.Stdout = os.Stdout
		chownCmd.Stderr = os.Stderr
		if err := chownCmd.Run(); err != nil {
			log.Fatal("Error running chown", zap.Error(err))
		}

		// Ensure external network is present
		if err := docker.EnsureArachneNetwork(); err != nil {
			log.Fatal("Could not create or verify arachne-net", zap.Error(err))
		}

		// Pull images and deploy
		log.Info("🐳 Pulling docker images")
		if err := execute.ExecuteInDir(shared.HeraDir, "docker", "compose", "pull"); err != nil {
			log.Fatal("Failed to pull docker images", zap.Error(err))
		}

		log.Info("🚀 Launching Hera via docker compose")
		if err := execute.ExecuteInDir(shared.HeraDir, "docker", "compose", "up", "-d"); err != nil {
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
		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateHeraCmd)
}
