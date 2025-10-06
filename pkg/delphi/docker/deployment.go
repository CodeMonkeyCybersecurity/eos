package docker

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RunDeployment runs Docker deployment for Delphi
// Migrated from cmd/create/delphi.go runDockerDeployment
func RunDeployment(rc *eos_io.RuntimeContext, version, deployType, proxyAddress string, port int, force bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check prerequisites
	logger.Info(" Assessing Docker deployment prerequisites",
		zap.String("version", version),
		zap.String("deploy_type", deployType),
		zap.String("proxy_address", proxyAddress),
		zap.Int("port", port))

	// Check if Docker is installed
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker is not installed: %w", err)
	}

	// Interactive prompts if needed
	if version == "" {
		logger.Info("🔤 terminal prompt: Enter Wazuh version (e.g., 4.10.1)")
		fmt.Print("Enter Wazuh version (e.g., 4.10.1): ")
		fmt.Scanln(&version)
	}

	if deployType == "" {
		logger.Info("🔢 terminal prompt: Deployment type (1 for single-node, 2 for multi-node)")
		fmt.Print("Deployment type (1 for single-node, 2 for multi-node): ")
		var choice string
		fmt.Scanln(&choice)
		switch choice {
		case "1":
			deployType = "single-node"
		case "2":
			deployType = "multi-node"
		default:
			return fmt.Errorf("invalid deployment type choice")
		}
	}

	if proxyAddress == "" {
		logger.Info("🌐 terminal prompt: Enter proxy address (or press Enter to skip)")
		fmt.Print("Enter proxy address (or press Enter to skip): ")
		fmt.Scanln(&proxyAddress)
	}

	// INTERVENE - Deploy Docker configuration
	logger.Info("🚀 Starting Docker deployment")

	// Change to /opt directory
	if err := os.Chdir("/opt"); err != nil {
		return fmt.Errorf("failed to change to /opt directory: %w", err)
	}

	// Clean up any existing installation
	if !force {
		logger.Info("❓ terminal prompt: Remove any existing Wazuh installation? [Y/n]")
		fmt.Print("Remove any existing Wazuh installation? [Y/n]: ")
		var response string
		fmt.Scanln(&response)
		if response != "n" && response != "N" {
			logger.Info("🗑️ Removing existing wazuh-docker directory")
			if err := exec.Command("rm", "-rf", "wazuh-docker").Run(); err != nil {
				logger.Warn("Failed to remove wazuh-docker directory", zap.Error(err))
			}
		}
	} else {
		if err := exec.Command("rm", "-rf", "wazuh-docker").Run(); err != nil {
			logger.Warn("Failed to remove wazuh-docker directory", zap.Error(err))
		}
	}

	// Set vm.max_map_count for Elasticsearch
	logger.Info("⚙️ Setting vm.max_map_count for Elasticsearch")
	if err := exec.Command("sysctl", "-w", "vm.max_map_count=262144").Run(); err != nil {
		logger.Warn("⚠️ Failed to set vm.max_map_count", zap.Error(err))
	}

	// Clone repository
	logger.Info(" Cloning Wazuh Docker repository", zap.String("version", version))
	cloneCmd := exec.Command("git", "clone", "https://github.com/wazuh/wazuh-docker.git", "-b", "v"+version)
	cloneCmd.Stdout = os.Stdout
	cloneCmd.Stderr = os.Stderr
	if err := cloneCmd.Run(); err != nil {
		return fmt.Errorf("failed to clone repository: %w", err)
	}

	// Navigate to correct directory
	deployDir := fmt.Sprintf("wazuh-docker/%s", deployType)
	if err := os.Chdir(deployDir); err != nil {
		return fmt.Errorf("failed to change directory: %w", err)
	}

	// Apply customizations
	if proxyAddress != "" {
		logger.Info(" Configuring proxy settings", zap.String("proxy", proxyAddress))
		if err := ConfigureProxy(proxyAddress); err != nil {
			logger.Warn("⚠️ Failed to configure proxy", zap.Error(err))
		}
	}

	if port != 443 {
		logger.Info(" Configuring custom port for Hecate compatibility", zap.Int("port", port))
		if err := ConfigurePortMapping(port); err != nil {
			logger.Warn("⚠️ Failed to configure port mapping", zap.Error(err))
		}
	}

	// Generate certificates
	logger.Info("🔐 Generating indexer certificates")
	genCertsCmd := exec.Command("docker", "compose", "-f", "generate-indexer-certs.yml", "run", "--rm", "generator")
	genCertsCmd.Stdout = os.Stdout
	genCertsCmd.Stderr = os.Stderr
	if err := genCertsCmd.Run(); err != nil {
		return fmt.Errorf("failed to generate certificates: %w", err)
	}

	// Start containers
	logger.Info("🐳 Starting Wazuh containers")
	upCmd := exec.Command("docker", "compose", "up", "-d")
	upCmd.Stdout = os.Stdout
	upCmd.Stderr = os.Stderr
	if err := upCmd.Run(); err != nil {
		return fmt.Errorf("failed to start containers: %w", err)
	}

	// Set file permissions
	if err := exec.Command("chmod", "660", "*.conf").Run(); err != nil {
		logger.Warn("⚠️ Failed to set file permissions", zap.Error(err))
	}

	// Wait for services to be ready
	logger.Info("⏳ Waiting for services to become ready...")
	time.Sleep(30 * time.Second)

	// EVALUATE - Check deployment status
	logger.Info("📊 Evaluating deployment status")

	statusCmd := exec.Command("docker", "compose", "ps")
	statusCmd.Stdout = os.Stdout
	statusCmd.Stderr = os.Stderr
	if err := statusCmd.Run(); err != nil {
		logger.Warn("⚠️ Failed to check container status", zap.Error(err))
	}

	logger.Info(" Wazuh Docker deployment completed successfully")

	return nil
}

// ConfigureProxy configures proxy settings for Docker deployment
// Migrated from cmd/create/delphi.go configureProxy
func ConfigureProxy(proxyAddress string) error {
	// ASSESS - Validate proxy format
	// Add proxy configuration to generate-indexer-certs.yml
	proxyConfig := fmt.Sprintf(`
    environment:
      - HTTP_PROXY=%s
      - HTTPS_PROXY=%s`, proxyAddress, proxyAddress)

	// INTERVENE - Append proxy configuration
	file, err := os.OpenFile("generate-indexer-certs.yml", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			fmt.Printf("Warning: Failed to close file: %v\n", err)
		}
	}()

	// EVALUATE - Write configuration
	_, err = file.WriteString(proxyConfig)
	return err
}

// ConfigurePortMapping configures custom port mapping for Docker deployment
// Migrated from cmd/create/delphi.go configurePortMapping
func ConfigurePortMapping(port int) error {
	// ASSESS - Read current configuration
	content, err := os.ReadFile("docker-compose.yml")
	if err != nil {
		return err
	}

	// INTERVENE - Replace port mapping
	oldMapping := "- 443:5601"
	newMapping := fmt.Sprintf("- %d:5601", port)
	newContent := strings.ReplaceAll(string(content), oldMapping, newMapping)

	// EVALUATE - Write updated configuration
	return os.WriteFile("docker-compose.yml", []byte(newContent), 0644)
}
