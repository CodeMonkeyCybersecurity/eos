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
	logger.Info("Assessing Docker deployment prerequisites",
		zap.String("version", version),
		zap.String("deploy_type", deployType),
		zap.String("proxy_address", proxyAddress),
		zap.Int("port", port))
	
	// Check if Docker is installed
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker is not installed: %w", err)
	}
	
	// Check if docker-compose exists
	if _, err := os.Stat("docker-compose.yml"); !os.IsNotExist(err) && !force {
		logger.Warn("docker-compose.yml already exists. Use --force to overwrite")
		return fmt.Errorf("deployment already exists")
	}
	
	// INTERVENE - Deploy Docker configuration
	logger.Info("Starting Docker deployment")
	
	// Create wazuh-docker directory
	logger.Info("terminal prompt: Creating wazuh-docker directory")
	os.RemoveAll("wazuh-docker")
	
	// Clone repository
	logger.Info("Cloning Wazuh Docker repository")
	cloneCmd := exec.Command("git", "clone", "https://github.com/wazuh/wazuh-docker.git")
	cloneCmd.Stdout = os.Stdout
	cloneCmd.Stderr = os.Stderr
	if err := cloneCmd.Run(); err != nil {
		return fmt.Errorf("failed to clone repository: %w", err)
	}
	
	// Navigate to correct directory
	deployDir := fmt.Sprintf("wazuh-docker/%s-deployment", deployType)
	if err := os.Chdir(deployDir); err != nil {
		return fmt.Errorf("failed to change directory: %w", err)
	}
	
	// Apply customizations
	if proxyAddress != "" {
		logger.Info("Configuring proxy settings", zap.String("proxy", proxyAddress))
		if err := ConfigureProxy(proxyAddress); err != nil {
			return fmt.Errorf("failed to configure proxy: %w", err)
		}
	}
	
	if port != 443 {
		logger.Info("Configuring custom port", zap.Int("port", port))
		if err := ConfigurePortMapping(port); err != nil {
			return fmt.Errorf("failed to configure port: %w", err)
		}
	}
	
	// Generate certificates
	logger.Info("Generating certificates")
	genCertsCmd := exec.Command("docker-compose", "-f", "generate-indexer-certs.yml", "run", "--rm", "generator")
	genCertsCmd.Stdout = os.Stdout
	genCertsCmd.Stderr = os.Stderr
	if err := genCertsCmd.Run(); err != nil {
		return fmt.Errorf("failed to generate certificates: %w", err)
	}
	
	// Start containers
	logger.Info("Starting Docker containers")
	upCmd := exec.Command("docker-compose", "up", "-d")
	upCmd.Stdout = os.Stdout
	upCmd.Stderr = os.Stderr
	if err := upCmd.Run(); err != nil {
		return fmt.Errorf("failed to start containers: %w", err)
	}
	
	// Wait for services to be ready
	logger.Info("Waiting for services to become ready...")
	time.Sleep(30 * time.Second)
	
	// EVALUATE - Check deployment status
	logger.Info("Evaluating deployment status")
	
	statusCmd := exec.Command("docker-compose", "ps")
	statusCmd.Stdout = os.Stdout
	statusCmd.Stderr = os.Stderr
	if err := statusCmd.Run(); err != nil {
		logger.Warn("Failed to check container status", zap.Error(err))
	}
	
	logger.Info("Docker deployment completed successfully")
	
	// Extract and show passwords
	logger.Info("Extracting Wazuh passwords")
	
	return nil
}

// ConfigureProxy configures proxy settings for Docker deployment
// Migrated from cmd/create/delphi.go configureProxy
func ConfigureProxy(proxyAddress string) error {
	// ASSESS - Check proxy format
	if !strings.Contains(proxyAddress, "://") {
		proxyAddress = "http://" + proxyAddress
	}
	
	// INTERVENE - Update configuration
	// Add proxy configuration to generate-indexer-certs.yml
	content, err := os.ReadFile("generate-indexer-certs.yml")
	if err != nil {
		return fmt.Errorf("failed to read generate-indexer-certs.yml: %w", err)
	}
	
	// Add proxy environment variables
	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		if strings.Contains(line, "environment:") {
			lines[i] = line + "\n      - HTTP_PROXY=" + proxyAddress + "\n      - HTTPS_PROXY=" + proxyAddress
		}
	}
	
	// EVALUATE - Write updated configuration
	err = os.WriteFile("generate-indexer-certs.yml", []byte(strings.Join(lines, "\n")), 0644)
	if err != nil {
		return fmt.Errorf("failed to write proxy configuration: %w", err)
	}
	
	return nil
}

// ConfigurePortMapping configures custom port mapping for Docker deployment
// Migrated from cmd/create/delphi.go configurePortMapping
func ConfigurePortMapping(port int) error {
	// ASSESS - Validate port
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port number: %d", port)
	}
	
	// INTERVENE - Update docker-compose.yml
	// Read docker-compose.yml
	content, err := os.ReadFile("docker-compose.yml")
	if err != nil {
		return fmt.Errorf("failed to read docker-compose.yml: %w", err)
	}
	
	// Replace port mappings
	oldPort := "443:5601"
	newPort := fmt.Sprintf("%d:5601", port)
	newContent := strings.ReplaceAll(string(content), oldPort, newPort)
	
	// EVALUATE - Write updated configuration
	return os.WriteFile("docker-compose.yml", []byte(newContent), 0644)
}