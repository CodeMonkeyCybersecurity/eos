package docker

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RunCredentialsChange updates Wazuh Docker deployment credentials
// Migrated from cmd/create/delphi.go runCredentialsChange
func RunCredentialsChange(rc *eos_io.RuntimeContext, adminPassword, kibanaPassword, apiPassword, deployType string, interactive bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check prerequisites
	logger.Info(" Assessing credentials change prerequisites")

	// Interactive mode prompts
	if interactive {
		if deployType == "" {
			logger.Info("🤔 terminal prompt: Deployment type (single-node or multi-node):")
			fmt.Print("Deployment type (single-node or multi-node): ")
			if _, err := fmt.Scanln(&deployType); err != nil {
				fmt.Printf("Warning: Failed to read deployment type: %v\n", err)
				deployType = "single-node" // Use default
			}
		}

		if adminPassword == "" {
			logger.Info("🔐 terminal prompt: Enter new admin password")
			fmt.Print("Enter new admin password: ")
			if _, err := fmt.Scanln(&adminPassword); err != nil {
				fmt.Printf("Warning: Failed to read admin password: %v\n", err)
				return fmt.Errorf("admin password is required")
			}
		}

		if kibanaPassword == "" {
			logger.Info("🔐 terminal prompt: Enter new Kibana password")
			fmt.Print("Enter new Kibana password: ")
			if _, err := fmt.Scanln(&kibanaPassword); err != nil {
				fmt.Printf("Warning: Failed to read Kibana password: %v\n", err)
				return fmt.Errorf("Kibana password is required")
			}
		}

		if apiPassword == "" {
			logger.Info("🔐 terminal prompt: Enter new API password")
			fmt.Print("Enter new API password: ")
			_, _ = fmt.Scanln(&apiPassword)
		}
	}

	// Validate inputs
	if deployType == "" || adminPassword == "" || kibanaPassword == "" || apiPassword == "" {
		return fmt.Errorf("all parameters required: deploy-type, admin-password, kibana-password, api-password")
	}

	// INTERVENE - Update credentials
	logger.Info("🚀 Updating Wazuh credentials", zap.String("deploy_type", deployType))

	// Change to deployment directory
	deployDir := filepath.Join("/opt/wazuh-docker", deployType)
	if err := os.Chdir(deployDir); err != nil {
		return fmt.Errorf("failed to change to deployment directory: %w", err)
	}

	// Stop containers
	logger.Info("🛑 Stopping containers for credential update")
	if err := exec.Command("docker", "compose", "down").Run(); err != nil {
		logger.Warn(" Failed to stop containers", zap.Error(err))
	}

	// Update admin password
	logger.Info("🔑 Updating admin password")
	if err := UpdateAdminPassword(adminPassword); err != nil {
		return fmt.Errorf("failed to update admin password: %w", err)
	}

	// Update Kibana password
	logger.Info("🔑 Updating Kibana password")
	if err := UpdateKibanaPassword(kibanaPassword); err != nil {
		return fmt.Errorf("failed to update Kibana password: %w", err)
	}

	// Update API password
	logger.Info("🔑 Updating API password")
	if err := UpdateAPIPassword(apiPassword); err != nil {
		return fmt.Errorf("failed to update API password: %w", err)
	}

	// EVALUATE - Restart containers
	logger.Info(" Restarting containers with new credentials")
	if err := exec.Command("docker", "compose", "up", "-d").Run(); err != nil {
		return fmt.Errorf("failed to restart containers: %w", err)
	}

	logger.Info(" Credentials updated successfully")
	return nil
}

// UpdateAdminPassword updates the admin password in Docker configuration
// Migrated from cmd/create/delphi.go updateAdminPassword
func UpdateAdminPassword(password string) error {
	// Update docker-compose.yml
	if err := UpdateComposeFile("INDEXER_PASSWORD=SecretPassword", fmt.Sprintf("INDEXER_PASSWORD=%s", password)); err != nil {
		return err
	}

	// Generate hash and update internal_users.yml
	hash, err := GeneratePasswordHash(password)
	if err != nil {
		return err
	}

	return UpdateInternalUsers("$2y$12$K/SpwjtB.wOHJ/Nc6GVRDuc1h0rM1DfvziFRNPtk27P.c4yDr9njO", hash)
}

// UpdateKibanaPassword updates the Kibana password in Docker configuration
// Migrated from cmd/create/delphi.go updateKibanaPassword
func UpdateKibanaPassword(password string) error {
	// Update docker-compose.yml
	if err := UpdateComposeFile("DASHBOARD_PASSWORD=kibanaserver", fmt.Sprintf("DASHBOARD_PASSWORD=%s", password)); err != nil {
		return err
	}

	// Generate hash and update internal_users.yml
	hash, err := GeneratePasswordHash(password)
	if err != nil {
		return err
	}

	return UpdateInternalUsers("$2a$12$4AcgAt3xwOWadA5s5blL6ev39OXDNhmOesEoo33eZtrq2N0YrU3H.", hash)
}

// UpdateAPIPassword updates the API password in Docker configuration
// Migrated from cmd/create/delphi.go updateAPIPassword
func UpdateAPIPassword(password string) error {
	// Update docker-compose.yml
	if err := UpdateComposeFile("API_PASSWORD=MyS3cr37P450r.*-", fmt.Sprintf("API_PASSWORD=%s", password)); err != nil {
		return err
	}

	// Update wazuh.yml
	return UpdateWazuhYML("API_PASSWORD=MyS3cr37P450r.*-", fmt.Sprintf("API_PASSWORD=%s", password))
}

// UpdateComposeFile updates values in docker-compose.yml
// Migrated from cmd/create/delphi.go updateComposeFile
func UpdateComposeFile(oldValue, newValue string) error {
	return ReplaceInFile("docker-compose.yml", oldValue, newValue)
}

// UpdateInternalUsers updates values in internal_users.yml
// Migrated from cmd/create/delphi.go updateInternalUsers
func UpdateInternalUsers(oldHash, newHash string) error {
	return ReplaceInFile("config/wazuh_indexer/internal_users.yml", oldHash, newHash)
}

// UpdateWazuhYML updates values in wazuh.yml
// Migrated from cmd/create/delphi.go updateWazuhYML
func UpdateWazuhYML(oldValue, newValue string) error {
	return ReplaceInFile("config/wazuh_dashboard/wazuh.yml", oldValue, newValue)
}

// ReplaceInFile replaces a string in a file
// Migrated from cmd/create/delphi.go replaceInFile
func ReplaceInFile(filename, oldValue, newValue string) error {
	content, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	newContent := strings.ReplaceAll(string(content), oldValue, newValue)
	return os.WriteFile(filename, []byte(newContent), 0644)
}

// GeneratePasswordHash generates a bcrypt hash for the given password
// Migrated from cmd/create/delphi.go generatePasswordHash
func GeneratePasswordHash(password string) (string, error) {
	// Use Docker to generate hash
	cmd := exec.Command("docker", "run", "--rm", "-i", "wazuh/wazuh-indexer:latest",
		"bash", "/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh")
	cmd.Stdin = strings.NewReader(password + "\n" + password + "\n")

	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// Parse hash from output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "$") {
			return strings.TrimSpace(line), nil
		}
	}

	return "", fmt.Errorf("failed to extract hash from output")
}
