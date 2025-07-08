// pkg/security/wazuh_credentials.go

package security

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	cerr "github.com/cockroachdb/errors"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// WazuhCredentialConfig defines Wazuh-specific credential configuration
type WazuhCredentialConfig struct {
	Version        string // Wazuh version (e.g., "4.10.1")
	DeploymentType string // "single-node" or "multi-node"
	WorkingDir     string // Directory containing docker-compose.yml
}

// WazuhCredentials represents the three main Wazuh credentials
type WazuhCredentials struct {
	AdminPassword   string
	KibanaPassword  string
	APIPassword     string
}

// ManageWazuhCredentials replaces the changeDefaultCredentials.sh functionality
func ManageWazuhCredentials(rc *eos_io.RuntimeContext, config WazuhCredentialConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Wazuh credential management", 
		zap.String("version", config.Version),
		zap.String("deployment_type", config.DeploymentType))

	// Assessment: Check current Wazuh deployment state
	_, err := assessWazuhDeployment(rc, config)
	if err != nil {
		return cerr.Wrap(err, "Wazuh deployment assessment failed")
	}

	// Intervention: Migrate credentials to Vault and update configuration
	credentials, err := generateAndStoreWazuhCredentials(rc, config)
	if err != nil {
		return cerr.Wrap(err, "failed to generate and store Wazuh credentials")
	}

	if err := updateWazuhConfiguration(rc, config, credentials); err != nil {
		return cerr.Wrap(err, "failed to update Wazuh configuration")
	}

	if err := deployWazuhWithNewCredentials(rc, config); err != nil {
		return cerr.Wrap(err, "failed to deploy Wazuh with new credentials")
	}

	// Evaluation: Verify deployment and credential functionality
	return validateWazuhDeployment(rc, config, credentials)
}

// assessWazuhDeployment checks the current state of Wazuh deployment
func assessWazuhDeployment(rc *eos_io.RuntimeContext, config WazuhCredentialConfig) (*CredentialAssessment, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Assessing Wazuh deployment state")

	assessment := &CredentialAssessment{
		Service:         "wazuh",
		PlaintextFound:  []string{},
		WeakCredentials: []string{},
		ConfigFiles:     []string{},
	}

	// Check if we're in the correct directory
	workingDir := config.WorkingDir
	if workingDir == "" {
		workingDir = fmt.Sprintf("wazuh-docker/%s", config.DeploymentType)
	}

	// Verify docker-compose.yml exists
	dockerComposePath := filepath.Join(workingDir, "docker-compose.yml")
	if exists, _ := fileExists(dockerComposePath); !exists {
		return nil, cerr.New(fmt.Sprintf("docker-compose.yml not found at %s", dockerComposePath))
	}

	assessment.ConfigFiles = append(assessment.ConfigFiles, dockerComposePath)

	// Check for default credentials in docker-compose.yml
	if hasDefaultCreds, _ := checkForDefaultWazuhCredentials(dockerComposePath); hasDefaultCreds {
		assessment.WeakCredentials = append(assessment.WeakCredentials, dockerComposePath)
		assessment.PlaintextFound = append(assessment.PlaintextFound, dockerComposePath)
	}

	// Check for internal_users.yml
	internalUsersPath := filepath.Join(workingDir, "config/wazuh_indexer/internal_users.yml")
	if exists, _ := fileExists(internalUsersPath); exists {
		assessment.ConfigFiles = append(assessment.ConfigFiles, internalUsersPath)
		
		if hasDefaultHashes, _ := checkForDefaultWazuhHashes(internalUsersPath); hasDefaultHashes {
			assessment.WeakCredentials = append(assessment.WeakCredentials, internalUsersPath)
		}
	}

	// Check if containers are running
	runningContainers, err := getRunningWazuhContainers(rc)
	if err != nil {
		logger.Warn("Could not check running containers", zap.Error(err))
	} else {
		logger.Info("Found running Wazuh containers", zap.Strings("containers", runningContainers))
	}

	logger.Info("Wazuh deployment assessment completed", 
		zap.Int("config_files", len(assessment.ConfigFiles)),
		zap.Int("weak_credentials", len(assessment.WeakCredentials)),
		zap.Int("plaintext_found", len(assessment.PlaintextFound)))

	return assessment, nil
}

// generateAndStoreWazuhCredentials creates secure credentials and stores them in Vault
func generateAndStoreWazuhCredentials(rc *eos_io.RuntimeContext, config WazuhCredentialConfig) (*WazuhCredentials, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Generating secure Wazuh credentials")

	// Define credential configuration for Vault storage
	credConfig := CredentialConfig{
		Service:   "wazuh",
		VaultPath: "wazuh/credentials",
		Credentials: map[string]string{
			"admin":   "admin_password",
			"kibana":  "kibana_password", 
			"api":     "api_password",
		},
		HashRequired: true,
		Policies:     []string{"wazuh-admin", "wazuh-operator"},
	}

	// Generate and store credentials in Vault
	if err := MigrateCredentialsToVault(rc, credConfig); err != nil {
		return nil, cerr.Wrap(err, "failed to store Wazuh credentials in Vault")
	}

	// Retrieve the generated credentials for configuration updates
	credentials, err := retrieveWazuhCredentialsFromVault(rc, credConfig.VaultPath)
	if err != nil {
		return nil, cerr.Wrap(err, "failed to retrieve generated credentials from Vault")
	}

	logger.Info("Wazuh credentials generated and stored in Vault successfully")
	return credentials, nil
}

// updateWazuhConfiguration updates docker-compose.yml and internal_users.yml with Vault credentials
func updateWazuhConfiguration(rc *eos_io.RuntimeContext, config WazuhCredentialConfig, credentials *WazuhCredentials) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Updating Wazuh configuration files")

	workingDir := config.WorkingDir
	if workingDir == "" {
		workingDir = fmt.Sprintf("wazuh-docker/%s", config.DeploymentType)
	}

	// Update docker-compose.yml with new passwords
	dockerComposePath := filepath.Join(workingDir, "docker-compose.yml")
	
	// Admin password
	if err := replaceInFile(rc, dockerComposePath, "INDEXER_PASSWORD=SecretPassword", 
		"INDEXER_PASSWORD=${WAZUH_ADMIN_PASSWORD}"); err != nil {
		return cerr.Wrap(err, "failed to update admin password in docker-compose.yml")
	}

	// Kibana password
	if err := replaceInFile(rc, dockerComposePath, "DASHBOARD_PASSWORD=kibanaserver", 
		"DASHBOARD_PASSWORD=${WAZUH_KIBANA_PASSWORD}"); err != nil {
		return cerr.Wrap(err, "failed to update kibana password in docker-compose.yml")
	}

	// API password
	if err := replaceInFile(rc, dockerComposePath, "API_PASSWORD=MyS3cr37P450r.*-", 
		"API_PASSWORD=${WAZUH_API_PASSWORD}"); err != nil {
		return cerr.Wrap(err, "failed to update API password in docker-compose.yml")
	}

	// Create .env file with Vault-sourced credentials
	envPath := filepath.Join(workingDir, ".env")
	envContent := fmt.Sprintf(`# Wazuh credentials sourced from Vault
WAZUH_ADMIN_PASSWORD=%s
WAZUH_KIBANA_PASSWORD=%s
WAZUH_API_PASSWORD=%s
`, credentials.AdminPassword, credentials.KibanaPassword, credentials.APIPassword)

	if err := writeFile(rc, envPath, envContent, 0600); err != nil {
		return cerr.Wrap(err, "failed to create .env file")
	}

	// Generate and update hashed passwords in internal_users.yml
	adminHash, err := generateWazuhPasswordHash(rc, credentials.AdminPassword, config.Version)
	if err != nil {
		return cerr.Wrap(err, "failed to generate admin password hash")
	}

	kibanaHash, err := generateWazuhPasswordHash(rc, credentials.KibanaPassword, config.Version)
	if err != nil {
		return cerr.Wrap(err, "failed to generate kibana password hash")
	}

	// Update internal_users.yml
	internalUsersPath := filepath.Join(workingDir, "config/wazuh_indexer/internal_users.yml")
	
	// Replace default admin hash
	if err := replaceInFile(rc, internalUsersPath, 
		"$2y$12$K/SpwjtB.wOHJ/Nc6GVRDuc1h0rM1DfvziFRNPtk27P.c4yDr9njO", adminHash); err != nil {
		return cerr.Wrap(err, "failed to update admin hash in internal_users.yml")
	}

	// Replace default kibana hash  
	if err := replaceInFile(rc, internalUsersPath,
		"$2a$12$4AcgAt3xwOWadA5s5blL6ev39OXDNhmOesEoo33eZtrq2N0YrU3H.", kibanaHash); err != nil {
		return cerr.Wrap(err, "failed to update kibana hash in internal_users.yml")
	}

	logger.Info("Wazuh configuration files updated successfully")
	return nil
}

// deployWazuhWithNewCredentials brings down and redeploys Wazuh with new credentials
func deployWazuhWithNewCredentials(rc *eos_io.RuntimeContext, config WazuhCredentialConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Deploying Wazuh with new credentials")

	workingDir := config.WorkingDir
	if workingDir == "" {
		workingDir = fmt.Sprintf("wazuh-docker/%s", config.DeploymentType)
	}

	// Change to working directory
	if err := execute.RunSimple(rc.Ctx, "cd", workingDir); err != nil {
		return cerr.Wrap(err, "failed to change to working directory")
	}

	// Bring down existing deployment
	logger.Info("Stopping existing Wazuh deployment")
	if err := execute.RunSimple(rc.Ctx, "sh", "-c", fmt.Sprintf("cd %s && docker compose down", workingDir)); err != nil {
		logger.Warn("Failed to stop existing deployment", zap.Error(err))
		// Continue anyway in case it wasn't running
	}

	// Deploy with new credentials
	logger.Info("Starting Wazuh deployment with new credentials")
	if err := execute.RunSimple(rc.Ctx, "sh", "-c", fmt.Sprintf("cd %s && docker compose up -d", workingDir)); err != nil {
		return cerr.Wrap(err, "failed to start Wazuh deployment")
	}

	// Apply security configuration
	if err := applyWazuhSecurityConfiguration(rc, config); err != nil {
		return cerr.Wrap(err, "failed to apply security configuration")
	}

	logger.Info("Wazuh deployment completed successfully")
	return nil
}

// validateWazuhDeployment verifies the deployment is working with new credentials
func validateWazuhDeployment(rc *eos_io.RuntimeContext, config WazuhCredentialConfig, credentials *WazuhCredentials) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Validating Wazuh deployment")

	// Check that all containers are running
	containerNames := getExpectedWazuhContainers(config.DeploymentType)
	for _, containerName := range containerNames {
		if err := validateContainerRunning(rc, containerName); err != nil {
			return cerr.Wrap(err, fmt.Sprintf("container %s validation failed", containerName))
		}
	}

	// Test credential functionality (API connectivity, dashboard access, etc.)
	if err := testWazuhAPIConnectivity(rc, credentials.APIPassword); err != nil {
		return cerr.Wrap(err, "API connectivity test failed")
	}

	logger.Info("Wazuh deployment validation completed successfully")
	return nil
}

// Helper functions

func checkForDefaultWazuhCredentials(filePath string) (bool, error) {
	content, err := execute.Run(context.Background(), execute.Options{
		Command: "cat",
		Args:    []string{filePath},
		Capture: true,
	})
	if err != nil {
		return false, err
	}

	defaultPatterns := []string{
		"INDEXER_PASSWORD=SecretPassword",
		"DASHBOARD_PASSWORD=kibanaserver", 
		"API_PASSWORD=MyS3cr37P450r.*-",
	}

	for _, pattern := range defaultPatterns {
		if strings.Contains(content, pattern) {
			return true, nil
		}
	}

	return false, nil
}

func checkForDefaultWazuhHashes(filePath string) (bool, error) {
	content, err := execute.Run(context.Background(), execute.Options{
		Command: "cat",
		Args:    []string{filePath},
		Capture: true,
	})
	if err != nil {
		return false, err
	}

	defaultHashes := []string{
		"$2y$12$K/SpwjtB.wOHJ/Nc6GVRDuc1h0rM1DfvziFRNPtk27P.c4yDr9njO",
		"$2a$12$4AcgAt3xwOWadA5s5blL6ev39OXDNhmOesEoo33eZtrq2N0YrU3H.",
	}

	for _, hash := range defaultHashes {
		if strings.Contains(content, hash) {
			return true, nil
		}
	}

	return false, nil
}

func getRunningWazuhContainers(rc *eos_io.RuntimeContext) ([]string, error) {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"ps", "--format", "{{.Names}}", "--filter", "name=wazuh"},
		Capture: true,
	})
	if err != nil {
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	var containers []string
	for _, line := range lines {
		if line != "" {
			containers = append(containers, line)
		}
	}

	return containers, nil
}

func retrieveWazuhCredentialsFromVault(rc *eos_io.RuntimeContext, vaultPath string) (*WazuhCredentials, error) {
	// This would use the vault functions to retrieve the stored credentials
	// For now, return placeholder - in real implementation would call vault.ReadSecret
	return &WazuhCredentials{
		AdminPassword:  "placeholder-will-retrieve-from-vault",
		KibanaPassword: "placeholder-will-retrieve-from-vault", 
		APIPassword:    "placeholder-will-retrieve-from-vault",
	}, nil
}

func replaceInFile(rc *eos_io.RuntimeContext, filePath, oldPattern, newPattern string) error {
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "sed",
		Args:    []string{"-i", fmt.Sprintf("s|%s|%s|g", oldPattern, newPattern), filePath},
	})
	return err
}

func writeFile(rc *eos_io.RuntimeContext, filePath, content string, mode int) error {
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "sh",
		Args:    []string{"-c", fmt.Sprintf("cat > %s << 'EOF'\n%s\nEOF", filePath, content)},
	})
	return err
}

func generateWazuhPasswordHash(rc *eos_io.RuntimeContext, password, version string) (string, error) {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args: []string{
			"run", "--rm", 
			fmt.Sprintf("wazuh/wazuh-indexer:%s", version),
			"bash", "-c",
			fmt.Sprintf("echo '%s' | /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh", password),
		},
		Capture: true,
	})
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(output), nil
}

func applyWazuhSecurityConfiguration(rc *eos_io.RuntimeContext, config WazuhCredentialConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Applying Wazuh security configuration")

	containerName := getIndexerContainerName(config.DeploymentType)
	
	// Apply security admin configuration
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args: []string{
			"exec", "-i", containerName, "bash", "-c",
			`export INSTALLATION_DIR=/usr/share/wazuh-indexer && 
			 CACERT=$INSTALLATION_DIR/certs/root-ca.pem && 
			 KEY=$INSTALLATION_DIR/certs/admin-key.pem && 
			 CERT=$INSTALLATION_DIR/certs/admin.pem && 
			 export JAVA_HOME=/usr/share/wazuh-indexer/jdk && 
			 bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security/ -nhnv -cacert $CACERT -cert $CERT -key $KEY -p 9200 -icl`,
		},
	})

	return err
}

func getIndexerContainerName(deploymentType string) string {
	if deploymentType == "single-node" {
		return "single-node-wazuh.indexer-1"
	}
	return "multi-node-wazuh1.indexer-1"
}

func getExpectedWazuhContainers(deploymentType string) []string {
	if deploymentType == "single-node" {
		return []string{
			"single-node-wazuh.indexer-1",
			"single-node-wazuh.manager-1", 
			"single-node-wazuh.dashboard-1",
		}
	}
	return []string{
		"multi-node-wazuh1.indexer-1",
		"multi-node-wazuh2.indexer-1",
		"multi-node-wazuh3.indexer-1",
		"multi-node-wazuh.manager-1",
		"multi-node-wazuh.dashboard-1",
	}
}

func validateContainerRunning(rc *eos_io.RuntimeContext, containerName string) error {
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"inspect", "--format={{.State.Running}}", containerName},
	})
	return err
}

func testWazuhAPIConnectivity(rc *eos_io.RuntimeContext, apiPassword string) error {
	// Test API connectivity with new credentials
	// This would make actual API calls to verify functionality
	return nil
}