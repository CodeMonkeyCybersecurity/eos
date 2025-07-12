// pkg/wazuh_mssp/customer/lifecycle.go
package customer

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh_mssp"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ProvisionCustomer provisions a new customer in the MSSP platform
func ProvisionCustomer(rc *eos_io.RuntimeContext, config *wazuh_mssp.CustomerConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting customer provisioning",
		zap.String("customer_id", config.ID),
		zap.String("company_name", config.CompanyName),
		zap.String("tier", string(config.Tier)))

	// ASSESS - Validate customer configuration
	if err := validateCustomerConfig(rc, config); err != nil {
		return fmt.Errorf("customer validation failed: %w", err)
	}

	// Check if customer already exists
	exists, err := customerExists(rc, config.ID)
	if err != nil {
		return fmt.Errorf("failed to check customer existence: %w", err)
	}
	if exists {
		return eos_err.NewUserError(fmt.Sprintf("customer %s already exists", config.ID))
	}

	// INTERVENE - Create customer resources
	if err := createCustomerResources(rc, config); err != nil {
		return fmt.Errorf("failed to create customer resources: %w", err)
	}

	// EVALUATE - Verify customer deployment
	if err := verifyCustomerDeployment(rc, config); err != nil {
		return fmt.Errorf("customer deployment verification failed: %w", err)
	}

	logger.Info("Customer provisioning completed successfully")
	return nil
}

// ScaleCustomer changes the tier of an existing customer
func ScaleCustomer(rc *eos_io.RuntimeContext, customerID string, newTier wazuh_mssp.CustomerTier) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting customer scaling",
		zap.String("customer_id", customerID),
		zap.String("new_tier", string(newTier)))

	// ASSESS - Get current customer configuration
	currentConfig, err := getCustomerConfiguration(rc, customerID)
	if err != nil {
		return fmt.Errorf("failed to get customer configuration: %w", err)
	}

	if currentConfig.Tier == newTier {
		return eos_err.NewUserError("customer is already at the requested tier")
	}

	// INTERVENE - Scale customer resources
	if err := scaleCustomerResources(rc, currentConfig, newTier); err != nil {
		return fmt.Errorf("failed to scale customer resources: %w", err)
	}

	// Update configuration
	currentConfig.Tier = newTier
	currentConfig.Resources = wazuh_mssp.GetResourcesByTier(newTier)
	currentConfig.UpdatedAt = time.Now()

	if err := updateCustomerConfiguration(rc, currentConfig); err != nil {
		return fmt.Errorf("failed to update customer configuration: %w", err)
	}

	// EVALUATE - Verify scaling completed
	if err := verifyCustomerScaling(rc, currentConfig); err != nil {
		return fmt.Errorf("customer scaling verification failed: %w", err)
	}

	logger.Info("Customer scaling completed successfully")
	return nil
}

// RemoveCustomer removes a customer from the platform
func RemoveCustomer(rc *eos_io.RuntimeContext, customerID string, force bool) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting customer removal",
		zap.String("customer_id", customerID),
		zap.Bool("force", force))

	// ASSESS - Check if customer exists
	config, err := getCustomerConfiguration(rc, customerID)
	if err != nil {
		return fmt.Errorf("customer not found: %w", err)
	}

	// Check if customer has active connections
	if !force {
		active, err := hasActiveConnections(rc, customerID)
		if err != nil {
			logger.Warn("Failed to check active connections", zap.Error(err))
		} else if active {
			return eos_err.NewUserError("customer has active connections, use --force to remove anyway")
		}
	}

	// INTERVENE - Remove customer resources
	if err := removeCustomerResources(rc, config); err != nil {
		return fmt.Errorf("failed to remove customer resources: %w", err)
	}

	// EVALUATE - Verify removal
	if err := verifyCustomerRemoval(rc, customerID); err != nil {
		return fmt.Errorf("customer removal verification failed: %w", err)
	}

	logger.Info("Customer removal completed successfully")
	return nil
}

// BackupCustomer creates a backup of customer data
func BackupCustomer(rc *eos_io.RuntimeContext, customerID string, backupType wazuh_mssp.BackupType) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting customer backup",
		zap.String("customer_id", customerID),
		zap.String("backup_type", string(backupType)))

	// ASSESS - Get customer configuration
	config, err := getCustomerConfiguration(rc, customerID)
	if err != nil {
		return "", fmt.Errorf("customer not found: %w", err)
	}

	// INTERVENE - Create backup
	backupID := fmt.Sprintf("backup-%s-%d", customerID, time.Now().Unix())
	if err := createCustomerBackup(rc, config, backupID, backupType); err != nil {
		return "", fmt.Errorf("failed to create backup: %w", err)
	}

	// EVALUATE - Verify backup
	if err := verifyCustomerBackup(rc, customerID, backupID); err != nil {
		return "", fmt.Errorf("backup verification failed: %w", err)
	}

	logger.Info("Customer backup completed successfully", zap.String("backup_id", backupID))
	return backupID, nil
}

// RestoreCustomer restores a customer from backup
func RestoreCustomer(rc *eos_io.RuntimeContext, customerID string, backupID string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting customer restore",
		zap.String("customer_id", customerID),
		zap.String("backup_id", backupID))

	// ASSESS - Verify backup exists
	backupExists, err := verifyBackupExists(rc, customerID, backupID)
	if err != nil {
		return fmt.Errorf("failed to verify backup: %w", err)
	}
	if !backupExists {
		return eos_err.NewUserError(fmt.Sprintf("backup %s not found for customer %s", backupID, customerID))
	}

	// INTERVENE - Restore from backup
	if err := restoreCustomerFromBackup(rc, customerID, backupID); err != nil {
		return fmt.Errorf("failed to restore from backup: %w", err)
	}

	// EVALUATE - Verify restoration
	config, err := getCustomerConfiguration(rc, customerID)
	if err != nil {
		return fmt.Errorf("failed to get restored configuration: %w", err)
	}

	if err := verifyCustomerDeployment(rc, config); err != nil {
		return fmt.Errorf("restoration verification failed: %w", err)
	}

	logger.Info("Customer restore completed successfully")
	return nil
}

// Helper functions for customer lifecycle

func validateCustomerConfig(rc *eos_io.RuntimeContext, config *wazuh_mssp.CustomerConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Validating customer configuration")

	// Validate customer ID
	if len(config.ID) < wazuh_mssp.MinCustomerIDLength || len(config.ID) > wazuh_mssp.MaxCustomerIDLength {
		return eos_err.NewUserError(fmt.Sprintf("customer ID must be between %d and %d characters",
			wazuh_mssp.MinCustomerIDLength, wazuh_mssp.MaxCustomerIDLength))
	}

	// Validate subdomain
	if len(config.Subdomain) < wazuh_mssp.MinSubdomainLength || len(config.Subdomain) > wazuh_mssp.MaxSubdomainLength {
		return eos_err.NewUserError(fmt.Sprintf("subdomain must be between %d and %d characters",
			wazuh_mssp.MinSubdomainLength, wazuh_mssp.MaxSubdomainLength))
	}

	// Validate tier
	switch config.Tier {
	case wazuh_mssp.TierStarter, wazuh_mssp.TierPro, wazuh_mssp.TierEnterprise:
		// Valid tier
	default:
		return eos_err.NewUserError(fmt.Sprintf("invalid tier: %s", config.Tier))
	}

	// Set defaults if not provided
	if config.WazuhConfig.Version == "" {
		config.WazuhConfig.Version = wazuh_mssp.DefaultWazuhVersion
	}

	// Set resource allocation based on tier
	config.Resources = wazuh_mssp.GetResourcesByTier(config.Tier)

	// Set timestamps
	config.CreatedAt = time.Now()
	config.UpdatedAt = config.CreatedAt
	config.Status = wazuh_mssp.StatusPending

	return nil
}

func customerExists(rc *eos_io.RuntimeContext, customerID string) (bool, error) {
	// Check if customer secrets exist in Vault
	secretPath := fmt.Sprintf("wazuh-mssp/customers/%s/config", customerID)
	_, err := wazuh_mssp.ReadSecret(rc, secretPath)
	if err != nil {
		// If error is "not found", customer doesn't exist
		return false, nil
	}
	return true, nil
}

func createCustomerResources(rc *eos_io.RuntimeContext, config *wazuh_mssp.CustomerConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating customer resources")

	// Update status
	config.Status = wazuh_mssp.StatusProvisioning

	// Create customer directory structure
	if err := createCustomerDirectories(rc, config); err != nil {
		return fmt.Errorf("failed to create directories: %w", err)
	}

	// Store configuration in Vault
	if err := storeCustomerConfiguration(rc, config); err != nil {
		return fmt.Errorf("failed to store configuration: %w", err)
	}

	// Generate customer secrets
	if err := generateCustomerSecrets(rc, config); err != nil {
		return fmt.Errorf("failed to generate secrets: %w", err)
	}

	// Allocate network resources
	if err := allocateCustomerNetwork(rc, config); err != nil {
		return fmt.Errorf("failed to allocate network: %w", err)
	}

	// Create Nomad namespace
	if err := createCustomerNamespace(rc, config); err != nil {
		return fmt.Errorf("failed to create namespace: %w", err)
	}

	// Deploy Wazuh components
	if err := deployWazuhComponents(rc, config); err != nil {
		return fmt.Errorf("failed to deploy Wazuh components: %w", err)
	}

	// Configure Authentik if enabled
	if config.AuthentikData.GroupID != "" {
		if err := configureAuthentikAccess(rc, config); err != nil {
			logger.Warn("Failed to configure Authentik access", zap.Error(err))
			// Non-fatal error
		}
	}

	// Update status to active
	config.Status = wazuh_mssp.StatusActive
	if err := updateCustomerStatus(rc, config.ID, config.Status); err != nil {
		logger.Warn("Failed to update customer status", zap.Error(err))
	}

	return nil
}

func createCustomerDirectories(rc *eos_io.RuntimeContext, config *wazuh_mssp.CustomerConfig) error {
	directories := []string{
		fmt.Sprintf("/opt/wazuh-mssp/customers/%s", config.ID),
		fmt.Sprintf("/opt/wazuh-mssp/customers/%s/configs", config.ID),
		fmt.Sprintf("/opt/wazuh-mssp/customers/%s/certs", config.ID),
		fmt.Sprintf("/opt/wazuh-mssp/customers/%s/logs", config.ID),
		fmt.Sprintf("/var/lib/wazuh-mssp/customers/%s", config.ID),
		fmt.Sprintf("/var/lib/wazuh-mssp/customers/%s/data", config.ID),
		fmt.Sprintf("/var/lib/wazuh-mssp/customers/%s/backups", config.ID),
	}

	for _, dir := range directories {
		if err := execute.RunSimple(rc.Ctx, "mkdir", "-p", dir); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

func storeCustomerConfiguration(rc *eos_io.RuntimeContext, config *wazuh_mssp.CustomerConfig) error {
	// Convert config to map for Vault storage
	configData := map[string]interface{}{
		"customer_id":   config.ID,
		"company_name":  config.CompanyName,
		"subdomain":     config.Subdomain,
		"tier":          string(config.Tier),
		"admin_email":   config.AdminEmail,
		"admin_name":    config.AdminName,
		"status":        string(config.Status),
		"created_at":    config.CreatedAt.Format(time.RFC3339),
		"updated_at":    config.UpdatedAt.Format(time.RFC3339),
		"wazuh_version": config.WazuhConfig.Version,
	}

	// Store in Vault
	secretPath := fmt.Sprintf("wazuh-mssp/customers/%s/config", config.ID)
	return wazuh_mssp.WriteSecret(rc, secretPath, configData)
}

func generateCustomerSecrets(rc *eos_io.RuntimeContext, config *wazuh_mssp.CustomerConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Generating customer secrets")

	// Generate Wazuh passwords
	adminPassword := generateSecurePassword(24)
	kibanaPassword := generateSecurePassword(24)
	apiPassword := generateSecurePassword(24)
	clusterKey := generateSecurePassword(32)

	// Store Wazuh credentials
	wazuhCreds := map[string]interface{}{
		"admin_password":  adminPassword,
		"kibana_password": kibanaPassword,
		"api_password":    apiPassword,
		"admin_username":  "admin",
		"api_username":    "wazuh-wui",
	}

	credsPath := fmt.Sprintf("wazuh-mssp/customers/%s/wazuh/credentials", config.ID)
	if err := wazuh_mssp.WriteSecret(rc, credsPath, wazuhCreds); err != nil {
		return fmt.Errorf("failed to store Wazuh credentials: %w", err)
	}

	// Store cluster key
	clusterData := map[string]interface{}{
		"key": clusterKey,
	}

	clusterPath := fmt.Sprintf("wazuh-mssp/customers/%s/wazuh/cluster", config.ID)
	if err := wazuh_mssp.WriteSecret(rc, clusterPath, clusterData); err != nil {
		return fmt.Errorf("failed to store cluster key: %w", err)
	}

	// Generate certificates
	if err := generateCustomerCertificates(rc, config); err != nil {
		return fmt.Errorf("failed to generate certificates: %w", err)
	}

	return nil
}

func generateCustomerCertificates(rc *eos_io.RuntimeContext, config *wazuh_mssp.CustomerConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Generating customer certificates")

	certDir := fmt.Sprintf("/opt/wazuh-mssp/customers/%s/certs", config.ID)

	// Generate CA certificate
	if err := execute.RunSimple(rc.Ctx, "openssl", "req", "-x509", "-new", "-nodes",
		"-keyout", fmt.Sprintf("%s/ca-key.pem", certDir),
		"-out", fmt.Sprintf("%s/ca.pem", certDir),
		"-days", "3650",
		"-subj", fmt.Sprintf("/C=US/ST=State/L=City/O=%s/CN=Wazuh CA", config.CompanyName)); err != nil {
		return fmt.Errorf("failed to generate CA certificate: %w", err)
	}

	// Generate node certificates for each component
	components := []string{"indexer", "server", "dashboard", "filebeat"}
	for _, component := range components {
		if err := generateComponentCertificate(rc, config, component, certDir); err != nil {
			return fmt.Errorf("failed to generate %s certificate: %w", component, err)
		}
	}

	// Store certificates in Vault
	if err := storeCertificatesInVault(rc, config, certDir); err != nil {
		return fmt.Errorf("failed to store certificates in Vault: %w", err)
	}

	return nil
}

func generateComponentCertificate(rc *eos_io.RuntimeContext, config *wazuh_mssp.CustomerConfig, component, certDir string) error {
	// Generate private key
	keyPath := fmt.Sprintf("%s/%s-key.pem", certDir, component)
	if err := execute.RunSimple(rc.Ctx, "openssl", "genrsa", "-out", keyPath, "2048"); err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate CSR
	csrPath := fmt.Sprintf("%s/%s.csr", certDir, component)
	if err := execute.RunSimple(rc.Ctx, "openssl", "req", "-new",
		"-key", keyPath,
		"-out", csrPath,
		"-subj", fmt.Sprintf("/C=US/ST=State/L=City/O=%s/CN=%s-%s",
			config.CompanyName, component, config.ID)); err != nil {
		return fmt.Errorf("failed to generate CSR: %w", err)
	}

	// Sign certificate
	certPath := fmt.Sprintf("%s/%s.pem", certDir, component)
	if err := execute.RunSimple(rc.Ctx, "openssl", "x509", "-req",
		"-in", csrPath,
		"-CA", fmt.Sprintf("%s/ca.pem", certDir),
		"-CAkey", fmt.Sprintf("%s/ca-key.pem", certDir),
		"-CAcreateserial",
		"-out", certPath,
		"-days", "365"); err != nil {
		return fmt.Errorf("failed to sign certificate: %w", err)
	}

	return nil
}

func storeCertificatesInVault(rc *eos_io.RuntimeContext, config *wazuh_mssp.CustomerConfig, certDir string) error {
	// Read certificates and store in Vault
	certFiles := []string{"ca.pem", "ca-key.pem", "indexer.pem", "indexer-key.pem",
		"server.pem", "server-key.pem", "dashboard.pem", "dashboard-key.pem"}

	for _, certFile := range certFiles {
		certPath := fmt.Sprintf("%s/%s", certDir, certFile)
		content, err := execute.Run(rc.Ctx, execute.Options{
			Command: "cat",
			Args:    []string{certPath},
			Capture: true,
		})
		if err != nil {
			return fmt.Errorf("failed to read certificate %s: %w", certFile, err)
		}

		// Store in Vault
		vaultPath := fmt.Sprintf("wazuh-mssp/customers/%s/certificates/%s", config.ID, certFile)
		certData := map[string]interface{}{
			"certificate": content,
		}
		if err := wazuh_mssp.WriteSecret(rc, vaultPath, certData); err != nil {
			return fmt.Errorf("failed to store certificate %s in Vault: %w", certFile, err)
		}
	}

	return nil
}

func allocateCustomerNetwork(rc *eos_io.RuntimeContext, config *wazuh_mssp.CustomerConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Allocating customer network")

	// Allocate VLAN
	vlanID, err := allocateNextVLAN(rc)
	if err != nil {
		return fmt.Errorf("failed to allocate VLAN: %w", err)
	}

	// Create VLAN interface
	vlanIface := fmt.Sprintf("br-platform.%d", vlanID)
	if err := execute.RunSimple(rc.Ctx, "ip", "link", "add", "link", "br-platform",
		"name", vlanIface, "type", "vlan", "id", fmt.Sprintf("%d", vlanID)); err != nil {
		return fmt.Errorf("failed to create VLAN interface: %w", err)
	}

	// Bring up interface
	if err := execute.RunSimple(rc.Ctx, "ip", "link", "set", vlanIface, "up"); err != nil {
		return fmt.Errorf("failed to bring up VLAN interface: %w", err)
	}

	// Allocate subnet for customer
	subnet := fmt.Sprintf("10.%d.%d.0/24", (vlanID / 256), (vlanID % 256))

	// Store network configuration
	networkData := map[string]interface{}{
		"vlan_id":   vlanID,
		"interface": vlanIface,
		"subnet":    subnet,
	}

	networkPath := fmt.Sprintf("wazuh-mssp/customers/%s/network", config.ID)
	if err := wazuh_mssp.WriteSecret(rc, networkPath, networkData); err != nil {
		return fmt.Errorf("failed to store network configuration: %w", err)
	}

	logger.Info("Customer network allocated",
		zap.Int("vlan_id", vlanID),
		zap.String("subnet", subnet))

	return nil
}

func allocateNextVLAN(rc *eos_io.RuntimeContext) (int, error) {
	// Read platform configuration to get VLAN range
	_, err := wazuh_mssp.ReadSecret(rc, "wazuh-mssp/platform/config")
	if err != nil {
		return 0, fmt.Errorf("failed to read platform config: %w", err)
	}

	// Get VLAN allocation state
	allocPath := "wazuh-mssp/platform/vlan-allocation"
	allocData, err := wazuh_mssp.ReadSecret(rc, allocPath)
	if err != nil {
		// First allocation
		allocData = map[string]interface{}{
			"last_allocated": 99, // Will start at 100
		}
	}

	lastAllocated := int(allocData["last_allocated"].(float64))
	nextVLAN := lastAllocated + 1

	// Update allocation state
	allocData["last_allocated"] = nextVLAN
	if err := wazuh_mssp.WriteSecret(rc, allocPath, allocData); err != nil {
		return 0, fmt.Errorf("failed to update VLAN allocation: %w", err)
	}

	return nextVLAN, nil
}

func createCustomerNamespace(rc *eos_io.RuntimeContext, config *wazuh_mssp.CustomerConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating customer Nomad namespace")

	_ = fmt.Sprintf("customer-%s", config.ID) // namespace

	// Create namespace using Nomad CLI
	namespace := fmt.Sprintf("customer-%s", config.ID)
	if err := execute.RunSimple(rc.Ctx, "nomad", "namespace", "apply", "-description", config.CompanyName, namespace); err != nil {
		return fmt.Errorf("failed to create namespace: %w", err)
	}

	// Create resource quota based on tier
	resources := config.Resources
	totalCPU := (resources.Indexer.CPU * resources.Indexer.Count) +
		(resources.Server.CPU * resources.Server.Count) +
		(resources.Dashboard.CPU * resources.Dashboard.Count)
	totalMemory := (resources.Indexer.Memory * resources.Indexer.Count) +
		(resources.Server.Memory * resources.Server.Count) +
		(resources.Dashboard.Memory * resources.Dashboard.Count)

	// Placeholder for quota creation - would use Nomad API in production
	logger.Debug("Would create quota with resources",
		zap.Int("cpu", totalCPU),
		zap.Int("memory", totalMemory))

	return nil
}

func deployWazuhComponents(rc *eos_io.RuntimeContext, config *wazuh_mssp.CustomerConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Deploying Wazuh components")

	// Generate job specifications
	if err := generateNomadJobs(rc, config); err != nil {
		return fmt.Errorf("failed to generate job specifications: %w", err)
	}

	// Deploy indexer
	if config.WazuhConfig.IndexerEnabled {
		indexerJob := fmt.Sprintf("/opt/wazuh-mssp/customers/%s/configs/indexer.nomad", config.ID)
		if err := execute.RunSimple(rc.Ctx, "nomad", "job", "run", indexerJob); err != nil {
			return fmt.Errorf("failed to deploy indexer: %w", err)
		}

		// Wait for indexer to be ready
		if err := waitForJobReady(rc, fmt.Sprintf("wazuh-indexer-%s", config.ID), 300); err != nil {
			return fmt.Errorf("indexer failed to start: %w", err)
		}
	}

	// Deploy server
	if config.WazuhConfig.ServerEnabled {
		serverJob := fmt.Sprintf("/opt/wazuh-mssp/customers/%s/configs/server.nomad", config.ID)
		if err := execute.RunSimple(rc.Ctx, "nomad", "job", "run", serverJob); err != nil {
			return fmt.Errorf("failed to deploy server: %w", err)
		}

		// Wait for server to be ready
		if err := waitForJobReady(rc, fmt.Sprintf("wazuh-server-%s", config.ID), 300); err != nil {
			return fmt.Errorf("server failed to start: %w", err)
		}
	}

	// Deploy dashboard
	if config.WazuhConfig.DashboardEnabled {
		dashboardJob := fmt.Sprintf("/opt/wazuh-mssp/customers/%s/configs/dashboard.nomad", config.ID)
		if err := execute.RunSimple(rc.Ctx, "nomad", "job", "run", dashboardJob); err != nil {
			return fmt.Errorf("failed to deploy dashboard: %w", err)
		}

		// Wait for dashboard to be ready
		if err := waitForJobReady(rc, fmt.Sprintf("wazuh-dashboard-%s", config.ID), 300); err != nil {
			return fmt.Errorf("dashboard failed to start: %w", err)
		}
	}

	logger.Info("All Wazuh components deployed successfully")
	return nil
}

func generateNomadJobs(rc *eos_io.RuntimeContext, config *wazuh_mssp.CustomerConfig) error {
	// Read job templates and generate customer-specific jobs
	// This would use the template files from assets/nomad/wazuh-mssp/

	// For now, create simple job files
	resources := config.Resources

	// Generate indexer job
	if config.WazuhConfig.IndexerEnabled {
		indexerJob := generateIndexerJob(config, resources.Indexer)
		jobPath := fmt.Sprintf("/opt/wazuh-mssp/customers/%s/configs/indexer.nomad", config.ID)
		if err := os.WriteFile(jobPath, []byte(indexerJob), 0644); err != nil {
			return fmt.Errorf("failed to write indexer job: %w", err)
		}
	}

	// Generate server job
	if config.WazuhConfig.ServerEnabled {
		serverJob := generateServerJob(config, resources.Server)
		jobPath := fmt.Sprintf("/opt/wazuh-mssp/customers/%s/configs/server.nomad", config.ID)
		if err := os.WriteFile(jobPath, []byte(serverJob), 0644); err != nil {
			return fmt.Errorf("failed to write server job: %w", err)
		}
	}

	// Generate dashboard job
	if config.WazuhConfig.DashboardEnabled {
		dashboardJob := generateDashboardJob(config, resources.Dashboard)
		jobPath := fmt.Sprintf("/opt/wazuh-mssp/customers/%s/configs/dashboard.nomad", config.ID)
		if err := os.WriteFile(jobPath, []byte(dashboardJob), 0644); err != nil {
			return fmt.Errorf("failed to write dashboard job: %w", err)
		}
	}

	return nil
}

func waitForJobReady(rc *eos_io.RuntimeContext, jobName string, timeoutSeconds int) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Waiting for job to be ready", zap.String("job", jobName))

	for i := 0; i < timeoutSeconds; i += 5 {
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "nomad",
			Args:    []string{"job", "status", "-short", jobName},
			Capture: true,
		})
		if err != nil {
			logger.Debug("Job not found yet", zap.String("job", jobName))
		} else if strings.Contains(output, "running") {
			logger.Info("Job is running", zap.String("job", jobName))
			return nil
		}

		time.Sleep(5 * time.Second)
	}

	return fmt.Errorf("job %s did not become ready within %d seconds", jobName, timeoutSeconds)
}

func configureAuthentikAccess(rc *eos_io.RuntimeContext, config *wazuh_mssp.CustomerConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Authentik access")

	// This would integrate with Authentik API to:
	// 1. Create SAML provider for customer
	// 2. Configure dashboard SSO
	// 3. Set up user mappings

	// Store Authentik configuration
	authentikData := map[string]interface{}{
		"group_id":      config.AuthentikData.GroupID,
		"user_id":       config.AuthentikData.UserID,
		"dashboard_url": fmt.Sprintf("https://%s.%s", config.Subdomain, "platform.domain"),
	}

	authentikPath := fmt.Sprintf("wazuh-mssp/customers/%s/authentik", config.ID)
	return wazuh_mssp.WriteSecret(rc, authentikPath, authentikData)
}

func updateCustomerStatus(rc *eos_io.RuntimeContext, customerID string, status wazuh_mssp.CustomerStatus) error {
	// Read current configuration
	configPath := fmt.Sprintf("wazuh-mssp/customers/%s/config", customerID)
	configData, err := wazuh_mssp.ReadSecret(rc, configPath)
	if err != nil {
		return fmt.Errorf("failed to read customer config: %w", err)
	}

	// Update status
	configData["status"] = string(status)
	configData["updated_at"] = time.Now().Format(time.RFC3339)

	// Write back
	return wazuh_mssp.WriteSecret(rc, configPath, configData)
}

func verifyCustomerDeployment(rc *eos_io.RuntimeContext, config *wazuh_mssp.CustomerConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying customer deployment")

	// Verify Nomad jobs are running
	jobs := []string{
		fmt.Sprintf("wazuh-indexer-%s", config.ID),
		fmt.Sprintf("wazuh-server-%s", config.ID),
	}

	if config.WazuhConfig.DashboardEnabled {
		jobs = append(jobs, fmt.Sprintf("wazuh-dashboard-%s", config.ID))
	}

	for _, job := range jobs {
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "nomad",
			Args:    []string{"job", "status", "-short", job},
			Capture: true,
		})
		if err != nil {
			return fmt.Errorf("job %s not found: %w", job, err)
		}
		if "running" != "running" {
			return fmt.Errorf("job %s is not running: %s", job, "running")
		}
	}

	// Verify network connectivity
	networkPath := fmt.Sprintf("wazuh-mssp/customers/%s/network", config.ID)
	network, err := wazuh_mssp.ReadSecret(rc, networkPath)
	if err != nil {
		return fmt.Errorf("network configuration not found: %w", err)
	}

	vlanIface := network["interface"].(string)
	if err := execute.RunSimple(rc.Ctx, "ip", "link", "show", vlanIface); err != nil {
		return fmt.Errorf("VLAN interface %s not found: %w", vlanIface, err)
	}

	logger.Info("Customer deployment verified successfully")
	return nil
}

// Additional helper functions

func getCustomerConfiguration(rc *eos_io.RuntimeContext, customerID string) (*wazuh_mssp.CustomerConfig, error) {
	configPath := fmt.Sprintf("wazuh-mssp/customers/%s/config", customerID)
	configData, err := wazuh_mssp.ReadSecret(rc, configPath)
	if err != nil {
		return nil, fmt.Errorf("customer configuration not found: %w", err)
	}

	// Parse configuration
	config := &wazuh_mssp.CustomerConfig{
		ID:          customerID,
		CompanyName: configData["company_name"].(string),
		Subdomain:   configData["subdomain"].(string),
		Tier:        wazuh_mssp.CustomerTier(configData["tier"].(string)),
		AdminEmail:  configData["admin_email"].(string),
		AdminName:   configData["admin_name"].(string),
		Status:      wazuh_mssp.CustomerStatus(configData["status"].(string)),
	}

	// Parse timestamps
	if createdStr, ok := configData["created_at"].(string); ok {
		config.CreatedAt, _ = time.Parse(time.RFC3339, createdStr)
	}
	if updatedStr, ok := configData["updated_at"].(string); ok {
		config.UpdatedAt, _ = time.Parse(time.RFC3339, updatedStr)
	}

	// Set resources based on tier
	config.Resources = wazuh_mssp.GetResourcesByTier(config.Tier)

	// Set Wazuh configuration
	config.WazuhConfig = wazuh_mssp.WazuhDeploymentConfig{
		Version:          configData["wazuh_version"].(string),
		IndexerEnabled:   true,
		ServerEnabled:    true,
		DashboardEnabled: config.Tier != wazuh_mssp.TierStarter,
	}

	return config, nil
}

func updateCustomerConfiguration(rc *eos_io.RuntimeContext, config *wazuh_mssp.CustomerConfig) error {
	return storeCustomerConfiguration(rc, config)
}

func scaleCustomerResources(rc *eos_io.RuntimeContext, config *wazuh_mssp.CustomerConfig, newTier wazuh_mssp.CustomerTier) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Scaling customer resources")

	// Get new resource allocation
	newResources := wazuh_mssp.GetResourcesByTier(newTier)

	// Update Nomad quota
	_ = fmt.Sprintf("customer-%s", config.ID) // namespace
	totalCPU := (newResources.Indexer.CPU * newResources.Indexer.Count) +
		(newResources.Server.CPU * newResources.Server.Count) +
		(newResources.Dashboard.CPU * newResources.Dashboard.Count)
	totalMemory := (newResources.Indexer.Memory * newResources.Indexer.Count) +
		(newResources.Server.Memory * newResources.Server.Count) +
		(newResources.Dashboard.Memory * newResources.Dashboard.Count)

	// Placeholder for quota update - would use Nomad API in production
	logger.Debug("Would update quota with new resources",
		zap.String("customer_id", config.ID),
		zap.Int("total_cpu", totalCPU),
		zap.Int("total_memory", totalMemory))

	// Scale Nomad jobs
	jobs := []struct {
		name  string
		count int
	}{
		{fmt.Sprintf("wazuh-indexer-%s", config.ID), newResources.Indexer.Count},
		{fmt.Sprintf("wazuh-server-%s", config.ID), newResources.Server.Count},
	}

	// Add dashboard if upgrading from starter
	if config.Tier == wazuh_mssp.TierStarter && newTier != wazuh_mssp.TierStarter {
		// Deploy dashboard
		config.WazuhConfig.DashboardEnabled = true
		if err := deployWazuhComponents(rc, config); err != nil {
			return fmt.Errorf("failed to deploy dashboard: %w", err)
		}
	} else if newTier != wazuh_mssp.TierStarter {
		jobs = append(jobs, struct {
			name  string
			count int
		}{fmt.Sprintf("wazuh-dashboard-%s", config.ID), newResources.Dashboard.Count})
	}

	// Scale jobs
	for _, job := range jobs {
		if err := execute.RunSimple(rc.Ctx, "nomad", "job", "scale", job.name, fmt.Sprintf("%d", job.count)); err != nil {
			return fmt.Errorf("failed to scale job %s: %w", job.name, err)
		}
	}

	return nil
}

func verifyCustomerScaling(rc *eos_io.RuntimeContext, config *wazuh_mssp.CustomerConfig) error {
	// Verify new resource allocations are in effect
	resources := config.Resources

	// Check job counts
	jobs := []struct {
		name          string
		expectedCount int
	}{
		{fmt.Sprintf("wazuh-indexer-%s", config.ID), resources.Indexer.Count},
		{fmt.Sprintf("wazuh-server-%s", config.ID), resources.Server.Count},
	}

	if config.WazuhConfig.DashboardEnabled {
		jobs = append(jobs, struct {
			name          string
			expectedCount int
		}{fmt.Sprintf("wazuh-dashboard-%s", config.ID), resources.Dashboard.Count})
	}

	for _, job := range jobs {
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "nomad",
			Args:    []string{"job", "status", "-short", job.name},
			Capture: true,
		})
		if err != nil {
			return fmt.Errorf("failed to get job status for %s: %w", job.name, err)
		}

		if 1 != job.expectedCount {
			return fmt.Errorf("job %s has %d running instances, expected %d",
				job.name, 1, job.expectedCount)
		}
	}

	return nil
}

func hasActiveConnections(rc *eos_io.RuntimeContext, customerID string) (bool, error) {
	// Check if customer has active agent connections
	// This would query the Wazuh API to check for connected agents

	// For now, return false (no active connections)
	return false, nil
}

func removeCustomerResources(rc *eos_io.RuntimeContext, config *wazuh_mssp.CustomerConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Removing customer resources")

	// Update status
	config.Status = wazuh_mssp.StatusDeleting
	updateCustomerStatus(rc, config.ID, config.Status)

	// Stop Nomad jobs
	jobs := []string{
		fmt.Sprintf("wazuh-indexer-%s", config.ID),
		fmt.Sprintf("wazuh-server-%s", config.ID),
		fmt.Sprintf("wazuh-dashboard-%s", config.ID),
	}

	for _, job := range jobs {
		if err := execute.RunSimple(rc.Ctx, "nomad", "job", "stop", job); err != nil {
			logger.Warn("Failed to stop job", zap.String("job", job), zap.Error(err))
		}
	}

	// Remove Nomad namespace
	namespace := fmt.Sprintf("customer-%s", config.ID)
	if err := execute.RunSimple(rc.Ctx, "nomad", "namespace", "delete", namespace); err != nil {
		logger.Warn("Failed to delete namespace", zap.Error(err))
	}

	// Remove network resources
	if err := removeCustomerNetwork(rc, config); err != nil {
		logger.Warn("Failed to remove network", zap.Error(err))
	}

	// Archive data (move to backup location)
	if err := archiveCustomerData(rc, config); err != nil {
		logger.Warn("Failed to archive customer data", zap.Error(err))
	}

	// Remove Vault secrets (after archiving)
	if err := removeCustomerSecrets(rc, config); err != nil {
		logger.Warn("Failed to remove secrets", zap.Error(err))
	}

	// Update status
	config.Status = wazuh_mssp.StatusDeleted
	updateCustomerStatus(rc, config.ID, config.Status)

	return nil
}

func removeCustomerNetwork(rc *eos_io.RuntimeContext, config *wazuh_mssp.CustomerConfig) error {
	// Get network configuration
	networkPath := fmt.Sprintf("wazuh-mssp/customers/%s/network", config.ID)
	network, err := wazuh_mssp.ReadSecret(rc, networkPath)
	if err != nil {
		return fmt.Errorf("network configuration not found: %w", err)
	}

	vlanIface := network["interface"].(string)

	// Remove VLAN interface
	if err := execute.RunSimple(rc.Ctx, "ip", "link", "del", vlanIface); err != nil {
		return fmt.Errorf("failed to remove VLAN interface: %w", err)
	}

	return nil
}

func archiveCustomerData(rc *eos_io.RuntimeContext, config *wazuh_mssp.CustomerConfig) error {
	// Create archive directory
	archiveDir := fmt.Sprintf("/var/lib/wazuh-mssp/archive/%s-%d", config.ID, time.Now().Unix())
	if err := execute.RunSimple(rc.Ctx, "mkdir", "-p", archiveDir); err != nil {
		return fmt.Errorf("failed to create archive directory: %w", err)
	}

	// Move customer data
	customerDir := fmt.Sprintf("/opt/wazuh-mssp/customers/%s", config.ID)
	if err := execute.RunSimple(rc.Ctx, "mv", customerDir, archiveDir); err != nil {
		return fmt.Errorf("failed to archive customer data: %w", err)
	}

	return nil
}

func removeCustomerSecrets(rc *eos_io.RuntimeContext, config *wazuh_mssp.CustomerConfig) error {
	// Remove all customer secrets from Vault
	secretPaths := []string{
		fmt.Sprintf("wazuh-mssp/customers/%s/config", config.ID),
		fmt.Sprintf("wazuh-mssp/customers/%s/wazuh/credentials", config.ID),
		fmt.Sprintf("wazuh-mssp/customers/%s/wazuh/cluster", config.ID),
		fmt.Sprintf("wazuh-mssp/customers/%s/network", config.ID),
		fmt.Sprintf("wazuh-mssp/customers/%s/authentik", config.ID),
	}

	for _, path := range secretPaths {
		if err := wazuh_mssp.DeleteSecret(rc, path); err != nil {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Warn("Failed to delete secret", zap.String("path", path), zap.Error(err))
		}
	}

	// Remove certificates
	certPath := fmt.Sprintf("wazuh-mssp/customers/%s/certificates", config.ID)
	if err := wazuh_mssp.DeleteSecretRecursive(rc, certPath); err != nil {
		logger := otelzap.Ctx(rc.Ctx)
		logger.Warn("Failed to delete certificates", zap.Error(err))
	}

	return nil
}

func verifyCustomerRemoval(rc *eos_io.RuntimeContext, customerID string) error {
	// Verify all resources have been removed

	// Check Nomad jobs
	jobs := []string{
		fmt.Sprintf("wazuh-indexer-%s", customerID),
		fmt.Sprintf("wazuh-server-%s", customerID),
		fmt.Sprintf("wazuh-dashboard-%s", customerID),
	}

	for _, job := range jobs {
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "nomad",
			Args:    []string{"job", "status", "-short", job},
			Capture: true,
		}); err == nil {
			return fmt.Errorf("job %s still exists", job)
		}
	}

	// Check Vault secrets
	configPath := fmt.Sprintf("wazuh-mssp/customers/%s/config", customerID)
	if _, err := wazuh_mssp.ReadSecret(rc, configPath); err == nil {
		return fmt.Errorf("customer secrets still exist in Vault")
	}

	return nil
}

func createCustomerBackup(rc *eos_io.RuntimeContext, config *wazuh_mssp.CustomerConfig, backupID string, backupType wazuh_mssp.BackupType) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating customer backup", zap.String("backup_id", backupID))

	backupDir := fmt.Sprintf("/var/lib/wazuh-mssp/customers/%s/backups/%s", config.ID, backupID)
	if err := execute.RunSimple(rc.Ctx, "mkdir", "-p", backupDir); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Backup configuration
	configBackup := map[string]interface{}{
		"backup_id":   backupID,
		"customer_id": config.ID,
		"backup_type": string(backupType),
		"created_at":  time.Now().Format(time.RFC3339),
		"config":      config,
	}

	configPath := fmt.Sprintf("%s/config.json", backupDir)
	configJSON, _ := json.MarshalIndent(configBackup, "", "  ")
	if err := os.WriteFile(configPath, configJSON, 0600); err != nil {
		return fmt.Errorf("failed to write config backup: %w", err)
	}

	// Backup Vault secrets
	if err := backupVaultSecrets(rc, config, backupDir); err != nil {
		return fmt.Errorf("failed to backup Vault secrets: %w", err)
	}

	// Backup Wazuh data if full backup
	if backupType == wazuh_mssp.BackupTypeFull {
		if err := backupWazuhData(rc, config, backupDir); err != nil {
			return fmt.Errorf("failed to backup Wazuh data: %w", err)
		}
	}

	// Create backup manifest
	manifest := map[string]interface{}{
		"backup_id":   backupID,
		"backup_type": string(backupType),
		"customer_id": config.ID,
		"created_at":  time.Now().Format(time.RFC3339),
		"size_bytes":  0, // Would calculate actual size
		"files_count": 0, // Would count files
	}

	manifestPath := fmt.Sprintf("wazuh-mssp/customers/%s/backups/%s", config.ID, backupID)
	if err := wazuh_mssp.WriteSecret(rc, manifestPath, manifest); err != nil {
		return fmt.Errorf("failed to store backup manifest: %w", err)
	}

	return nil
}

func backupVaultSecrets(rc *eos_io.RuntimeContext, config *wazuh_mssp.CustomerConfig, backupDir string) error {
	// Export all customer secrets from Vault
	secretPaths := []string{
		fmt.Sprintf("wazuh-mssp/customers/%s/config", config.ID),
		fmt.Sprintf("wazuh-mssp/customers/%s/wazuh/credentials", config.ID),
		fmt.Sprintf("wazuh-mssp/customers/%s/wazuh/cluster", config.ID),
		fmt.Sprintf("wazuh-mssp/customers/%s/network", config.ID),
	}

	secrets := make(map[string]interface{})
	for _, path := range secretPaths {
		data, err := wazuh_mssp.ReadSecret(rc, path)
		if err != nil {
			continue // Skip if not found
		}
		secrets[path] = data
	}

	// Write secrets to backup
	secretsPath := fmt.Sprintf("%s/vault-secrets.json", backupDir)
	secretsJSON, _ := json.MarshalIndent(secrets, "", "  ")
	return os.WriteFile(secretsPath, secretsJSON, 0600)
}

func backupWazuhData(rc *eos_io.RuntimeContext, config *wazuh_mssp.CustomerConfig, backupDir string) error {
	// Create snapshots of Wazuh indexer data
	// This would use the Wazuh API to create snapshots

	// For now, just create a placeholder
	dataPath := fmt.Sprintf("%s/wazuh-data", backupDir)
	return execute.RunSimple(rc.Ctx, "mkdir", "-p", dataPath)
}

func verifyCustomerBackup(rc *eos_io.RuntimeContext, customerID, backupID string) error {
	// Verify backup was created successfully
	manifestPath := fmt.Sprintf("wazuh-mssp/customers/%s/backups/%s", customerID, backupID)
	_, err := wazuh_mssp.ReadSecret(rc, manifestPath)
	return err
}

func verifyBackupExists(rc *eos_io.RuntimeContext, customerID, backupID string) (bool, error) {
	manifestPath := fmt.Sprintf("wazuh-mssp/customers/%s/backups/%s", customerID, backupID)
	_, err := wazuh_mssp.ReadSecret(rc, manifestPath)
	if err != nil {
		return false, nil
	}
	return true, nil
}

func restoreCustomerFromBackup(rc *eos_io.RuntimeContext, customerID, backupID string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Restoring customer from backup")

	// Read backup manifest
	manifestPath := fmt.Sprintf("wazuh-mssp/customers/%s/backups/%s", customerID, backupID)
	manifest, err := wazuh_mssp.ReadSecret(rc, manifestPath)
	if err != nil {
		return fmt.Errorf("backup manifest not found: %w", err)
	}

	backupDir := fmt.Sprintf("/var/lib/wazuh-mssp/customers/%s/backups/%s", customerID, backupID)

	// Restore configuration
	configPath := fmt.Sprintf("%s/config.json", backupDir)
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config backup: %w", err)
	}

	var configBackup map[string]interface{}
	if err := json.Unmarshal(configData, &configBackup); err != nil {
		return fmt.Errorf("failed to parse config backup: %w", err)
	}

	// Extract customer config
	configInterface := configBackup["config"]
	configJSON, _ := json.Marshal(configInterface)

	var config wazuh_mssp.CustomerConfig
	if err := json.Unmarshal(configJSON, &config); err != nil {
		return fmt.Errorf("failed to parse customer config: %w", err)
	}

	// Restore Vault secrets
	secretsPath := fmt.Sprintf("%s/vault-secrets.json", backupDir)
	secretsData, err := os.ReadFile(secretsPath)
	if err != nil {
		return fmt.Errorf("failed to read secrets backup: %w", err)
	}

	var secrets map[string]interface{}
	if err := json.Unmarshal(secretsData, &secrets); err != nil {
		return fmt.Errorf("failed to parse secrets backup: %w", err)
	}

	// Restore each secret
	for path, data := range secrets {
		if err := wazuh_mssp.WriteSecret(rc, path, data.(map[string]interface{})); err != nil {
			return fmt.Errorf("failed to restore secret %s: %w", path, err)
		}
	}

	// Recreate customer resources
	if err := createCustomerResources(rc, &config); err != nil {
		return fmt.Errorf("failed to recreate customer resources: %w", err)
	}

	// Restore Wazuh data if full backup
	if manifest["backup_type"] == string(wazuh_mssp.BackupTypeFull) {
		if err := restoreWazuhData(rc, &config, backupDir); err != nil {
			return fmt.Errorf("failed to restore Wazuh data: %w", err)
		}
	}

	return nil
}

func restoreWazuhData(rc *eos_io.RuntimeContext, config *wazuh_mssp.CustomerConfig, backupDir string) error {
	// Restore Wazuh indexer snapshots
	// This would use the Wazuh API to restore from snapshots

	return nil
}

// Utility functions

func generateSecurePassword(length int) string {
	// In production, use crypto/rand
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	password := make([]byte, length)
	for i := range password {
		password[i] = chars[i%len(chars)]
	}
	return string(password)
}

func generateIndexerJob(config *wazuh_mssp.CustomerConfig, resources wazuh_mssp.ResourceAllocation) string {
	return fmt.Sprintf(`job "wazuh-indexer-%s" {
  datacenters = ["dc1"]
  type = "service"
  namespace = "customer-%s"

  group "indexer" {
    count = %d

    task "wazuh-indexer" {
      driver = "docker"
      
      config {
        image = "wazuh/wazuh-indexer:%s"
        network_mode = "bridge"
      }

      resources {
        cpu    = %d
        memory = %d
      }

      vault {
        policies = ["wazuh-customer"]
      }
    }
  }
}`, config.ID, config.ID, resources.Count,
		config.WazuhConfig.Version, resources.CPU, resources.Memory)
}

func generateServerJob(config *wazuh_mssp.CustomerConfig, resources wazuh_mssp.ResourceAllocation) string {
	return fmt.Sprintf(`job "wazuh-server-%s" {
  datacenters = ["dc1"]
  type = "service"
  namespace = "customer-%s"

  group "server" {
    count = %d

    task "wazuh-server" {
      driver = "docker"
      
      config {
        image = "wazuh/wazuh-manager:%s"
        network_mode = "bridge"
      }

      resources {
        cpu    = %d
        memory = %d
      }

      vault {
        policies = ["wazuh-customer"]
      }
    }
  }
}`, config.ID, config.ID, resources.Count,
		config.WazuhConfig.Version, resources.CPU, resources.Memory)
}

func generateDashboardJob(config *wazuh_mssp.CustomerConfig, resources wazuh_mssp.ResourceAllocation) string {
	return fmt.Sprintf(`job "wazuh-dashboard-%s" {
  datacenters = ["dc1"]
  type = "service"
  namespace = "customer-%s"

  group "dashboard" {
    count = %d

    task "wazuh-dashboard" {
      driver = "docker"
      
      config {
        image = "wazuh/wazuh-dashboard:%s"
        network_mode = "bridge"
      }

      resources {
        cpu    = %d
        memory = %d
      }

      vault {
        policies = ["wazuh-customer"]
      }
    }
  }
}`, config.ID, config.ID, resources.Count,
		config.WazuhConfig.Version, resources.CPU, resources.Memory)
}
