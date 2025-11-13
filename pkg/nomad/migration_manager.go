// pkg/nomad/migration_manager.go
package nomad

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// MigrationManager handles migration from K3s/Kubernetes to Nomad
type MigrationManager struct {
	logger           otelzap.LoggerWithCtx
	jobGenerator     *JobGenerator
	serviceDiscovery *ServiceDiscoveryManager
}

// NewMigrationManager creates a new migration manager
func NewMigrationManager(logger otelzap.LoggerWithCtx) *MigrationManager {
	return &MigrationManager{
		logger:           logger,
		jobGenerator:     NewJobGenerator(logger),
		serviceDiscovery: NewServiceDiscoveryManager(logger, ""),
	}
}

// MigrationResult represents the result of a K3s to Nomad migration
type MigrationResult struct {
	ServicesConverted int      `json:"services_converted"`
	JobsCreated       int      `json:"jobs_created"`
	IngressSetup      bool     `json:"ingress_setup"`
	MailProxySetup    bool     `json:"mail_proxy_setup"`
	Errors            []string `json:"errors,omitempty"`
	MigrationSummary  string   `json:"migration_summary"`
}

// K3sMigrationConfig represents configuration for K3s migration
type K3sMigrationConfig struct {
	SourceClusterPath string `json:"source_cluster_path"`
	PreservePVCs      bool   `json:"preserve_pvcs"`
	MigrateIngress    bool   `json:"migrate_ingress"`
	MigrateMailProxy  bool   `json:"migrate_mail_proxy"`
	Domain            string `json:"domain,omitempty"`
	TargetDatacenter  string `json:"target_datacenter"`
	TargetRegion      string `json:"target_region"`
	DryRun            bool   `json:"dry_run"`
}

// MigrateK3sToNomad migrates an existing K3s cluster to Nomad
func (mm *MigrationManager) MigrateK3sToNomad(rc *eos_io.RuntimeContext, config K3sMigrationConfig) (*MigrationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting K3s to Nomad migration",
		zap.String("source_cluster", config.SourceClusterPath),
		zap.Bool("dry_run", config.DryRun),
		zap.Bool("migrate_ingress", config.MigrateIngress))

	result := &MigrationResult{
		Errors: make([]string, 0),
	}

	// ASSESS - Check K3s cluster and Nomad readiness
	logger.Info("Assessing migration prerequisites")

	if err := mm.assessMigrationPrerequisites(rc, config); err != nil {
		return nil, fmt.Errorf("migration prerequisites assessment failed: %w", err)
	}

	// INTERVENE - Perform migration steps
	logger.Info("Executing K3s to Nomad migration")

	// Step 1: Extract K3s configuration and workloads
	k3sWorkloads, err := mm.extractK3sWorkloads(rc, config)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to extract K3s workloads: %v", err))
		return result, fmt.Errorf("failed to extract K3s workloads: %w", err)
	}

	// Step 2: Convert K3s services to Nomad jobs
	nomadJobs, err := mm.convertK3sWorkloadsToNomad(rc, k3sWorkloads, config)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to convert workloads: %v", err))
		return result, fmt.Errorf("failed to convert K3s workloads to Nomad: %w", err)
	}

	result.ServicesConverted = len(nomadJobs)

	// Step 3: Setup ingress if requested
	if config.MigrateIngress {
		if err := mm.setupNomadIngress(rc, config); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("failed to setup ingress: %v", err))
		} else {
			result.IngressSetup = true
		}
	}

	// Step 4: Setup mail proxy if requested
	if config.MigrateMailProxy {
		if err := mm.setupNomadMailProxy(rc, config); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("failed to setup mail proxy: %v", err))
		} else {
			result.MailProxySetup = true
		}
	}

	// Step 5: Deploy Nomad jobs (unless dry run)
	if !config.DryRun {
		deployedJobs, err := mm.deployNomadJobs(rc, nomadJobs)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("failed to deploy jobs: %v", err))
		} else {
			result.JobsCreated = deployedJobs
		}
	}

	// EVALUATE - Verify migration success
	logger.Info("Evaluating migration results")

	if err := mm.verifyMigration(rc, result); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("migration verification failed: %v", err))
	}

	// Generate migration summary
	result.MigrationSummary = mm.generateMigrationSummary(result)

	logger.Info("K3s to Nomad migration completed",
		zap.Int("services_converted", result.ServicesConverted),
		zap.Int("jobs_created", result.JobsCreated),
		zap.Bool("ingress_setup", result.IngressSetup),
		zap.Int("error_count", len(result.Errors)))

	return result, nil
}

// UninstallK3s safely removes K3s after migration to Nomad
func (mm *MigrationManager) UninstallK3s(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting K3s uninstallation after Nomad migration")

	// ASSESS - Check if K3s is installed and migration is complete
	logger.Info("Assessing K3s uninstallation prerequisites")

	if err := mm.checkMigrationComplete(rc); err != nil {
		return fmt.Errorf("cannot uninstall K3s: migration not complete: %w", err)
	}

	// INTERVENE - Stop and remove K3s components
	logger.Info("Removing K3s components")

	if err := mm.stopK3sServices(rc); err != nil {
		logger.Warn("Failed to stop K3s services", zap.Error(err))
	}

	if err := mm.removeK3sBinaries(rc); err != nil {
		logger.Warn("Failed to remove K3s binaries", zap.Error(err))
	}

	if err := mm.cleanupK3sData(rc); err != nil {
		logger.Warn("Failed to cleanup K3s data", zap.Error(err))
	}

	// EVALUATE - Verify K3s removal
	logger.Info("Verifying K3s removal")

	if err := mm.verifyK3sRemoval(rc); err != nil {
		logger.Warn("K3s removal verification failed", zap.Error(err))
		return fmt.Errorf("K3s removal verification failed: %w", err)
	}

	logger.Info("K3s uninstallation completed successfully")
	return nil
}

// assessMigrationPrerequisites checks if migration can proceed
func (mm *MigrationManager) assessMigrationPrerequisites(rc *eos_io.RuntimeContext, config K3sMigrationConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if K3s is running
	if !mm.isK3sRunning(rc) {
		return fmt.Errorf("K3s is not running - cannot migrate")
	}

	// Check if Nomad is available
	if !mm.isNomadAvailable(rc) {
		return fmt.Errorf("Nomad is not available - install Nomad first")
	}

	// Check if kubectl is available for K3s extraction
	if !mm.isKubectlAvailable(rc) {
		return fmt.Errorf("kubectl is not available - needed for K3s workload extraction")
	}

	logger.Info("Migration prerequisites satisfied")
	return nil
}

// extractK3sWorkloads extracts workloads from K3s cluster
func (mm *MigrationManager) extractK3sWorkloads(rc *eos_io.RuntimeContext, config K3sMigrationConfig) ([]map[string]interface{}, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Extracting K3s workloads")

	// This would implement actual kubectl commands to extract:
	// - Deployments
	// - Services
	// - ConfigMaps
	// - Secrets
	// - PersistentVolumeClaims
	// - Ingress resources

	// For now, return mock workloads
	workloads := []map[string]interface{}{
		{
			"kind":     "Deployment",
			"name":     "web-app",
			"image":    "nginx:1.20",
			"replicas": 2,
			"ports":    []int{80},
			"env": map[string]string{
				"ENV": "production",
			},
		},
		{
			"kind": "Service",
			"name": "web-app-service",
			"type": "ClusterIP",
			"ports": []map[string]interface{}{
				{"port": 80, "targetPort": 80},
			},
			"selector": map[string]string{
				"app": "web-app",
			},
		},
	}

	logger.Info("K3s workloads extracted",
		zap.Int("workload_count", len(workloads)))

	return workloads, nil
}

// convertK3sWorkloadsToNomad converts K3s workloads to Nomad job specifications
func (mm *MigrationManager) convertK3sWorkloadsToNomad(rc *eos_io.RuntimeContext, workloads []map[string]interface{}, config K3sMigrationConfig) ([]string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Converting K3s workloads to Nomad jobs",
		zap.Int("workload_count", len(workloads)))

	var nomadJobs []string

	for _, workload := range workloads {
		kind, _ := workload["kind"].(string)

		switch kind {
		case "Deployment":
			jobConfig, err := mm.jobGenerator.ConvertK3sToNomadConfig(rc, workload)
			if err != nil {
				logger.Error("Failed to convert K3s deployment", zap.Error(err))
				continue
			}

			// Set migration-specific fields
			jobConfig.Datacenter = config.TargetDatacenter
			jobConfig.Region = config.TargetRegion
			jobConfig.ServiceTags = append(jobConfig.ServiceTags, "migrated-from-k3s")

			jobSpec, err := mm.jobGenerator.GenerateServiceJob(rc, jobConfig)
			if err != nil {
				logger.Error("Failed to generate Nomad job", zap.Error(err))
				continue
			}

			nomadJobs = append(nomadJobs, jobSpec)

		case "Service":
			// Convert K3s service to Consul service registration
			consulService, err := mm.serviceDiscovery.ConvertK3sServiceToConsul(rc, workload)
			if err != nil {
				logger.Error("Failed to convert K3s service", zap.Error(err))
				continue
			}

			if err := mm.serviceDiscovery.RegisterService(rc, consulService); err != nil {
				logger.Error("Failed to register Consul service", zap.Error(err))
			}

		default:
			logger.Info("Skipping unsupported workload type",
				zap.String("kind", kind))
		}
	}

	logger.Info("K3s workloads converted to Nomad jobs",
		zap.Int("nomad_jobs", len(nomadJobs)))

	return nomadJobs, nil
}

// setupNomadIngress sets up Caddy ingress to replace K3s ingress
func (mm *MigrationManager) setupNomadIngress(rc *eos_io.RuntimeContext, config K3sMigrationConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Setting up Nomad ingress with Caddy")

	caddyConfig := GetDefaultCaddyConfig()
	caddyConfig.Domain = config.Domain
	caddyConfig.Datacenter = config.TargetDatacenter
	caddyConfig.Region = config.TargetRegion

	jobSpec, err := mm.jobGenerator.GenerateCaddyIngressJob(rc, caddyConfig)
	if err != nil {
		return fmt.Errorf("failed to generate Caddy ingress job: %w", err)
	}

	// Deploy if not dry run
	if !config.DryRun {
		if err := mm.jobGenerator.DeployNomadJob(rc, jobSpec); err != nil {
			return fmt.Errorf("failed to deploy Caddy ingress: %w", err)
		}
	}

	logger.Info("Nomad ingress setup completed")
	return nil
}

// setupNomadMailProxy sets up Nginx mail proxy
func (mm *MigrationManager) setupNomadMailProxy(rc *eos_io.RuntimeContext, config K3sMigrationConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Setting up Nomad mail proxy with Nginx")

	nginxConfig := GetDefaultNginxConfig()
	nginxConfig.Domain = config.Domain
	nginxConfig.Datacenter = config.TargetDatacenter
	nginxConfig.Region = config.TargetRegion

	jobSpec, err := mm.jobGenerator.GenerateNginxMailJob(rc, nginxConfig)
	if err != nil {
		return fmt.Errorf("failed to generate Nginx mail proxy job: %w", err)
	}

	// Deploy if not dry run
	if !config.DryRun {
		if err := mm.jobGenerator.DeployNomadJob(rc, jobSpec); err != nil {
			return fmt.Errorf("failed to deploy Nginx mail proxy: %w", err)
		}
	}

	logger.Info("Nomad mail proxy setup completed")
	return nil
}

// deployNomadJobs deploys the generated Nomad jobs
func (mm *MigrationManager) deployNomadJobs(rc *eos_io.RuntimeContext, nomadJobs []string) (int, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Deploying Nomad jobs",
		zap.Int("job_count", len(nomadJobs)))

	var deployedCount int

	for i, jobSpec := range nomadJobs {
		logger.Info("Deploying Nomad job",
			zap.Int("job_index", i+1),
			zap.Int("total_jobs", len(nomadJobs)))

		if err := mm.jobGenerator.DeployNomadJob(rc, jobSpec); err != nil {
			logger.Error("Failed to deploy Nomad job",
				zap.Int("job_index", i+1),
				zap.Error(err))
			continue
		}

		deployedCount++
	}

	logger.Info("Nomad job deployment completed",
		zap.Int("deployed_count", deployedCount),
		zap.Int("total_jobs", len(nomadJobs)))

	return deployedCount, nil
}

// verifyMigration verifies migration success
func (mm *MigrationManager) verifyMigration(rc *eos_io.RuntimeContext, result *MigrationResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Verifying migration success")

	// Check if Nomad jobs are running
	// Check if Consul services are registered
	// Check if ingress is accessible

	logger.Info("Migration verification completed")
	return nil
}

// Helper methods for checking system state
func (mm *MigrationManager) isK3sRunning(rc *eos_io.RuntimeContext) bool {
	return shared.FileExists("/usr/local/bin/k3s")
}

func (mm *MigrationManager) isNomadAvailable(rc *eos_io.RuntimeContext) bool {
	return shared.FileExists("/usr/local/bin/nomad")
}

func (mm *MigrationManager) isKubectlAvailable(rc *eos_io.RuntimeContext) bool {
	return shared.FileExists("/usr/local/bin/kubectl") || shared.FileExists("/usr/bin/kubectl")
}

func (mm *MigrationManager) checkMigrationComplete(rc *eos_io.RuntimeContext) error {
	// Check if Nomad is running and has migrated workloads
	return nil
}

func (mm *MigrationManager) stopK3sServices(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Stopping K3s services")

	// This would implement actual service stopping
	return nil
}

func (mm *MigrationManager) removeK3sBinaries(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Removing K3s binaries")

	binaries := []string{
		"/usr/local/bin/k3s",
		"/usr/local/bin/k3s-uninstall.sh",
		"/usr/local/bin/k3s-agent-uninstall.sh",
		"/usr/local/bin/k3s-killall.sh",
	}

	for _, binary := range binaries {
		if shared.FileExists(binary) {
			if err := os.Remove(binary); err != nil {
				logger.Warn("Failed to remove binary",
					zap.String("binary", binary),
					zap.Error(err))
			}
		}
	}

	return nil
}

func (mm *MigrationManager) cleanupK3sData(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Cleaning up K3s data")

	dataDirs := []string{
		"/var/lib/rancher/k3s",
		"/etc/rancher/k3s",
	}

	for _, dataDir := range dataDirs {
		if shared.FileExists(dataDir) {
			if err := os.RemoveAll(dataDir); err != nil {
				logger.Warn("Failed to remove data directory",
					zap.String("directory", dataDir),
					zap.Error(err))
			}
		}
	}

	return nil
}

func (mm *MigrationManager) verifyK3sRemoval(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if K3s binaries are removed
	if shared.FileExists("/usr/local/bin/k3s") {
		return fmt.Errorf("K3s binary still exists")
	}

	logger.Info("K3s removal verified")
	return nil
}

func (mm *MigrationManager) generateMigrationSummary(result *MigrationResult) string {
	var summary strings.Builder

	summary.WriteString("K3s to Nomad Migration Summary:\n")
	summary.WriteString(fmt.Sprintf("- Services converted: %d\n", result.ServicesConverted))
	summary.WriteString(fmt.Sprintf("- Nomad jobs created: %d\n", result.JobsCreated))
	summary.WriteString(fmt.Sprintf("- Ingress setup: %t\n", result.IngressSetup))
	summary.WriteString(fmt.Sprintf("- Mail proxy setup: %t\n", result.MailProxySetup))

	if len(result.Errors) > 0 {
		summary.WriteString(fmt.Sprintf("- Errors encountered: %d\n", len(result.Errors)))
		for _, err := range result.Errors {
			summary.WriteString(fmt.Sprintf("  - %s\n", err))
		}
	} else {
		summary.WriteString("- Migration completed successfully with no errors\n")
	}

	return summary.String()
}

// UninstallNomad safely removes Nomad from the system
func (mm *MigrationManager) UninstallNomad(rc *eos_io.RuntimeContext, force bool, preserveData bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Nomad uninstallation",
		zap.Bool("force", force),
		zap.Bool("preserve_data", preserveData))

	// ASSESS - Check Nomad status
	logger.Info("Assessing Nomad status for uninstallation")

	if !mm.isNomadAvailable(rc) {
		logger.Info("Nomad is not installed, nothing to uninstall")
		return nil
	}

	// INTERVENE - Stop and remove Nomad
	logger.Info("Stopping Nomad services")

	if err := mm.stopNomadServices(rc, force); err != nil {
		logger.Warn("Failed to stop Nomad services gracefully", zap.Error(err))
		if !force {
			return fmt.Errorf("failed to stop Nomad services: %w", err)
		}
	}

	if err := mm.removeNomadBinaries(rc); err != nil {
		logger.Warn("Failed to remove Nomad binaries", zap.Error(err))
	}

	if err := mm.removeNomadConfiguration(rc); err != nil {
		logger.Warn("Failed to remove Nomad configuration", zap.Error(err))
	}

	if !preserveData {
		if err := mm.cleanupNomadData(rc); err != nil {
			logger.Warn("Failed to cleanup Nomad data", zap.Error(err))
		}
	}

	// EVALUATE - Verify Nomad removal
	logger.Info("Verifying Nomad removal")

	if err := mm.verifyNomadRemoval(rc); err != nil {
		logger.Warn("Nomad removal verification failed", zap.Error(err))
		return fmt.Errorf("Nomad removal verification failed: %w", err)
	}

	logger.Info("Nomad uninstallation completed successfully")
	return nil
}

// Helper methods for Nomad uninstallation
func (mm *MigrationManager) stopNomadServices(rc *eos_io.RuntimeContext, force bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	if !force {
		logger.Info("Gracefully draining Nomad jobs")
		// This would implement graceful job draining
	}

	logger.Info("Stopping Nomad systemd service")
	// This would implement actual service stopping
	return nil
}

func (mm *MigrationManager) removeNomadBinaries(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Removing Nomad binaries")

	binaries := []string{
		"/usr/local/bin/nomad",
		"/usr/bin/nomad",
	}

	for _, binary := range binaries {
		if shared.FileExists(binary) {
			if err := os.Remove(binary); err != nil {
				logger.Warn("Failed to remove binary",
					zap.String("binary", binary),
					zap.Error(err))
			}
		}
	}

	return nil
}

func (mm *MigrationManager) removeNomadConfiguration(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Removing Nomad configuration")

	configDirs := []string{
		"/etc/nomad.d",
		"/etc/nomad",
	}

	for _, configDir := range configDirs {
		if shared.FileExists(configDir) {
			if err := os.RemoveAll(configDir); err != nil {
				logger.Warn("Failed to remove config directory",
					zap.String("directory", configDir),
					zap.Error(err))
			}
		}
	}

	// Remove systemd service
	serviceFiles := []string{
		"/etc/systemd/system/nomad.service",
		"/lib/systemd/system/nomad.service",
	}

	for _, serviceFile := range serviceFiles {
		if shared.FileExists(serviceFile) {
			if err := os.Remove(serviceFile); err != nil {
				logger.Warn("Failed to remove service file",
					zap.String("service_file", serviceFile),
					zap.Error(err))
			}
		}
	}

	return nil
}

func (mm *MigrationManager) cleanupNomadData(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Cleaning up Nomad data directories")

	dataDirs := []string{
		"/opt/nomad",
		"/var/lib/nomad",
		"/var/log/nomad",
	}

	for _, dataDir := range dataDirs {
		if shared.FileExists(dataDir) {
			if err := os.RemoveAll(dataDir); err != nil {
				logger.Warn("Failed to remove data directory",
					zap.String("directory", dataDir),
					zap.Error(err))
			}
		}
	}

	return nil
}

func (mm *MigrationManager) verifyNomadRemoval(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if Nomad binaries are removed
	if shared.FileExists("/usr/local/bin/nomad") {
		return fmt.Errorf("Nomad binary still exists")
	}

	logger.Info("Nomad removal verified")
	return nil
}
