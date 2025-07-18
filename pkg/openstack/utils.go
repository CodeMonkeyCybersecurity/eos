package openstack

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// configureDatabases creates and configures databases for OpenStack services
func configureDatabases(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring databases")

	// Start MariaDB
	if err := enableAndStartService(rc, "mariadb"); err != nil {
		return fmt.Errorf("failed to start MariaDB: %w", err)
	}

	// Secure MariaDB installation
	if err := secureMariaDB(rc, config); err != nil {
		return fmt.Errorf("failed to secure MariaDB: %w", err)
	}

	// Create databases for each service
	databases := []string{
		"keystone", "glance", "nova", "nova_api", "nova_cell0",
		"neutron", "cinder", "heat", "placement",
	}

	for _, db := range databases {
		if err := createServiceDatabase(rc, db, config.DBPassword); err != nil {
			logger.Warn("Failed to create database",
				zap.String("database", db),
				zap.Error(err))
		}
	}

	return nil
}

// configureMessageQueue sets up RabbitMQ for OpenStack
func configureMessageQueue(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring message queue")

	// Install RabbitMQ
	packages := []string{"rabbitmq-server"}
	if err := installPackages(rc, packages); err != nil {
		return fmt.Errorf("failed to install RabbitMQ: %w", err)
	}

	// Start RabbitMQ
	if err := enableAndStartService(rc, "rabbitmq-server"); err != nil {
		return fmt.Errorf("failed to start RabbitMQ: %w", err)
	}

	// Add openstack user
	addUserCmd := exec.CommandContext(rc.Ctx, "rabbitmqctl", "add_user",
		"openstack", config.RabbitMQPassword)
	if err := addUserCmd.Run(); err != nil {
		// User might already exist
		changePassCmd := exec.CommandContext(rc.Ctx, "rabbitmqctl", "change_password",
			"openstack", config.RabbitMQPassword)
		if err := changePassCmd.Run(); err != nil {
			return fmt.Errorf("failed to set RabbitMQ password: %w", err)
		}
	}

	// Set permissions
	setPermCmd := exec.CommandContext(rc.Ctx, "rabbitmqctl", "set_permissions",
		"openstack", ".*", ".*", ".*")
	if err := setPermCmd.Run(); err != nil {
		return fmt.Errorf("failed to set RabbitMQ permissions: %w", err)
	}

	// Enable management plugin
	enablePluginCmd := exec.CommandContext(rc.Ctx, "rabbitmq-plugins", "enable",
		"rabbitmq_management")
	enablePluginCmd.Run()

	// Configure for OpenStack scale
	if err := configureRabbitMQForOpenStack(rc); err != nil {
		logger.Warn("Failed to optimize RabbitMQ configuration", zap.Error(err))
	}

	return nil
}

// secureMariaDB performs security hardening on MariaDB
func secureMariaDB(rc *eos_io.RuntimeContext, config *Config) error {
	// Set root password if not already set
	setRootPassCmd := fmt.Sprintf(`mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '%s';"`,
		config.DBPassword)
	exec.CommandContext(rc.Ctx, "bash", "-c", setRootPassCmd).Run()

	// Remove anonymous users
	removeAnonCmd := fmt.Sprintf(`mysql -u root -p%s -e "DELETE FROM mysql.user WHERE User='';"`,
		config.DBPassword)
	exec.CommandContext(rc.Ctx, "bash", "-c", removeAnonCmd).Run()

	// Remove remote root access
	removeRemoteRootCmd := fmt.Sprintf(`mysql -u root -p%s -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"`,
		config.DBPassword)
	exec.CommandContext(rc.Ctx, "bash", "-c", removeRemoteRootCmd).Run()

	// Remove test database
	removeTestDBCmd := fmt.Sprintf(`mysql -u root -p%s -e "DROP DATABASE IF EXISTS test;"`,
		config.DBPassword)
	exec.CommandContext(rc.Ctx, "bash", "-c", removeTestDBCmd).Run()

	// Flush privileges
	flushCmd := fmt.Sprintf(`mysql -u root -p%s -e "FLUSH PRIVILEGES;"`,
		config.DBPassword)
	exec.CommandContext(rc.Ctx, "bash", "-c", flushCmd).Run()

	return nil
}

// configureRabbitMQForOpenStack optimizes RabbitMQ for OpenStack
func configureRabbitMQForOpenStack(rc *eos_io.RuntimeContext) error {
	// Create RabbitMQ configuration for OpenStack
	rabbitmqConfig := `# OpenStack optimized configuration
vm_memory_high_watermark.relative = 0.4
disk_free_limit.absolute = 5GB

# Increase connection limits
tcp_listen_options.backlog = 4096
tcp_listen_options.nodelay = true

# Management settings
management.tcp.port = 15672
management.tcp.ip = 0.0.0.0

# Logging
log.file.level = info
log.console.level = info
`

	configPath := "/etc/rabbitmq/rabbitmq.conf"
	if err := os.WriteFile(configPath, []byte(rabbitmqConfig), 0644); err != nil {
		return err
	}

	// Restart RabbitMQ to apply configuration
	return restartService(rc, "rabbitmq-server")
}





// detectIPInNetwork finds an IP address in the specified network
func detectIPInNetwork(network string) string {
	// This would parse the network CIDR and find a matching interface
	// Simplified for this example
	return "10.0.0.10"
}

// getPrimaryIP gets the primary IP address of the system
func getPrimaryIP() string {
	cmd := exec.Command("hostname", "-I")
	output, err := cmd.Output()
	if err != nil {
		return "127.0.0.1"
	}

	ips := strings.Fields(string(output))
	if len(ips) > 0 {
		// Skip loopback and link-local addresses
		for _, ip := range ips {
			if !strings.HasPrefix(ip, "127.") && !strings.HasPrefix(ip, "169.254.") {
				return ip
			}
		}
	}

	return "127.0.0.1"
}

// formatMode returns a human-readable deployment mode string
func formatMode(mode DeploymentMode) string {
	switch mode {
	case ModeAllInOne:
		return "All-in-One"
	case ModeController:
		return "Controller"
	case ModeCompute:
		return "Compute"
	case ModeStorage:
		return "Storage"
	default:
		return string(mode)
	}
}

// formatNetworkType returns a human-readable network type string
func formatNetworkType(nt NetworkType) string {
	switch nt {
	case NetworkProvider:
		return "Provider"
	case NetworkTenant:
		return "Tenant"
	case NetworkHybrid:
		return "Hybrid"
	default:
		return string(nt)
	}
}

// formatStorageBackend returns a human-readable storage backend string
func formatStorageBackend(sb StorageBackend) string {
	switch sb {
	case StorageLVM:
		return "LVM"
	case StorageCeph:
		return "Ceph"
	case StorageNFS:
		return "NFS"
	default:
		return string(sb)
	}
}

// formatEnabled returns a human-readable enabled/disabled string
func formatEnabled(enabled bool) string {
	if enabled {
		return "Enabled"
	}
	return "Disabled"
}









// createBackupDirectory creates a directory for backups
func createBackupDirectory() (string, error) {
	backupDir := fmt.Sprintf("/var/backups/openstack-%d", 
		time.Now().Unix())
	
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return "", err
	}
	
	return backupDir, nil
}

// logProgress logs installation progress with a progress indicator
func logProgress(logger *otelzap.Logger, step, total int, message string) {
	percentage := (step * 100) / total
	logger.Info(fmt.Sprintf("[%d/%d] %s", step, total, message),
		zap.Int("progress", percentage))
}

// validateEndpointURL validates an endpoint URL format
func validateEndpointURL(url string) error {
	if url == "" {
		return fmt.Errorf("endpoint URL cannot be empty")
	}
	
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("endpoint URL must start with http:// or https://")
	}
	
	return nil
}

// ensureServiceUser creates a system user for a service if it doesn't exist
func ensureServiceUser(rc *eos_io.RuntimeContext, service string) error {
	// Check if user exists
	checkCmd := exec.CommandContext(rc.Ctx, "id", service)
	if checkCmd.Run() == nil {
		return nil // User exists
	}
	
	// Create user
	createCmd := exec.CommandContext(rc.Ctx, "useradd",
		"-r", "-d", fmt.Sprintf("/var/lib/%s", service),
		"-s", "/bin/false", service)
	
	if err := createCmd.Run(); err != nil {
		return fmt.Errorf("failed to create %s user: %w", service, err)
	}
	
	return nil
}

// setServiceOwnership sets ownership of files to the service user
func setServiceOwnership(path, service string) error {
	return eos_unix.EnsureOwnership(nil, path, service+":"+service)
}

// waitForService waits for a service to become ready
func waitForService(rc *eos_io.RuntimeContext, service string, timeout int) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	for i := 0; i < timeout; i++ {
		statusCmd := exec.CommandContext(rc.Ctx, "systemctl", "is-active", service)
		if statusCmd.Run() == nil {
			logger.Debug("Service is active", zap.String("service", service))
			return nil
		}
		
		exec.CommandContext(rc.Ctx, "sleep", "1").Run()
	}
	
	return fmt.Errorf("timeout waiting for %s to start", service)
}

// extractVersion extracts version number from a version string
func extractVersion(versionString string) string {
	// Extract semantic version from strings like "1.2.3-ubuntu1"
	parts := strings.Split(versionString, "-")
	if len(parts) > 0 {
		return parts[0]
	}
	return versionString
}


