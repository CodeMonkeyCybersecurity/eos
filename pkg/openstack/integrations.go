package openstack

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// configureVaultIntegration sets up Vault integration for OpenStack
func configureVaultIntegration(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Vault integration for OpenStack")

	// Verify Vault is accessible
	if err := verifyVaultConnection(rc, config); err != nil {
		return fmt.Errorf("cannot connect to Vault: %w", err)
	}

	// Create OpenStack secrets engine
	if err := createVaultSecretsEngine(rc, config); err != nil {
		return fmt.Errorf("failed to create Vault secrets engine: %w", err)
	}

	// Store OpenStack credentials in Vault
	if err := storeOpenStackCredentials(rc, config); err != nil {
		return fmt.Errorf("failed to store credentials in Vault: %w", err)
	}

	// Configure Keystone to use Vault for credential storage
	if err := configureKeystoneVault(rc, config); err != nil {
		return fmt.Errorf("failed to configure Keystone with Vault: %w", err)
	}

	// Configure Barbican (if needed) for secret management
	if contains(config.GetEnabledServices(), "barbican") {
		if err := configureBarbicanVault(rc, config); err != nil {
			return fmt.Errorf("failed to configure Barbican with Vault: %w", err)
		}
	}

	// Create Vault policies for OpenStack services
	if err := createVaultPolicies(rc, config); err != nil {
		return fmt.Errorf("failed to create Vault policies: %w", err)
	}

	logger.Info("Vault integration configured successfully")
	return nil
}

// configureConsulIntegration sets up Consul integration for OpenStack
func configureConsulIntegration(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Consul integration for OpenStack")

	// Verify Consul is accessible
	if err := verifyConsulConnection(rc, config); err != nil {
		return fmt.Errorf("cannot connect to Consul: %w", err)
	}

	// Register OpenStack services with Consul
	services := []struct {
		name string
		port int
		tags []string
		meta map[string]string
	}{
		{
			name: "openstack-keystone",
			port: PortKeystone,
			tags: []string{"openstack", "identity", "api"},
			meta: map[string]string{
				"version":  "v3",
				"endpoint": fmt.Sprintf("%s:%d/v3", config.PublicEndpoint, PortKeystone),
			},
		},
		{
			name: "openstack-glance",
			port: PortGlance,
			tags: []string{"openstack", "image", "api"},
			meta: map[string]string{
				"version":  "v2",
				"endpoint": fmt.Sprintf("%s:%d", config.PublicEndpoint, PortGlance),
			},
		},
		{
			name: "openstack-nova",
			port: PortNovaAPI,
			tags: []string{"openstack", "compute", "api"},
			meta: map[string]string{
				"version":  "v2.1",
				"endpoint": fmt.Sprintf("%s:%d/v2.1", config.PublicEndpoint, PortNovaAPI),
			},
		},
		{
			name: "openstack-neutron",
			port: PortNeutron,
			tags: []string{"openstack", "network", "api"},
			meta: map[string]string{
				"version":  "v2",
				"endpoint": fmt.Sprintf("%s:%d", config.PublicEndpoint, PortNeutron),
			},
		},
		{
			name: "openstack-cinder",
			port: PortCinder,
			tags: []string{"openstack", "volume", "api"},
			meta: map[string]string{
				"version":  "v3",
				"endpoint": fmt.Sprintf("%s:%d/v3", config.PublicEndpoint, PortCinder),
			},
		},
	}

	// Register each service
	for _, svc := range services {
		if shouldRegisterService(config, svc.name) {
			if err := registerConsulService(rc, config, svc.name, svc.port, svc.tags, svc.meta); err != nil {
				logger.Warn("Failed to register service with Consul",
					zap.String("service", svc.name),
					zap.Error(err))
			}
		}
	}

	// Configure health checks
	if err := configureConsulHealthChecks(rc, config); err != nil {
		return fmt.Errorf("failed to configure Consul health checks: %w", err)
	}

	// Set up Consul watches for configuration changes
	if err := setupConsulWatches(rc, config); err != nil {
		logger.Warn("Failed to setup Consul watches", zap.Error(err))
	}

	// Store configuration in Consul KV
	if err := storeConfigInConsul(rc, config); err != nil {
		logger.Warn("Failed to store configuration in Consul", zap.Error(err))
	}

	logger.Info("Consul integration configured successfully")
	return nil
}

// verifyVaultConnection checks if Vault is accessible
func verifyVaultConnection(rc *eos_io.RuntimeContext, config *Config) error {
	// Set Vault address
	os.Setenv("VAULT_ADDR", config.VaultAddress)

	// Check Vault status
	statusCmd := exec.CommandContext(rc.Ctx, "vault", "status", "-format=json")
	output, err := statusCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to check Vault status: %w", err)
	}

	var status map[string]interface{}
	if err := json.Unmarshal(output, &status); err != nil {
		return fmt.Errorf("failed to parse Vault status: %w", err)
	}

	if sealed, ok := status["sealed"].(bool); ok && sealed {
		return fmt.Errorf("Vault is sealed")
	}

	return nil
}

// createVaultSecretsEngine creates OpenStack secrets engine in Vault
func createVaultSecretsEngine(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Enable KV v2 secrets engine for OpenStack
	enableCmd := exec.CommandContext(rc.Ctx, "vault", "secrets", "enable",
		"-path=openstack", "-version=2", "kv")
	if err := enableCmd.Run(); err != nil {
		// Check if already enabled
		listCmd := exec.CommandContext(rc.Ctx, "vault", "secrets", "list", "-format=json")
		output, _ := listCmd.Output()
		if strings.Contains(string(output), "openstack/") {
			logger.Debug("OpenStack secrets engine already enabled")
		} else {
			return fmt.Errorf("failed to enable secrets engine: %w", err)
		}
	}

	return nil
}

// storeOpenStackCredentials stores OpenStack credentials in Vault
func storeOpenStackCredentials(rc *eos_io.RuntimeContext, config *Config) error {
	credentials := map[string]interface{}{
		"admin_password":    config.AdminPassword,
		"service_password":  config.ServicePassword,
		"db_password":       config.DBPassword,
		"rabbitmq_password": config.RabbitMQPassword,
		"metadata_secret":   generateToken(),
	}

	// Store main credentials
	credsJSON, err := json.Marshal(credentials)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	storeCmd := exec.CommandContext(rc.Ctx, "vault", "kv", "put",
		"openstack/credentials", "-", "-format=json")
	storeCmd.Stdin = strings.NewReader(string(credsJSON))
	if err := storeCmd.Run(); err != nil {
		return fmt.Errorf("failed to store credentials in Vault: %w", err)
	}

	// Store service-specific credentials
	services := []string{"keystone", "glance", "nova", "neutron", "cinder"}
	for _, svc := range services {
		svcCreds := map[string]interface{}{
			"password": config.ServicePassword,
			"user":     svc,
			"project":  "service",
		}

		svcJSON, _ := json.Marshal(svcCreds)
		svcCmd := exec.CommandContext(rc.Ctx, "vault", "kv", "put",
			fmt.Sprintf("openstack/services/%s", svc), "-")
		svcCmd.Stdin = strings.NewReader(string(svcJSON))
		svcCmd.Run()
	}

	return nil
}

// configureKeystoneVault configures Keystone to use Vault
func configureKeystoneVault(rc *eos_io.RuntimeContext, config *Config) error {
	// Add Vault configuration to Keystone
	vaultConfig := fmt.Sprintf(`
[credential]
provider = vault
vault_url = %s
vault_token = %s
vault_path = openstack/credentials

[fernet_tokens]
key_repository = vault://openstack/fernet-keys/
`, config.VaultAddress, config.VaultToken)

	keystoneConfig := "/etc/keystone/keystone.conf.d/vault.conf"
	if err := os.MkdirAll(filepath.Dir(keystoneConfig), 0755); err != nil {
		return err
	}

	if err := os.WriteFile(keystoneConfig, []byte(vaultConfig), 0640); err != nil {
		return fmt.Errorf("failed to write Keystone Vault config: %w", err)
	}

	// Set ownership
	uid, gid, err := eos_unix.LookupUser(rc.Ctx, "keystone")
	if err == nil {
		os.Chown(keystoneConfig, uid, gid)
	}

	// Restart Keystone
	exec.CommandContext(rc.Ctx, "systemctl", "restart", "apache2").Run()

	return nil
}

// createVaultPolicies creates Vault policies for OpenStack services
func createVaultPolicies(rc *eos_io.RuntimeContext, config *Config) error {
	// Create policies for each service
	services := []string{"keystone", "glance", "nova", "neutron", "cinder"}

	for _, svc := range services {
		policy := fmt.Sprintf(`
# Policy for OpenStack %s service
path "openstack/data/services/%s" {
  capabilities = ["read"]
}

path "openstack/data/credentials" {
  capabilities = ["read"]
}

path "openstack/metadata/*" {
  capabilities = ["list"]
}
`, svc, svc)

		// Write policy to temp file
		policyFile := fmt.Sprintf("/tmp/openstack-%s-policy.hcl", svc)
		if err := os.WriteFile(policyFile, []byte(policy), 0600); err != nil {
			continue
		}

		// Create policy in Vault
		policyCmd := exec.CommandContext(rc.Ctx, "vault", "policy", "write",
			fmt.Sprintf("openstack-%s", svc), policyFile)
		policyCmd.Run()

		// Clean up temp file
		os.Remove(policyFile)
	}

	return nil
}

// verifyConsulConnection checks if Consul is accessible
func verifyConsulConnection(rc *eos_io.RuntimeContext, config *Config) error {
	// Set Consul address
	os.Setenv("CONSUL_HTTP_ADDR", config.ConsulAddress)

	// Check Consul status
	statusCmd := exec.CommandContext(rc.Ctx, "consul", "members")
	if err := statusCmd.Run(); err != nil {
		return fmt.Errorf("failed to connect to Consul: %w", err)
	}

	return nil
}

// registerConsulService registers a service with Consul
func registerConsulService(rc *eos_io.RuntimeContext, config *Config, name string, port int, tags []string, meta map[string]string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Registering service with Consul", zap.String("service", name))

	// Create service definition
	checkURL := fmt.Sprintf("http://localhost:%d/", port)
	// Special handling for Keystone (health check endpoint)
	if strings.Contains(name, "keystone") {
		checkURL = fmt.Sprintf("http://localhost:%d/v3/", port)
	}
	
	service := map[string]interface{}{
		"name": name,
		"port": port,
		"tags": tags,
		"meta": meta,
		"check": map[string]interface{}{
			"http":     checkURL,
			"interval": "30s",
			"timeout":  "10s",
		},
	}

	// Marshal service definition
	serviceJSON, err := json.Marshal(service)
	if err != nil {
		return err
	}

	// Register with Consul
	registerCmd := exec.CommandContext(rc.Ctx, "consul", "services", "register", "-")
	registerCmd.Stdin = strings.NewReader(string(serviceJSON))
	if err := registerCmd.Run(); err != nil {
		return fmt.Errorf("failed to register service: %w", err)
	}

	return nil
}

// configureConsulHealthChecks sets up health checks for OpenStack services
func configureConsulHealthChecks(rc *eos_io.RuntimeContext, config *Config) error {
	// Create health check scripts
	healthCheckDir := "/etc/consul.d/health-checks"
	if err := os.MkdirAll(healthCheckDir, 0755); err != nil {
		return err
	}

	// Keystone health check
	keystoneCheck := `#!/bin/bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/v3/ | grep -q "200\|300"
`
	if err := createHealthCheckScript(healthCheckDir, "keystone", keystoneCheck); err != nil {
		return err
	}

	// Glance health check
	glanceCheck := `#!/bin/bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:9292/ | grep -q "200\|300"
`
	if err := createHealthCheckScript(healthCheckDir, "glance", glanceCheck); err != nil {
		return err
	}

	// Nova health check
	novaCheck := `#!/bin/bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:8774/ | grep -q "200\|300"
`
	if err := createHealthCheckScript(healthCheckDir, "nova", novaCheck); err != nil {
		return err
	}

	return nil
}

// createHealthCheckScript creates a health check script
func createHealthCheckScript(dir, service, content string) error {
	scriptPath := filepath.Join(dir, fmt.Sprintf("%s-health.sh", service))
	if err := os.WriteFile(scriptPath, []byte(content), 0755); err != nil {
		return err
	}
	return nil
}

// setupConsulWatches configures Consul watches for configuration changes
func setupConsulWatches(rc *eos_io.RuntimeContext, config *Config) error {
	// Create watch handlers directory
	watchDir := "/etc/consul.d/watch-handlers"
	if err := os.MkdirAll(watchDir, 0755); err != nil {
		return err
	}

	// Watch for configuration changes
	configWatch := map[string]interface{}{
		"type": "key",
		"key":  "openstack/config/reload",
		"handler": filepath.Join(watchDir, "reload-openstack.sh"),
	}

	// Create reload handler script
	reloadScript := `#!/bin/bash
# Reload OpenStack services when configuration changes
echo "Configuration change detected, reloading services..."
systemctl reload apache2  # Keystone
systemctl reload glance-api
systemctl reload nova-api
systemctl reload neutron-server
`
	
	scriptPath := filepath.Join(watchDir, "reload-openstack.sh")
	if err := os.WriteFile(scriptPath, []byte(reloadScript), 0755); err != nil {
		return err
	}

	// Register watch with Consul
	watchJSON, _ := json.Marshal(configWatch)
	watchFile := "/etc/consul.d/openstack-watch.json"
	if err := os.WriteFile(watchFile, watchJSON, 0644); err != nil {
		return err
	}

	// Reload Consul to pick up new watch
	exec.CommandContext(rc.Ctx, "consul", "reload").Run()

	return nil
}

// storeConfigInConsul stores OpenStack configuration in Consul KV store
func storeConfigInConsul(rc *eos_io.RuntimeContext, config *Config) error {
	// Store endpoint configuration
	endpoints := map[string]string{
		"public":   config.PublicEndpoint,
		"internal": config.InternalEndpoint,
		"admin":    config.AdminEndpoint,
	}

	for key, value := range endpoints {
		putCmd := exec.CommandContext(rc.Ctx, "consul", "kv", "put",
			fmt.Sprintf("openstack/endpoints/%s", key), value)
		putCmd.Run()
	}

	// Store service configuration
	configData := map[string]interface{}{
		"mode":            string(config.Mode),
		"network_type":    string(config.NetworkType),
		"storage_backend": string(config.StorageBackend),
		"features": map[string]bool{
			"dashboard": config.EnableDashboard,
			"ssl":       config.EnableSSL,
		},
	}

	configJSON, _ := json.Marshal(configData)
	configCmd := exec.CommandContext(rc.Ctx, "consul", "kv", "put",
		"openstack/config", "-")
	configCmd.Stdin = strings.NewReader(string(configJSON))
	configCmd.Run()

	return nil
}

// Helper functions

func shouldRegisterService(config *Config, serviceName string) bool {
	// Extract service name from full name (e.g., "openstack-keystone" -> "keystone")
	parts := strings.Split(serviceName, "-")
	if len(parts) < 2 {
		return false
	}
	
	svcName := parts[1]
	services := config.GetEnabledServices()
	
	for _, svc := range services {
		if strings.ToLower(string(svc)) == svcName {
			return true
		}
	}
	
	// Always register Keystone
	return svcName == "keystone"
}

// configureBarbicanVault configures Barbican with Vault backend
func configureBarbicanVault(rc *eos_io.RuntimeContext, config *Config) error {
	// Barbican is the OpenStack key management service
	// It can use Vault as a backend for secret storage
	
	barbicanConfig := fmt.Sprintf(`
[secretstore:vault]
secret_store_plugin = vault_secret_store
vault_url = %s
vault_token = %s
vault_path = openstack/barbican

[secretstore]
enabled_secretstore_plugins = vault
`, config.VaultAddress, config.VaultToken)

	configPath := "/etc/barbican/barbican.conf.d/vault.conf"
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return err
	}

	if err := os.WriteFile(configPath, []byte(barbicanConfig), 0640); err != nil {
		return err
	}

	// Set ownership
	uid, gid, err := eos_unix.LookupUser(rc.Ctx, "barbican")
	if err == nil {
		os.Chown(configPath, uid, gid)
	}

	// Restart Barbican
	exec.CommandContext(rc.Ctx, "systemctl", "restart", "barbican-api").Run()

	return nil
}

// applySecurityHardening applies security hardening for OpenStack
func applySecurityHardening(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Applying security hardening")

	// Disable unnecessary services
	unnecessaryServices := []string{
		"rpcbind", "nfs-server", "snmpd",
	}
	
	for _, svc := range unnecessaryServices {
		disableCmd := exec.CommandContext(rc.Ctx, "systemctl", "disable", svc)
		disableCmd.Run()
		stopCmd := exec.CommandContext(rc.Ctx, "systemctl", "stop", svc)
		stopCmd.Run()
	}

	// Configure firewall rules
	if err := configureFirewall(rc, config); err != nil {
		logger.Warn("Failed to configure firewall", zap.Error(err))
	}

	// Set secure file permissions
	secureFiles := map[string]os.FileMode{
		"/etc/keystone/keystone.conf":     0640,
		"/etc/glance/glance-api.conf":     0640,
		"/etc/nova/nova.conf":             0640,
		"/etc/neutron/neutron.conf":       0640,
		"/etc/cinder/cinder.conf":         0640,
		"/etc/openstack/admin-openrc.sh":  0600,
	}

	for file, mode := range secureFiles {
		if err := os.Chmod(file, mode); err != nil {
			logger.Debug("Failed to set file permissions",
				zap.String("file", file),
				zap.Error(err))
		}
	}

	// Configure SELinux/AppArmor if available
	if err := configureMAC(rc); err != nil {
		logger.Debug("Failed to configure MAC", zap.Error(err))
	}

	return nil
}

// configureFirewall sets up firewall rules for OpenStack
func configureFirewall(rc *eos_io.RuntimeContext, config *Config) error {
	// Check if ufw is available
	ufwCmd := exec.CommandContext(rc.Ctx, "which", "ufw")
	if ufwCmd.Run() == nil {
		// Configure UFW
		rules := []struct {
			port    int
			service string
		}{
			{22, "SSH"},
			{80, "HTTP"},
			{443, "HTTPS"},
			{PortKeystone, "Keystone"},
			{PortGlance, "Glance"},
			{PortNovaAPI, "Nova API"},
			{PortNeutron, "Neutron"},
			{PortCinder, "Cinder"},
			{3306, "MySQL"},
			{5672, "RabbitMQ"},
			{11211, "Memcached"},
		}

		for _, rule := range rules {
			allowCmd := exec.CommandContext(rc.Ctx, "ufw", "allow", fmt.Sprintf("%d/tcp", rule.port))
			allowCmd.Run()
		}

		// Enable UFW
		exec.CommandContext(rc.Ctx, "ufw", "--force", "enable").Run()
	}

	return nil
}

// configureMAC configures Mandatory Access Control (SELinux/AppArmor)
func configureMAC(rc *eos_io.RuntimeContext) error {
	// Check for SELinux
	if _, err := os.Stat("/etc/selinux/config"); err == nil {
		// Set SELinux contexts for OpenStack
		contexts := []struct {
			path    string
			context string
		}{
			{"/var/lib/glance", "system_u:object_r:glance_var_lib_t:s0"},
			{"/var/lib/nova", "system_u:object_r:nova_var_lib_t:s0"},
			{"/var/lib/neutron", "system_u:object_r:neutron_var_lib_t:s0"},
		}

		for _, ctx := range contexts {
			semanageCmd := exec.CommandContext(rc.Ctx, "semanage", "fcontext", "-a", "-t",
				ctx.context, ctx.path+"(/.*)?")
			semanageCmd.Run()
			
			restoreconCmd := exec.CommandContext(rc.Ctx, "restorecon", "-R", ctx.path)
			restoreconCmd.Run()
		}
	}

	// Check for AppArmor
	if _, err := os.Stat("/etc/apparmor.d"); err == nil {
		// OpenStack services typically have their own AppArmor profiles
		// Ensure they're loaded
		parserCmd := exec.CommandContext(rc.Ctx, "apparmor_parser", "-r",
			"/etc/apparmor.d/usr.bin.nova-*")
		parserCmd.Run()
	}

	return nil
}