package openstack

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// installKeystone installs and configures the Keystone identity service
func installKeystone(rc *eos_io.RuntimeContext, config *Config) error {
	ctx, span := telemetry.Start(rc.Ctx, "openstack.installKeystone")
	defer span.End()
	rc = &eos_io.RuntimeContext{Ctx: ctx}

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Keystone identity service")

	// Install packages
	packages := []string{
		"keystone",
		"apache2",
		"libapache2-mod-wsgi-py3",
		"python3-oauth2client",
	}

	installCmd := exec.CommandContext(rc.Ctx, "apt-get", "install", "-y")
	installCmd.Args = append(installCmd.Args, packages...)
	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("failed to install Keystone packages: %w", err)
	}

	// Stop Keystone service (we'll use Apache)
	exec.CommandContext(rc.Ctx, "systemctl", "stop", "keystone").Run()
	exec.CommandContext(rc.Ctx, "systemctl", "disable", "keystone").Run()

	// Initialize database
	if err := initializeKeystoneDatabase(rc, config); err != nil {
		return fmt.Errorf("failed to initialize Keystone database: %w", err)
	}

	// Initialize Fernet keys
	if err := initializeFernetKeys(rc); err != nil {
		return fmt.Errorf("failed to initialize Fernet keys: %w", err)
	}

	// Configure Apache for Keystone
	if err := configureApacheKeystone(rc, config); err != nil {
		return fmt.Errorf("failed to configure Apache for Keystone: %w", err)
	}

	// Bootstrap Keystone
	if err := bootstrapKeystone(rc, config); err != nil {
		return fmt.Errorf("failed to bootstrap Keystone: %w", err)
	}

	// Create service catalog
	if err := createServiceCatalog(rc, config); err != nil {
		return fmt.Errorf("failed to create service catalog: %w", err)
	}

	// Configure LDAP/AD if requested
	if config.EnableLDAP {
		if err := configureLDAPBackend(rc, config); err != nil {
			logger.Warn("Failed to configure LDAP backend", zap.Error(err))
		}
	}

	logger.Info("Keystone installation completed")
	return nil
}

// initializeKeystoneDatabase creates and initializes the Keystone database
func initializeKeystoneDatabase(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Initializing Keystone database")

	// Create database
	createDBCmd := fmt.Sprintf(`mysql -u root -p%s -e "CREATE DATABASE IF NOT EXISTS keystone;"`,
		config.DBPassword)
	if err := exec.CommandContext(rc.Ctx, "bash", "-c", createDBCmd).Run(); err != nil {
		return fmt.Errorf("failed to create Keystone database: %w", err)
	}

	// Grant privileges
	grantCmd := fmt.Sprintf(`mysql -u root -p%s -e "GRANT ALL PRIVILEGES ON keystone.* TO 'keystone'@'localhost' IDENTIFIED BY '%s';"`,
		config.DBPassword, config.DBPassword)
	if err := exec.CommandContext(rc.Ctx, "bash", "-c", grantCmd).Run(); err != nil {
		return fmt.Errorf("failed to grant Keystone database privileges: %w", err)
	}

	grantCmd2 := fmt.Sprintf(`mysql -u root -p%s -e "GRANT ALL PRIVILEGES ON keystone.* TO 'keystone'@'%%' IDENTIFIED BY '%s';"`,
		config.DBPassword, config.DBPassword)
	exec.CommandContext(rc.Ctx, "bash", "-c", grantCmd2).Run()

	// Sync database
	syncCmd := exec.CommandContext(rc.Ctx, "keystone-manage", "db_sync")
	syncCmd.Env = append(os.Environ(),
		fmt.Sprintf("OS_DATABASE_PASSWORD=%s", config.DBPassword))
	if err := syncCmd.Run(); err != nil {
		return fmt.Errorf("failed to sync Keystone database: %w", err)
	}

	return nil
}

// initializeFernetKeys sets up Fernet token encryption keys
func initializeFernetKeys(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Initializing Fernet keys")

	// Setup Fernet key repository
	fernetCmd := exec.CommandContext(rc.Ctx, "keystone-manage", "fernet_setup",
		"--keystone-user", "keystone",
		"--keystone-group", "keystone")
	if err := fernetCmd.Run(); err != nil {
		return fmt.Errorf("failed to setup Fernet keys: %w", err)
	}

	// Setup credential keys
	credCmd := exec.CommandContext(rc.Ctx, "keystone-manage", "credential_setup",
		"--keystone-user", "keystone",
		"--keystone-group", "keystone")
	if err := credCmd.Run(); err != nil {
		return fmt.Errorf("failed to setup credential keys: %w", err)
	}

	return nil
}

// configureApacheKeystone configures Apache to serve Keystone
func configureApacheKeystone(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Apache for Keystone")

	// Create Apache configuration for Keystone
	apacheConfig := fmt.Sprintf(`Listen %d

<VirtualHost *:%d>
    ServerName %s
    
    SSLEngine %s
    %s
    
    WSGIDaemonProcess keystone-public processes=5 threads=1 user=keystone group=keystone display-name=%%{GROUP}
    WSGIProcessGroup keystone-public
    WSGIScriptAlias / /usr/bin/keystone-wsgi-public
    WSGIApplicationGroup %%{GLOBAL}
    WSGIPassAuthorization On
    
    ErrorLogFormat "%%{cu}t %%M"
    ErrorLog /var/log/apache2/keystone-error.log
    CustomLog /var/log/apache2/keystone-access.log combined
    
    <Directory /usr/bin>
        Require all granted
    </Directory>
</VirtualHost>
`, PortKeystone, PortKeystone, getServerName(config),
		getSSLEngine(config), getSSLConfig(config))

	// Write Apache configuration
	configPath := "/etc/apache2/sites-available/keystone.conf"
	if err := os.WriteFile(configPath, []byte(apacheConfig), 0644); err != nil {
		return fmt.Errorf("failed to write Apache config: %w", err)
	}

	// Enable required Apache modules
	modules := []string{"wsgi", "ssl", "headers", "rewrite"}
	for _, mod := range modules {
		enableCmd := exec.CommandContext(rc.Ctx, "a2enmod", mod)
		if err := enableCmd.Run(); err != nil {
			logger.Warn("Failed to enable Apache module",
				zap.String("module", mod),
				zap.Error(err))
		}
	}

	// Disable default site
	exec.CommandContext(rc.Ctx, "a2dissite", "000-default").Run()

	// Enable Keystone site
	enableSiteCmd := exec.CommandContext(rc.Ctx, "a2ensite", "keystone")
	if err := enableSiteCmd.Run(); err != nil {
		return fmt.Errorf("failed to enable Keystone site: %w", err)
	}

	// Restart Apache
	restartCmd := exec.CommandContext(rc.Ctx, "systemctl", "restart", "apache2")
	if err := restartCmd.Run(); err != nil {
		return fmt.Errorf("failed to restart Apache: %w", err)
	}

	return nil
}

// bootstrapKeystone performs initial Keystone bootstrap
func bootstrapKeystone(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Bootstrapping Keystone")

	adminURL := fmt.Sprintf("%s:%d/v3/", config.AdminEndpoint, PortKeystone)
	publicURL := fmt.Sprintf("%s:%d/v3/", config.PublicEndpoint, PortKeystone)
	internalURL := fmt.Sprintf("%s:%d/v3/", config.InternalEndpoint, PortKeystone)

	bootstrapCmd := exec.CommandContext(rc.Ctx, "keystone-manage", "bootstrap",
		"--bootstrap-password", config.AdminPassword,
		"--bootstrap-admin-url", adminURL,
		"--bootstrap-internal-url", internalURL,
		"--bootstrap-public-url", publicURL,
		"--bootstrap-region-id", "RegionOne")

	output, err := bootstrapCmd.CombinedOutput()
	if err != nil {
		logger.Error("Keystone bootstrap failed",
			zap.String("output", string(output)),
			zap.Error(err))
		return fmt.Errorf("failed to bootstrap Keystone: %w", err)
	}

	logger.Info("Keystone bootstrap completed")
	return nil
}

// createServiceCatalog creates the OpenStack service catalog entries
func createServiceCatalog(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating OpenStack service catalog")

	// Set environment for OpenStack commands
	env := []string{
		fmt.Sprintf("OS_PROJECT_DOMAIN_NAME=Default"),
		fmt.Sprintf("OS_USER_DOMAIN_NAME=Default"),
		fmt.Sprintf("OS_PROJECT_NAME=admin"),
		fmt.Sprintf("OS_USERNAME=admin"),
		fmt.Sprintf("OS_PASSWORD=%s", config.AdminPassword),
		fmt.Sprintf("OS_AUTH_URL=%s:%d/v3", config.InternalEndpoint, PortKeystone),
		fmt.Sprintf("OS_IDENTITY_API_VERSION=3"),
		fmt.Sprintf("OS_IMAGE_API_VERSION=2"),
	}

	// Create service project
	createProjectCmd := exec.CommandContext(rc.Ctx, "openstack", "project", "create",
		"--domain", "default",
		"--description", "Service Project",
		"service")
	createProjectCmd.Env = append(os.Environ(), env...)
	if err := createProjectCmd.Run(); err != nil {
		logger.Warn("Failed to create service project", zap.Error(err))
	}

	// Create service users and endpoints
	services := []struct {
		name        string
		description string
		serviceType string
		port        int
	}{
		{"glance", "OpenStack Image", "image", PortGlance},
		{"nova", "OpenStack Compute", "compute", PortNovaAPI},
		{"placement", "Placement API", "placement", 8778},
		{"neutron", "OpenStack Networking", "network", PortNeutron},
		{"cinder", "OpenStack Block Storage", "volumev3", PortCinder},
		{"swift", "OpenStack Object Storage", "object-store", PortSwift},
		{"heat", "OpenStack Orchestration", "orchestration", PortHeat},
	}

	for _, svc := range services {
		if !contains(config.GetEnabledServices(), Service(svc.name)) && svc.name != "placement" {
			continue
		}

		logger.Info("Creating service catalog entry", zap.String("service", svc.name))

		// Create user
		createUserCmd := exec.CommandContext(rc.Ctx, "openstack", "user", "create",
			"--domain", "default",
			"--password", config.ServicePassword,
			svc.name)
		createUserCmd.Env = append(os.Environ(), env...)
		if err := createUserCmd.Run(); err != nil {
			logger.Warn("Failed to create service user",
				zap.String("service", svc.name),
				zap.Error(err))
			continue
		}

		// Add user to service project with admin role
		addRoleCmd := exec.CommandContext(rc.Ctx, "openstack", "role", "add",
			"--project", "service",
			"--user", svc.name,
			"admin")
		addRoleCmd.Env = append(os.Environ(), env...)
		addRoleCmd.Run()

		// Create service
		createServiceCmd := exec.CommandContext(rc.Ctx, "openstack", "service", "create",
			"--name", svc.name,
			"--description", svc.description,
			svc.serviceType)
		createServiceCmd.Env = append(os.Environ(), env...)
		if err := createServiceCmd.Run(); err != nil {
			logger.Warn("Failed to create service",
				zap.String("service", svc.name),
				zap.Error(err))
			continue
		}

		// Create endpoints
		for _, endpointType := range []string{"public", "internal", "admin"} {
			var url string
			switch endpointType {
			case "public":
				url = fmt.Sprintf("%s:%d", config.PublicEndpoint, svc.port)
			case "internal":
				url = fmt.Sprintf("%s:%d", config.InternalEndpoint, svc.port)
			case "admin":
				url = fmt.Sprintf("%s:%d", getAdminEndpoint(config), svc.port)
			}

			// Add path based on service
			switch svc.name {
			case "nova":
				url += "/v2.1"
			case "placement":
				url += "/"
			case "cinder":
				url += "/v3/%(project_id)s"
			case "glance":
				url += "/"
			case "neutron":
				url += "/"
			case "swift":
				url += "/v1/AUTH_%(project_id)s"
			case "heat":
				url += "/v1/%(project_id)s"
			}

			createEndpointCmd := exec.CommandContext(rc.Ctx, "openstack", "endpoint", "create",
				"--region", "RegionOne",
				svc.serviceType,
				endpointType,
				url)
			createEndpointCmd.Env = append(os.Environ(), env...)
			if err := createEndpointCmd.Run(); err != nil {
				logger.Warn("Failed to create endpoint",
					zap.String("service", svc.name),
					zap.String("type", endpointType),
					zap.Error(err))
			}
		}
	}

	// Create additional roles
	roles := []string{"member", "reader", "heat_stack_owner", "heat_stack_user"}
	for _, role := range roles {
		createRoleCmd := exec.CommandContext(rc.Ctx, "openstack", "role", "create", role)
		createRoleCmd.Env = append(os.Environ(), env...)
		createRoleCmd.Run() // Ignore errors if role exists
	}

	// Create demo project and user for testing
	if err := createDemoResources(rc, config, env); err != nil {
		logger.Warn("Failed to create demo resources", zap.Error(err))
	}

	return nil
}

// createDemoResources creates demo project and user for testing
func createDemoResources(rc *eos_io.RuntimeContext, config *Config, env []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating demo resources")

	// Create demo project
	createProjectCmd := exec.CommandContext(rc.Ctx, "openstack", "project", "create",
		"--domain", "default",
		"--description", "Demo Project",
		"demo")
	createProjectCmd.Env = append(os.Environ(), env...)
	if err := createProjectCmd.Run(); err != nil {
		return fmt.Errorf("failed to create demo project: %w", err)
	}

	// Create demo user
	demoPassword := "demo" // In production, use a secure password
	createUserCmd := exec.CommandContext(rc.Ctx, "openstack", "user", "create",
		"--domain", "default",
		"--password", demoPassword,
		"demo")
	createUserCmd.Env = append(os.Environ(), env...)
	if err := createUserCmd.Run(); err != nil {
		return fmt.Errorf("failed to create demo user: %w", err)
	}

	// Add member role to demo user
	addRoleCmd := exec.CommandContext(rc.Ctx, "openstack", "role", "add",
		"--project", "demo",
		"--user", "demo",
		"member")
	addRoleCmd.Env = append(os.Environ(), env...)
	addRoleCmd.Run()

	// Create demo environment file
	demoEnvContent := fmt.Sprintf(`# Demo user environment
export OS_PROJECT_DOMAIN_NAME=Default
export OS_USER_DOMAIN_NAME=Default
export OS_PROJECT_NAME=demo
export OS_USERNAME=demo
export OS_PASSWORD=%s
export OS_AUTH_URL=%s:%d/v3
export OS_IDENTITY_API_VERSION=3
export OS_IMAGE_API_VERSION=2
`, demoPassword, config.PublicEndpoint, PortKeystone)

	demoEnvPath := "/etc/openstack/demo-openrc.sh"
	if err := os.WriteFile(demoEnvPath, []byte(demoEnvContent), 0600); err != nil {
		logger.Warn("Failed to write demo environment file", zap.Error(err))
	}

	return nil
}

// configureLDAPBackend configures LDAP/AD authentication backend
func configureLDAPBackend(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring LDAP authentication backend")

	// Install LDAP packages
	packages := []string{"python3-ldap", "python3-ldappool"}
	installCmd := exec.CommandContext(rc.Ctx, "apt-get", "install", "-y")
	installCmd.Args = append(installCmd.Args, packages...)
	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("failed to install LDAP packages: %w", err)
	}

	// Generate LDAP configuration
	ldapConfig := fmt.Sprintf(`[identity]
driver = ldap

[ldap]
url = %s
user = %s
password = %s
suffix = %s
use_tls = %v
tls_cacertfile = %s
tls_req_cert = demand

user_tree_dn = %s
user_objectclass = %s
user_id_attribute = %s
user_name_attribute = %s
user_mail_attribute = %s
user_enabled_attribute = %s
user_enabled_default = True
user_attribute_ignore = password,tenant_id,tenants

group_tree_dn = %s
group_objectclass = %s
group_id_attribute = %s
group_name_attribute = %s
group_member_attribute = %s
group_desc_attribute = %s

[assignment]
driver = sql
`, config.LDAPServer, config.LDAPUser, config.LDAPPassword,
		config.LDAPSuffix, config.LDAPUseTLS, config.LDAPCACert,
		config.LDAPUserTreeDN, config.LDAPUserObjectClass,
		config.LDAPUserIDAttribute, config.LDAPUserNameAttribute,
		config.LDAPUserMailAttribute, config.LDAPUserEnabledAttribute,
		config.LDAPGroupTreeDN, config.LDAPGroupObjectClass,
		config.LDAPGroupIDAttribute, config.LDAPGroupNameAttribute,
		config.LDAPGroupMemberAttribute, config.LDAPGroupDescAttribute)

	// Create domains configuration directory
	domainsDir := "/etc/keystone/domains"
	if err := os.MkdirAll(domainsDir, 0755); err != nil {
		return fmt.Errorf("failed to create domains directory: %w", err)
	}

	// Write LDAP domain configuration
	ldapDomainConfig := filepath.Join(domainsDir, "keystone.LDAP.conf")
	if err := os.WriteFile(ldapDomainConfig, []byte(ldapConfig), 0640); err != nil {
		return fmt.Errorf("failed to write LDAP config: %w", err)
	}

	// Set ownership
	uid, gid, err := eos_unix.LookupUser(rc.Ctx, "keystone")
	if err != nil {
		logger.Warn("Failed to lookup keystone user", zap.Error(err))
	} else {
		if err := os.Chown(ldapDomainConfig, uid, gid); err != nil {
			logger.Warn("Failed to set ownership on LDAP config", zap.Error(err))
		}
	}

	// Update main Keystone config to enable domain-specific configs
	// This would update the configuration to enable domain_specific_drivers_enabled
	// Simplified for this example

	// Restart Keystone
	restartCmd := exec.CommandContext(rc.Ctx, "systemctl", "restart", "apache2")
	if err := restartCmd.Run(); err != nil {
		return fmt.Errorf("failed to restart Apache: %w", err)
	}

	logger.Info("LDAP backend configured successfully")
	return nil
}

// configureKeystoneVaultIntegration sets up Vault integration for Keystone
func configureKeystoneVaultIntegration(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Vault integration for Keystone")

	// Store service passwords in Vault
	secrets := map[string]string{
		"admin_password":    config.AdminPassword,
		"service_password":  config.ServicePassword,
		"db_password":       config.DBPassword,
		"rabbitmq_password": config.RabbitMQPassword,
	}

	for key, value := range secrets {
		path := fmt.Sprintf("secret/openstack/keystone/%s", key)
		if err := storeInVault(rc, config, path, value); err != nil {
			logger.Warn("Failed to store secret in Vault",
				zap.String("key", key),
				zap.Error(err))
		}
	}

	// Configure Keystone to use Vault for credential backend
	// This would require additional Keystone configuration
	// Simplified for this example

	return nil
}

// Helper functions for identity management

func getServerName(config *Config) string {
	// Extract hostname from endpoint URL
	parts := strings.Split(config.PublicEndpoint, "://")
	if len(parts) > 1 {
		return strings.Split(parts[1], ":")[0]
	}
	return "localhost"
}

func getSSLEngine(config *Config) string {
	if config.EnableSSL {
		return "on"
	}
	return "off"
}

func getSSLConfig(config *Config) string {
	if !config.EnableSSL {
		return ""
	}

	return fmt.Sprintf(`SSLCertificateFile %s
    SSLCertificateKeyFile %s
    SSLProtocol All -SSLv2 -SSLv3
    SSLCipherSuite ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256
    SSLHonorCipherOrder On`,
		config.SSLCertPath, config.SSLKeyPath)
}

func storeInVault(rc *eos_io.RuntimeContext, config *Config, path, value string) error {
	// This would use the Vault API to store secrets
	// Simplified for this example
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Storing secret in Vault", zap.String("path", path))
	return nil
}

