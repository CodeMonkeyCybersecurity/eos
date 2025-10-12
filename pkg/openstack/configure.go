package openstack

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"text/template"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/crypto"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Configuration templates for various OpenStack services
const (
	keystoneConfTemplate = `[DEFAULT]
admin_token = {{ .AdminToken }}
log_dir = {{ .LogDir }}
use_syslog = False

[database]
connection = mysql+pymysql://keystone:{{ .DBPassword }}@{{ .DBHost }}/keystone

[token]
provider = fernet

[cache]
enabled = true
backend = oslo_cache.memcache_pool
memcache_servers = {{ .MemcacheServers }}

[federation]
driver = sql

[identity]
driver = sql

[trust]
driver = sql`

	novaConfTemplate = `[DEFAULT]
my_ip = {{ .ManagementIP }}
use_neutron = True
firewall_driver = nova.virt.firewall.NoopFirewallDriver
log_dir = {{ .LogDir }}
state_path = {{ .StateDir }}
transport_url = rabbit://openstack:{{ .RabbitPassword }}@{{ .RabbitHost }}:5672/

[api]
auth_strategy = keystone

[api_database]
connection = mysql+pymysql://nova:{{ .DBPassword }}@{{ .DBHost }}/nova_api

[database]
connection = mysql+pymysql://nova:{{ .DBPassword }}@{{ .DBHost }}/nova

[keystone_authtoken]
www_authenticate_uri = {{ .KeystonePublicURL }}
auth_url = {{ .KeystoneInternalURL }}
memcached_servers = {{ .MemcacheServers }}
auth_type = password
project_domain_name = Default
user_domain_name = Default
project_name = service
username = nova
password = {{ .ServicePassword }}

[neutron]
auth_url = {{ .KeystoneInternalURL }}
auth_type = password
project_domain_name = Default
user_domain_name = Default
region_name = RegionOne
project_name = service
username = neutron
password = {{ .ServicePassword }}
service_metadata_proxy = true
metadata_proxy_shared_secret = {{ .MetadataSecret }}

[placement]
region_name = RegionOne
project_domain_name = Default
project_name = service
auth_type = password
user_domain_name = Default
auth_url = {{ .KeystoneInternalURL }}
username = placement
password = {{ .ServicePassword }}

[scheduler]
discover_hosts_in_cells_interval = 300

[filter_scheduler]
cpu_allocation_ratio = {{ .CPUAllocationRatio }}
ram_allocation_ratio = {{ .RAMAllocationRatio }}
disk_allocation_ratio = {{ .DiskAllocationRatio }}`

	neutronConfTemplate = `[DEFAULT]
core_plugin = ml2
service_plugins = router
allow_overlapping_ips = true
transport_url = rabbit://openstack:{{ .RabbitPassword }}@{{ .RabbitHost }}:5672/
auth_strategy = keystone
notify_nova_on_port_status_changes = true
notify_nova_on_port_data_changes = true
log_dir = {{ .LogDir }}

[database]
connection = mysql+pymysql://neutron:{{ .DBPassword }}@{{ .DBHost }}/neutron

[keystone_authtoken]
www_authenticate_uri = {{ .KeystonePublicURL }}
auth_url = {{ .KeystoneInternalURL }}
memcached_servers = {{ .MemcacheServers }}
auth_type = password
project_domain_name = Default
user_domain_name = Default
project_name = service
username = neutron
password = {{ .ServicePassword }}

[nova]
auth_url = {{ .KeystoneInternalURL }}
auth_type = password
project_domain_name = Default
user_domain_name = Default
region_name = RegionOne
project_name = service
username = nova
password = {{ .ServicePassword }}

[oslo_concurrency]
lock_path = /var/lib/neutron/tmp`
)

// generateConfiguration creates all necessary configuration files
func generateConfiguration(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Generating OpenStack configuration files")

	// Generate passwords if not provided
	if err := generatePasswords(config); err != nil {
		return fmt.Errorf("failed to generate passwords: %w", err)
	}

	// Generate configuration for each enabled service
	services := config.GetEnabledServices()
	for _, service := range services {
		if err := generateServiceConfig(rc, config, service); err != nil {
			return fmt.Errorf("failed to generate config for %s: %w", service, err)
		}
	}

	// Generate ML2 plugin configuration for Neutron
	if contains(services, ServiceNeutron) {
		if err := generateML2Config(rc, config); err != nil {
			return fmt.Errorf("failed to generate ML2 config: %w", err)
		}
	}

	// Generate Apache configuration for Horizon
	if config.EnableDashboard {
		if err := generateHorizonConfig(rc, config); err != nil {
			return fmt.Errorf("failed to generate Horizon config: %w", err)
		}
	}

	// Generate environment file
	if err := generateEnvironmentFile(rc, config); err != nil {
		return fmt.Errorf("failed to generate environment file: %w", err)
	}

	logger.Info("Configuration generation completed")
	return nil
}

// generateServiceConfig generates configuration for a specific service
func generateServiceConfig(rc *eos_io.RuntimeContext, config *Config, service Service) error {
	logger := otelzap.Ctx(rc.Ctx)

	var configTemplate string
	var configPath string
	templateData := createTemplateData(config)

	switch service {
	case ServiceKeystone:
		configTemplate = keystoneConfTemplate
		configPath = "/etc/keystone/keystone.conf"
	case ServiceNova:
		configTemplate = novaConfTemplate
		configPath = "/etc/nova/nova.conf"
	case ServiceNeutron:
		configTemplate = neutronConfTemplate
		configPath = "/etc/neutron/neutron.conf"
	case ServiceGlance:
		configTemplate = generateGlanceConfig(config)
		configPath = "/etc/glance/glance-api.conf"
	case ServiceCinder:
		configTemplate = generateCinderConfig(config)
		configPath = "/etc/cinder/cinder.conf"
	default:
		logger.Debug("No configuration template for service", zap.String("service", string(service)))
		return nil
	}

	// Parse and execute template
	tmpl, err := template.New(string(service)).Parse(configTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, templateData); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	// Ensure directory exists
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write configuration file
	if err := os.WriteFile(configPath, buf.Bytes(), 0640); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	// Set ownership
	if err := setFileOwnership(configPath, service); err != nil {
		logger.Warn("Failed to set file ownership", zap.Error(err))
	}

	logger.Info("Generated configuration file",
		zap.String("service", string(service)),
		zap.String("path", configPath))

	return nil
}

// generateML2Config generates the ML2 plugin configuration for Neutron
func generateML2Config(rc *eos_io.RuntimeContext, config *Config) error {
	ml2Config := fmt.Sprintf(`[ml2]
type_drivers = flat,vlan,vxlan
tenant_network_types = vxlan
mechanism_drivers = openvswitch,l2population
extension_drivers = port_security

[ml2_type_flat]
flat_networks = %s

[ml2_type_vlan]
network_vlan_ranges = %s:1000:2000

[ml2_type_vxlan]
vni_ranges = 1:1000

[securitygroup]
enable_ipset = true

[ovs]
bridge_mappings = %s:%s
local_ip = %s
`, config.ProviderPhysnet, config.ProviderPhysnet,
		config.ProviderPhysnet, getBridgeName(config.ProviderInterface),
		getLocalIP(rc))

	configPath := "/etc/neutron/plugins/ml2/ml2_conf.ini"
	configDir := filepath.Dir(configPath)

	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create ML2 config directory: %w", err)
	}

	if err := os.WriteFile(configPath, []byte(ml2Config), 0640); err != nil {
		return fmt.Errorf("failed to write ML2 config: %w", err)
	}

	// Create symlink for Neutron
	symlinkPath := "/etc/neutron/plugin.ini"
	_ = os.Remove(symlinkPath) // Remove if exists
	if err := os.Symlink(configPath, symlinkPath); err != nil {
		return fmt.Errorf("failed to create ML2 symlink: %w", err)
	}

	return nil
}

// generateEnvironmentFile creates an environment file with all service endpoints
func generateEnvironmentFile(rc *eos_io.RuntimeContext, config *Config) error {
	envContent := fmt.Sprintf(`# OpenStack Environment Configuration
# Generated by eos

export OS_PROJECT_DOMAIN_NAME=Default
export OS_USER_DOMAIN_NAME=Default
export OS_PROJECT_NAME=admin
export OS_USERNAME=admin
export OS_PASSWORD=%s
export OS_AUTH_URL=%s/v3
export OS_IDENTITY_API_VERSION=3
export OS_IMAGE_API_VERSION=2

# Service Endpoints
export OS_PUBLIC_ENDPOINT=%s
export OS_INTERNAL_ENDPOINT=%s
export OS_ADMIN_ENDPOINT=%s

# Region
export OS_REGION_NAME=RegionOne

# Optional: Disable SSL warnings in dev environments
%s
`, config.AdminPassword, config.InternalEndpoint,
		config.PublicEndpoint, config.InternalEndpoint,
		getAdminEndpoint(config),
		getSSLWarningConfig(config))

	// Write to multiple locations for convenience
	locations := []string{
		"/etc/openstack/admin-openrc.sh",
		filepath.Join(os.Getenv("HOME"), ".openstack-admin-rc"),
	}

	for _, path := range locations {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			continue
		}
		if err := os.WriteFile(path, []byte(envContent), 0600); err != nil {
			otelzap.Ctx(rc.Ctx).Warn("Failed to write environment file",
				zap.String("path", path),
				zap.Error(err))
		}
	}

	return nil
}

// Helper functions

func createTemplateData(config *Config) map[string]interface{} {
	// Build template data from config
	data := map[string]interface{}{
		"AdminToken":          generateToken(),
		"AdminPassword":       config.AdminPassword,
		"ServicePassword":     config.ServicePassword,
		"DBPassword":          config.DBPassword,
		"RabbitPassword":      config.RabbitMQPassword,
		"DBHost":              getDBHost(config),
		"RabbitHost":          getRabbitHost(config),
		"MemcacheServers":     getMemcacheServers(config),
		"KeystonePublicURL":   fmt.Sprintf("%s:5000", config.PublicEndpoint),
		"KeystoneInternalURL": fmt.Sprintf("%s:5000", config.InternalEndpoint),
		"LogDir":              OpenStackLogDir,
		"StateDir":            OpenStackStateDir,
		"ManagementIP":        getManagementIP(config),
		"MetadataSecret":      generateToken(),
		"CPUAllocationRatio":  config.CPUAllocationRatio,
		"RAMAllocationRatio":  config.RAMAllocationRatio,
		"DiskAllocationRatio": config.DiskAllocationRatio,
	}

	return data
}

func generatePasswords(config *Config) error {
	if config.ServicePassword == "" {
		config.ServicePassword = generateSecurePassword()
	}
	if config.DBPassword == "" {
		config.DBPassword = generateSecurePassword()
	}
	if config.RabbitMQPassword == "" {
		config.RabbitMQPassword = generateSecurePassword()
	}
	return nil
}

func generateSecurePassword() string {
	cryptoOps := crypto.NewRandomOperations()
	password, err := cryptoOps.GenerateRandomString(nil, 16, crypto.CharsetAlphaNum)
	if err != nil {
		// Fallback to a simpler method if crypto fails
		return "OpenStack" + fmt.Sprintf("%d", time.Now().Unix())
	}
	return password
}

func generateToken() string {
	cryptoOps := crypto.NewRandomOperations()
	token, err := cryptoOps.GenerateRandomString(nil, 32, crypto.CharsetAlphaNum)
	if err != nil {
		// Fallback to a simpler method if crypto fails
		return "Token" + fmt.Sprintf("%d", time.Now().Unix())
	}
	return token
}

func getDBHost(config *Config) string {
	if config.IsControllerNode() {
		return "localhost"
	}
	return config.ControllerAddress
}

func getRabbitHost(config *Config) string {
	return getDBHost(config)
}

func getMemcacheServers(config *Config) string {
	if config.IsControllerNode() {
		return "localhost:11211"
	}
	return fmt.Sprintf("%s:11211", config.ControllerAddress)
}

func getManagementIP(config *Config) string {
	// In production, this would detect the management network IP
	if config.ManagementNetwork != "" {
		return config.ManagementNetwork
	}
	return "0.0.0.0"
}

func getBridgeName(iface string) string {
	return fmt.Sprintf("br-%s", iface)
}

func getLocalIP(rc *eos_io.RuntimeContext) string {
	// Get the IP address of the management interface
	// This is simplified - production would be more sophisticated
	return "MANAGEMENT_IP"
}

func getAdminEndpoint(config *Config) string {
	if config.AdminEndpoint != "" {
		return config.AdminEndpoint
	}
	return config.InternalEndpoint
}

func getSSLWarningConfig(config *Config) string {
	if !config.EnableSSL {
		return "# export PYTHONWARNINGS=\"ignore:Unverified HTTPS request\""
	}
	return ""
}

func setFileOwnership(path string, service Service) error {
	// Set appropriate ownership based on service
	var user string

	switch service {
	case ServiceKeystone:
		user = "keystone"
	case ServiceGlance:
		user = "glance"
	case ServiceNova:
		user = "nova"
	case ServiceNeutron:
		user = "neutron"
	case ServiceCinder:
		user = "cinder"
	default:
		user = OpenStackUser
	}

	uid, gid, err := eos_unix.LookupUser(nil, user)
	if err != nil {
		return fmt.Errorf("failed to lookup user %s: %w", user, err)
	}
	
	return os.Chown(path, uid, gid)
}

func contains(services []Service, service Service) bool {
	for _, s := range services {
		if s == service {
			return true
		}
	}
	return false
}

// Additional configuration generators for other services
func generateGlanceConfig(config *Config) string {
	return fmt.Sprintf(`[DEFAULT]
bind_host = 0.0.0.0
bind_port = 9292
log_file = %s/glance-api.log
[database]
connection = mysql+pymysql://glance:%s@%s/glance
[keystone_authtoken]
www_authenticate_uri = %s
auth_url = %s
[glance_store]
stores = file,http
default_store = file
filesystem_store_datadir = /var/lib/glance/images/
`, OpenStackLogDir, config.DBPassword, getDBHost(config),
		config.PublicEndpoint+":5000", config.InternalEndpoint+":5000")
}

func generateCinderConfig(config *Config) string {
	return fmt.Sprintf(`[DEFAULT]
transport_url = rabbit://openstack:%s@%s:5672/
auth_strategy = keystone
my_ip = %s
[database]
connection = mysql+pymysql://cinder:%s@%s/cinder
[keystone_authtoken]
www_authenticate_uri = %s
auth_url = %s
`, config.RabbitMQPassword, getRabbitHost(config),
		getManagementIP(config), config.DBPassword, getDBHost(config),
		config.PublicEndpoint+":5000", config.InternalEndpoint+":5000")
}

// generateHorizonConfig generates Horizon dashboard configuration
func generateHorizonConfig(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Generating Horizon dashboard configuration")
	
	// Generate Django settings for Horizon
	horizonSettings := fmt.Sprintf(`import os
from django.utils.translation import ugettext_lazy as _
from openstack_dashboard.settings import HORIZON_CONFIG

DEBUG = False
ALLOWED_HOSTS = ['*']
LOCAL_PATH = os.path.dirname(os.path.abspath(__file__))

SECRET_KEY = '%s'

# Session configuration
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = %t

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.memcached.MemcachedCache',
        'LOCATION': '%s',
    },
}

# Email configuration  
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# OpenStack configuration
OPENSTACK_HOST = "%s"
OPENSTACK_KEYSTONE_URL = "%s:5000/v3"
OPENSTACK_KEYSTONE_DEFAULT_ROLE = "_member_"

# Multi-domain support
OPENSTACK_KEYSTONE_MULTIDOMAIN_SUPPORT = True
OPENSTACK_KEYSTONE_DEFAULT_DOMAIN = "Default"

# API versions
OPENSTACK_API_VERSIONS = {
    "identity": 3,
    "image": 2,
    "volume": 3,
}

# Neutron configuration
OPENSTACK_NEUTRON_NETWORK = {
    'enable_router': True,
    'enable_quotas': True,
    'enable_ipv6': True,
    'enable_distributed_router': False,
    'enable_ha_router': True,
    'enable_fip_topology_check': True,
}

# Security
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
USE_X_FORWARDED_HOST = True

# Timezone
TIME_ZONE = "UTC"
`, generateToken(), config.EnableSSL, getMemcacheServers(config), 
   getControllerIP(config), config.InternalEndpoint)
	
	// Write the configuration
	horizonConfigPath := "/etc/openstack-dashboard/local_settings.py"
	if err := os.WriteFile(horizonConfigPath, []byte(horizonSettings), 0640); err != nil {
		return fmt.Errorf("failed to write Horizon config: %w", err)
	}
	
	// Set ownership
	uid, gid, err := eos_unix.LookupUser(rc.Ctx, "horizon")
	if err != nil {
		// Try www-data as fallback
		uid, gid, err = eos_unix.LookupUser(rc.Ctx, "www-data")
		if err != nil {
			logger.Warn("Could not find horizon or www-data user", zap.Error(err))
			return nil
		}
	}
	
	if err := os.Chown(horizonConfigPath, uid, gid); err != nil {
		logger.Warn("Failed to set ownership on Horizon config", zap.Error(err))
	}
	
	return nil
}
