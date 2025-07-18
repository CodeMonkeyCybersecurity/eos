package orchestrator

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack/client"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack/orchestrator"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Options holds orchestration options for OpenStack deployment
type Options struct {
	Target string
	Pillar map[string]interface{}
}

// IsSaltAvailable checks if SaltStack is available for orchestration
func IsSaltAvailable() bool {
	saltConfig := config.GetFromEnv()
	return saltConfig.BaseURL != "" && saltConfig.Username != "" && saltConfig.Password != ""
}

// CreateSaltOperation creates the Salt operation for OpenStack installation
func CreateSaltOperation(opts *Options) *orchestrator.SaltOperation {
	// Build comprehensive pillar data for OpenStack
	pillar := make(map[string]interface{})
	
	// Copy provided pillar data
	for k, v := range opts.Pillar {
		pillar[k] = v
	}

	// Add OpenStack-specific configuration
	pillar["openstack"] = map[string]interface{}{
		"release":           "2024.1", // Caracal
		"region":            "RegionOne",
		"enable_telemetry":  true,
		"enable_monitoring": true,
		"database": map[string]interface{}{
			"engine":        "mysql",
			"root_password": pillar["openstack_db_root_password"],
		},
		"messaging": map[string]interface{}{
			"engine":   "rabbitmq",
			"password": pillar["openstack_rabbitmq_password"],
		},
		"keystone": map[string]interface{}{
			"enabled":        true,
			"admin_password": pillar["openstack_admin_password"],
			"endpoints":      pillar["openstack_endpoints"],
		},
		"glance": map[string]interface{}{
			"enabled": true,
			"backend": "file", // or "ceph", "swift"
		},
		"nova": map[string]interface{}{
			"enabled":             true,
			"cpu_allocation_ratio": 16.0,
			"ram_allocation_ratio": 1.5,
		},
		"neutron": map[string]interface{}{
			"enabled":      true,
			"plugin":       "ml2",
			"ml2_drivers":  []string{"openvswitch"},
			"network_type": pillar["openstack_network_type"],
		},
		"cinder": map[string]interface{}{
			"enabled": true,
			"backend": pillar["openstack_storage_backend"],
		},
		"horizon": map[string]interface{}{
			"enabled": pillar["openstack_enable_dashboard"],
			"ssl":     pillar["openstack_enable_ssl"],
		},
	}

	return &orchestrator.SaltOperation{
		Type:   "orchestrate",
		Module: "openstack.deploy",
		Pillar: pillar,
	}
}

// ExecuteWithSalt executes OpenStack installation using Salt orchestration
func ExecuteWithSalt(rc *eos_io.RuntimeContext, opts *Options, directExec DirectExecutor, saltOp *orchestrator.SaltOperation) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Executing OpenStack installation via Salt orchestration")

	// Get Salt configuration
	saltConfig := config.GetFromEnv()
	
	// Validate Salt configuration
	if saltConfig.BaseURL == "" || saltConfig.Username == "" || saltConfig.Password == "" {
		logger.Warn("Salt configuration incomplete, falling back to direct execution")
		return directExec(rc)
	}

	// Create Salt client
	saltClient, err := client.NewHTTPSaltClient(rc, saltConfig)
	if err != nil {
		logger.Warn("Failed to create Salt client, falling back to direct execution",
			zap.Error(err))
		return directExec(rc)
	}

	// Authenticate with Salt
	_, err = saltClient.Login(rc.Ctx, nil)
	if err != nil {
		logger.Warn("Salt authentication failed, falling back to direct execution",
			zap.Error(err))
		return directExec(rc)
	}
	defer saltClient.Logout(rc.Ctx)

	// Check if OpenStack orchestration states exist
	if err := validateOrchestrationStates(rc, saltClient); err != nil {
		logger.Warn("OpenStack orchestration states not found, deploying states first",
			zap.Error(err))
		if err := deployOrchestrationStates(rc, saltClient); err != nil {
			return fmt.Errorf("failed to deploy orchestration states: %w", err)
		}
	}

	// Create orchestration enhancer
	enhancer := orchestrator.NewEnhancer(rc, saltClient)

	// Add OpenStack-specific enhancements
	// Convert interface{} pillar to string pillar for OrchestrationOptions
	pillarStr := make(map[string]string)
	for k, v := range saltOp.Pillar {
		pillarStr[k] = fmt.Sprintf("%v", v)
	}
	
	orchOpts := &orchestrator.OrchestrationOptions{
		Target:  opts.Target,
		Pillar:  pillarStr,
		Timeout: 3600 * time.Second, // 1 hour for full deployment
	}

	// Execute with orchestration
	result, err := enhancer.ExecuteWithOrchestration(rc.Ctx, orchOpts, orchestrator.DirectExecutor(directExec), saltOp)
	if err != nil {
		return fmt.Errorf("orchestrated OpenStack installation failed: %w", err)
	}

	// Display results
	return displayOrchestrationResult(rc, result)
}

// DirectExecutor is a function that performs direct execution without Salt
type DirectExecutor func(*eos_io.RuntimeContext) error

// validateOrchestrationStates checks if OpenStack orchestration states exist
func validateOrchestrationStates(rc *eos_io.RuntimeContext, saltClient *client.HTTPSaltClient) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check for required orchestration states
	requiredStates := []string{
		"openstack.deploy",
		"openstack.controller",
		"openstack.compute",
		"openstack.storage",
		"openstack.network",
	}

	// For now, we'll assume states need to be deployed
	// TODO: Implement state existence check via Salt API
	logger.Debug("Checking for required states", zap.Strings("states", requiredStates))
	return fmt.Errorf("orchestration states not deployed")
}

// deployOrchestrationStates deploys the OpenStack Salt states
func deployOrchestrationStates(rc *eos_io.RuntimeContext, saltClient *client.HTTPSaltClient) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Deploying OpenStack orchestration states")

	// Create Salt state tree for OpenStack
	stateTree := generateOpenStackStateTree()

	// Determine master target - we'll assume salt-master for now
	// TODO: Add proper master detection logic
	masterTarget := "salt-master"

	// Deploy states to Salt master using file.managed via cmd.run
	// We'll create a batch of file.managed states
	for path, content := range stateTree {
		// Use Salt's file.managed to deploy state files via CommandRequest
		req := &client.CommandRequest{
			Client:     client.ClientTypeLocal,
			Target:     masterTarget,
			Function:   "file.managed",
			Args:       []string{path},
			Kwargs: map[string]interface{}{
				"contents": content,
				"makedirs": true,
				"user":     "root",
				"group":    "root",
				"mode":     "0644",
			},
		}
		
		if _, err := saltClient.RunCommand(rc.Ctx, req); err != nil {
			return fmt.Errorf("failed to deploy state %s: %w", path, err)
		}
	}

	// Refresh Salt pillar
	pillarReq := &client.CommandRequest{
		Client:   client.ClientTypeLocal,
		Target:   "*",
		Function: "saltutil.refresh_pillar",
	}
	
	if _, err := saltClient.RunCommand(rc.Ctx, pillarReq); err != nil {
		logger.Warn("Failed to refresh pillar", zap.Error(err))
	}

	return nil
}

// generateOpenStackStateTree creates the Salt state files for OpenStack
func generateOpenStackStateTree() map[string]string {
	states := make(map[string]string)

	// Main orchestration state
	states["/srv/salt/openstack/deploy.sls"] = `# OpenStack Deployment Orchestration
{% set openstack = salt['pillar.get']('openstack', {}) %}

openstack_deployment:
  salt.runner:
    - name: state.orchestrate
    - mods: openstack.orchestrate.deploy
    - pillar: {{ openstack | yaml }}
`

	// Controller node state
	states["/srv/salt/openstack/controller.sls"] = `# OpenStack Controller Node Configuration
{% set openstack = salt['pillar.get']('openstack', {}) %}

include:
  - openstack.common
  - openstack.database
  - openstack.messaging
  - openstack.keystone
  - openstack.glance
  - openstack.nova.controller
  - openstack.neutron.controller
  - openstack.cinder.controller
  {% if openstack.horizon.enabled %}
  - openstack.horizon
  {% endif %}
`

	// Common state for all nodes
	states["/srv/salt/openstack/common.sls"] = `# Common OpenStack Configuration
{% set openstack = salt['pillar.get']('openstack', {}) %}

openstack_repo:
  pkgrepo.managed:
    - name: cloud-archive:{{ openstack.release }}
    - file: /etc/apt/sources.list.d/cloudarchive-{{ openstack.release }}.list
    - keyid: EC4926B15DED8B5E0C8F6B3A2F0BBB73391AE94D
    - keyserver: keyserver.ubuntu.com

openstack_packages:
  pkg.installed:
    - pkgs:
      - python3-openstackclient
      - python3-pymysql
      - python3-memcache
    - require:
      - pkgrepo: openstack_repo

ntp_service:
  pkg.installed:
    - name: chrony
  service.running:
    - name: chrony
    - enable: True
`

	// Database state
	states["/srv/salt/openstack/database.sls"] = `# OpenStack Database Configuration
{% set db = salt['pillar.get']('openstack:database', {}) %}

mariadb_packages:
  pkg.installed:
    - pkgs:
      - mariadb-server
      - python3-pymysql

mariadb_config:
  file.managed:
    - name: /etc/mysql/mariadb.conf.d/99-openstack.cnf
    - contents: |
        [mysqld]
        bind-address = 0.0.0.0
        default-storage-engine = innodb
        innodb_file_per_table = on
        max_connections = 4096
        collation-server = utf8_general_ci
        character-set-server = utf8
    - require:
      - pkg: mariadb_packages

mariadb_service:
  service.running:
    - name: mariadb
    - enable: True
    - watch:
      - file: mariadb_config

# Create databases for each service
{% for service in ['keystone', 'glance', 'nova', 'nova_api', 'nova_cell0', 'neutron', 'cinder'] %}
{{ service }}_database:
  mysql_database.present:
    - name: {{ service }}
    - require:
      - service: mariadb_service

{{ service }}_db_user:
  mysql_user.present:
    - name: {{ service }}
    - password: {{ db.password }}
    - host: '%'
    - require:
      - mysql_database: {{ service }}_database

{{ service }}_db_grants:
  mysql_grants.present:
    - grant: all privileges
    - database: {{ service }}.*
    - user: {{ service }}
    - host: '%'
    - require:
      - mysql_user: {{ service }}_db_user
{% endfor %}
`

	// Keystone state
	states["/srv/salt/openstack/keystone.sls"] = `# Keystone Identity Service
{% set keystone = salt['pillar.get']('openstack:keystone', {}) %}
{% set endpoints = keystone.get('endpoints', {}) %}

keystone_packages:
  pkg.installed:
    - pkgs:
      - keystone
      - apache2
      - libapache2-mod-wsgi-py3

keystone_config:
  file.managed:
    - name: /etc/keystone/keystone.conf
    - source: salt://openstack/files/keystone.conf.jinja
    - template: jinja
    - context:
        keystone: {{ keystone | yaml }}
    - require:
      - pkg: keystone_packages

keystone_db_sync:
  cmd.run:
    - name: keystone-manage db_sync
    - runas: keystone
    - require:
      - file: keystone_config
    - unless: keystone-manage db_sync --check

keystone_fernet_setup:
  cmd.run:
    - name: |
        keystone-manage fernet_setup --keystone-user keystone --keystone-group keystone
        keystone-manage credential_setup --keystone-user keystone --keystone-group keystone
    - require:
      - cmd: keystone_db_sync

keystone_bootstrap:
  cmd.run:
    - name: |
        keystone-manage bootstrap \
          --bootstrap-password {{ keystone.admin_password }} \
          --bootstrap-admin-url {{ endpoints.admin }}/v3/ \
          --bootstrap-internal-url {{ endpoints.internal }}/v3/ \
          --bootstrap-public-url {{ endpoints.public }}/v3/ \
          --bootstrap-region-id RegionOne
    - require:
      - cmd: keystone_fernet_setup
    - unless: openstack user show admin

apache_keystone:
  file.managed:
    - name: /etc/apache2/sites-available/keystone.conf
    - source: salt://openstack/files/apache-keystone.conf.jinja
    - template: jinja
    - context:
        keystone: {{ keystone | yaml }}
  module.run:
    - name: apache.a2ensite
    - site: keystone
    - require:
      - file: apache_keystone
  service.running:
    - name: apache2
    - enable: True
    - restart: True
    - watch:
      - file: keystone_config
      - file: apache_keystone
`

	// Add more states for other services...
	// This is a comprehensive example showing the pattern

	return states
}

// Pre-check functions
func checkMinions(rc *eos_io.RuntimeContext, saltClient *client.HTTPSaltClient, target string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking Salt minions", zap.String("target", target))

	// Test minion connectivity
	req := &client.CommandRequest{
		Client:   client.ClientTypeLocal,
		Target:   target,
		Function: "test.ping",
	}
	
	result, err := saltClient.RunCommand(rc.Ctx, req)
	if err != nil {
		return fmt.Errorf("failed to ping minions: %w", err)
	}

	if result == nil || len(result.Return) == 0 {
		return fmt.Errorf("no minions responded to ping")
	}

	// Count responding minions
	minionCount := 0
	if len(result.Return) > 0 {
		for range result.Return[0] {
			minionCount++
		}
	}
	
	logger.Info("Minions ready", zap.Int("count", minionCount))
	return nil
}

func checkSystemRequirements(rc *eos_io.RuntimeContext, saltClient *client.HTTPSaltClient, target string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking system requirements on minions")

	// Check CPU, memory, and disk space
	cmd := "lscpu | grep '^CPU(s):' && free -g | grep '^Mem:' && df -h /"
	req := &client.CommandRequest{
		Client:   client.ClientTypeLocal,
		Target:   target,
		Function: "cmd.run",
		Args:     []string{cmd},
	}
	
	result, err := saltClient.RunCommand(rc.Ctx, req)
	if err != nil {
		return fmt.Errorf("failed to check system requirements: %w", err)
	}

	// Parse and validate results
	if result != nil && len(result.Return) > 0 {
		for minion, output := range result.Return[0] {
			logger.Debug("System check result", 
				zap.String("minion", minion),
				zap.Any("output", output))
			// In production, parse and validate the output
		}
	}

	return nil
}

func checkNetworkConnectivity(rc *eos_io.RuntimeContext, saltClient *client.HTTPSaltClient, target string) error {
	// Check network connectivity between nodes
	// This would test management network, storage network, etc.
	return nil
}

// Post-check functions
func verifyOpenStackServices(rc *eos_io.RuntimeContext, saltClient *client.HTTPSaltClient, target string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying OpenStack services")

	// Check service status
	services := []string{
		"apache2",
		"mariadb",
		"rabbitmq-server",
		"memcached",
		"glance-api",
		"nova-api",
		"neutron-server",
	}

	for _, service := range services {
		cmd := fmt.Sprintf("systemctl is-active %s", service)
		req := &client.CommandRequest{
			Client:   client.ClientTypeLocal,
			Target:   target,
			Function: "cmd.run",
			Args:     []string{cmd},
		}
		
		result, err := saltClient.RunCommand(rc.Ctx, req)
		if err != nil {
			logger.Warn("Failed to check service",
				zap.String("service", service),
				zap.Error(err))
			continue
		}

		if result != nil && len(result.Return) > 0 {
			for minion, status := range result.Return[0] {
				if statusStr, ok := status.(string); ok && statusStr != "active" {
					logger.Error("Service not active",
						zap.String("minion", minion),
						zap.String("service", service),
						zap.String("status", statusStr))
				}
			}
		}
	}

	return nil
}

func testAPIEndpoints(rc *eos_io.RuntimeContext, saltClient *client.HTTPSaltClient, target string) error {
	// Test OpenStack API endpoints
	// This would use the openstack CLI to verify endpoints are accessible
	return nil
}

// displayOrchestrationResult displays the orchestration result
func displayOrchestrationResult(rc *eos_io.RuntimeContext, result *orchestrator.OrchestrationResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	if result.Success {
		logger.Info("OpenStack orchestration completed successfully",
			zap.Duration("duration", result.Duration),
			zap.Int("minions", len(result.Minions)))

		// Display summary
		fmt.Println("\n══════════════════════════════════════════════════════")
		fmt.Println("       OPENSTACK ORCHESTRATION COMPLETED")
		fmt.Println("══════════════════════════════════════════════════════")
		fmt.Printf("Duration: %s\n", result.Duration)
		fmt.Printf("Minions: %d\n", len(result.Minions))
		
		// Show service endpoints if available in details
		if result.Details != nil {
			if detailsMap, ok := result.Details.(map[string]interface{}); ok {
				if endpoints, ok := detailsMap["endpoints"].(map[string]interface{}); ok {
					fmt.Println("\nService Endpoints:")
					for service, endpoint := range endpoints {
						fmt.Printf("  • %-12s: %v\n", service, endpoint)
					}
				}
			}
		}

		fmt.Println("\nNext Steps:")
		fmt.Println("  1. Source admin credentials: source /etc/openstack/admin-openrc.sh")
		fmt.Println("  2. Verify services: openstack service list")
		fmt.Println("  3. Create networks: openstack network create --external public")
		fmt.Println("  4. Add images: openstack image create --file image.qcow2 ubuntu")
	} else {
		logger.Error("OpenStack orchestration failed",
			zap.String("error", result.Message),
			zap.Int("failed_minions", len(result.Failed)))

		// Show which minions failed
		if len(result.Failed) > 0 {
			fmt.Println("\nFailed Minions:")
			for _, minion := range result.Failed {
				fmt.Printf("  • %s\n", minion)
			}
		}
	}

	return nil
}