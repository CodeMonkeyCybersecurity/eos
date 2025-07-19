// pkg/nomad/install.go

package nomad

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CheckPrerequisites verifies that all prerequisites are met for Nomad installation
func CheckPrerequisites(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking Nomad installation prerequisites")
	
	// ASSESS - Check if this function can execute
	// Check if we have permission to run system checks
	if _, err := exec.LookPath("systemctl"); err != nil {
		return eos_err.NewUserError("systemctl not found - this command requires systemd")
	}
	
	// Check if we have root permissions
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("Nomad installation requires root privileges, please run with sudo")
	}
	
	// ASSESS - Check if we're on Ubuntu
	ubuntuRelease, err := platform.DetectUbuntuRelease(rc)
	if err != nil {
		return fmt.Errorf("Nomad installation via SaltStack is only supported on Ubuntu: %w", err)
	}
	logger.Debug("Detected Ubuntu release", zap.String("version", ubuntuRelease.Version))
	
	// Check if SaltStack is installed
	saltInstalled := false
	if _, err := exec.LookPath("salt-call"); err == nil {
		// Verify it's working
		_, err = execute.Run(rc.Ctx, execute.Options{
			Command: "salt-call",
			Args:    []string{"--version"},
			Capture: true,
			Timeout: 5 * time.Second,
		})
		saltInstalled = err == nil
	}
	
	if !saltInstalled {
		logger.Info("SaltStack is not installed, installing it first")
		
		// Install SaltStack using the existing installer
		saltInstaller := saltstack.NewInstaller()
		saltConfig := &saltstack.Config{
			MasterMode: false, // Install as masterless
			LogLevel:   "warning",
		}
		
		if err := saltInstaller.Install(rc, saltConfig); err != nil {
			return fmt.Errorf("failed to install SaltStack: %w", err)
		}
		
		if err := saltInstaller.Configure(rc, saltConfig); err != nil {
			return fmt.Errorf("failed to configure SaltStack: %w", err)
		}
		
		if err := saltInstaller.Verify(rc); err != nil {
			return fmt.Errorf("failed to verify SaltStack installation: %w", err)
		}
		
		logger.Info("SaltStack installed successfully")
	}
	
	// Check if Consul is running (required for Nomad integration)
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "consul"},
		Capture: true,
	})
	if err != nil {
		logger.Warn("Consul service is not running - Nomad will work but without service discovery")
	}
	
	// Check if Vault is running (required for secrets integration)
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "vault"},
		Capture: true,
	})
	if err != nil {
		logger.Warn("Vault service is not running - Nomad will work but without secrets integration")
	}
	
	// Check if Docker is available for the Docker driver
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"--version"},
		Capture: true,
	})
	if err != nil {
		logger.Warn("Docker is not available - Nomad will work but without Docker driver")
	}
	
	// Check available disk space
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "df",
		Args:    []string{"-h", "/"},
		Capture: true,
	})
	if err != nil {
		logger.Warn("Could not check disk space", zap.Error(err))
	} else {
		logger.Debug("Disk space check", zap.String("output", output))
	}
	
	logger.Info("Prerequisites check completed")
	return nil
}

// InstallWithSaltStack installs Nomad using SaltStack
func InstallWithSaltStack(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Nomad using SaltStack")
	
	// ASSESS - Check if we can execute this function
	// Check if we have necessary permissions
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("Nomad installation requires root privileges, please run with sudo")
	}
	
	// Check if salt-call command exists
	if _, err := exec.LookPath("salt-call"); err != nil {
		return eos_err.NewUserError("salt-call not found - SaltStack should have been installed by CheckPrerequisites")
	}
	
	// Check if Salt states directory exists
	statesDir := "/srv/salt"
	if _, err := os.Stat(statesDir); os.IsNotExist(err) {
		logger.Info("Creating Salt states directory")
		if err := os.MkdirAll(statesDir, 0755); err != nil {
			return fmt.Errorf("failed to create Salt states directory: %w", err)
		}
	}
	
	// ASSESS - Check if Nomad is already installed
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"version"},
		Capture: true,
	})
	if err == nil {
		logger.Info("Nomad is already installed, checking version")
		// Could add version comparison logic here
	}
	
	// INTERVENE - Apply SaltStack state for Nomad installation
	logger.Info("Applying SaltStack state for Nomad installation")
	
	// Create pillar data with configuration
	pillarData := fmt.Sprintf(`nomad:
  version: "%s"
  datacenter: "%s"
  region: "%s"
  node_role: "%s"
  enable_ui: %t
  http_port: %d
  rpc_port: %d
  serf_port: %d
  consul_integration: %t
  vault_integration: %t
  consul_address: "%s"
  vault_address: "%s"
  enable_tls: %t
  enable_acl: %t
  enable_gossip: %t
  data_dir: "%s"
  config_dir: "%s"
  log_level: "%s"
  server_bootstrap_expect: %d
  docker_enabled: %t
  exec_enabled: %t
  raw_exec_enabled: %t
  enable_telemetry: %t`,
		config.Version,
		config.Datacenter,
		config.Region,
		config.NodeRole,
		config.EnableUI,
		config.HTTPPort,
		config.RPCPort,
		config.SerfPort,
		config.ConsulIntegration,
		config.VaultIntegration,
		config.ConsulAddress,
		config.VaultAddress,
		config.EnableTLS,
		config.EnableACL,
		config.EnableGossip,
		config.DataDir,
		config.ConfigDir,
		config.LogLevel,
		config.ServerBootstrapExpect,
		config.DockerEnabled,
		config.ExecEnabled,
		config.RawExecEnabled,
		config.EnableTelemetry,
	)
	
	// Write pillar data to temporary file
	pillarFile := "/tmp/nomad-pillar.sls"
	
	// Check if we can write to the pillar file location
	if err := os.WriteFile(pillarFile, []byte(pillarData), 0600); err != nil {
		if os.IsPermission(err) {
			return eos_err.NewUserError("cannot write to /tmp - insufficient permissions")
		}
		return fmt.Errorf("failed to write pillar data: %w", err)
	}
	
	// INTERVENE - Create and apply Salt state for Nomad installation
	logger.Info("Creating Salt state for Nomad installation")
	
	// Create the Nomad Salt state
	if err := createNomadSaltState(rc, config); err != nil {
		return fmt.Errorf("failed to create Nomad Salt state: %w", err)
	}
	
	// Apply the Salt state
	logger.Info("Applying Nomad Salt state")
	
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"--local", "state.apply", "nomad"},
		Capture: true,
		Timeout: 10 * time.Minute, // Give enough time for download and installation
	})
	if err != nil {
		return fmt.Errorf("failed to apply Nomad Salt state: %w", err)
	}
	
	logger.Debug("Salt state execution result", zap.String("output", output))
	
	// EVALUATE - Verify installation immediately
	logger.Info("Verifying Nomad installation")
	
	// Check if Nomad binary exists
	if _, err := exec.LookPath("nomad"); err != nil {
		return fmt.Errorf("Nomad binary not found after installation")
	}
	
	// Check Nomad version
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"version"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to check Nomad version: %w", err)
	}
	logger.Info("Nomad installed", zap.String("version", strings.TrimSpace(output)))
	
	// Check if service is running
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "nomad"},
		Capture: true,
	})
	if err != nil {
		logger.Debug("Nomad service not yet active, will be started during configuration")
	}
	
	// EVALUATE - Verify installation
	logger.Info("Verifying Nomad installation")
	
	// Check if Nomad binary is installed
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"version"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("Nomad binary not found after installation: %w", err)
	}
	
	// Check if Nomad service is active
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "nomad"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("Nomad service is not active: %w", err)
	}
	
	logger.Info("Nomad installation completed successfully")
	return nil
}

// Configure configures Nomad after installation
func Configure(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring Nomad")
	
	// ASSESS - Check if we can execute configuration
	// Check if we have permission to restart services
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("Nomad configuration requires root privileges to restart services, please run with sudo")
	}
	
	// Check if systemctl exists
	if _, err := exec.LookPath("systemctl"); err != nil {
		return eos_err.NewUserError("systemctl not found - Nomad service management requires systemd")
	}
	
	// Check if nomad command exists
	if _, err := exec.LookPath("nomad"); err != nil {
		return eos_err.NewUserError("nomad command not found - please install Nomad first")
	}
	
	// ASSESS - Check if Nomad is running
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "nomad"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("Nomad service is not running: %w", err)
	}
	
	// INTERVENE - Apply configuration
	logger.Info("Applying Nomad configuration")
	
	// If this is a server node, initialize ACL system
	if config.NodeRole == NodeRoleServer || config.NodeRole == NodeRoleBoth {
		if config.EnableACL {
			logger.Info("Initializing ACL system")
			
			// Check if ACL is already bootstrapped
			_, err := execute.Run(rc.Ctx, execute.Options{
				Command: "nomad",
				Args:    []string{"acl", "bootstrap"},
				Capture: true,
			})
			if err != nil {
				logger.Debug("ACL bootstrap failed (may already be initialized)", zap.Error(err))
			} else {
				logger.Info("ACL system bootstrapped successfully")
			}
		}
	}
	
	// Restart Nomad service to apply configuration
	logger.Info("Restarting Nomad service")
	
	// Double-check we have permission to restart services
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("cannot restart services without root privileges")
	}
	
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"restart", "nomad"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("failed to restart Nomad service: %w", err)
	}
	
	// Wait for service to be ready
	logger.Info("Waiting for Nomad service to be ready")
	maxRetries := 30
	for i := 0; i < maxRetries; i++ {
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "systemctl",
			Args:    []string{"is-active", "nomad"},
			Capture: true,
		})
		if err == nil {
			break
		}
		
		if i == maxRetries-1 {
			return fmt.Errorf("Nomad service did not become active after restart")
		}
		
		logger.Debug("Waiting for Nomad service to be active", zap.Int("attempt", i+1))
		time.Sleep(2 * time.Second)
	}
	
	logger.Info("Nomad configuration completed successfully")
	return nil
}

// Verify verifies that Nomad is properly installed and configured
func Verify(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying Nomad installation")
	
	// ASSESS - Check if we can perform verification
	// Check if systemctl exists for service checks
	if _, err := exec.LookPath("systemctl"); err != nil {
		return eos_err.NewUserError("systemctl not found - cannot verify service status")
	}
	
	// Check if nomad command exists
	if _, err := exec.LookPath("nomad"); err != nil {
		return eos_err.NewUserError("nomad command not found - Nomad is not installed")
	}
	
	// Check if curl exists for API checks
	if _, err := exec.LookPath("curl"); err != nil {
		logger.Warn("curl not found - skipping API endpoint verification")
	}
	
	// ASSESS - Check service status
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"status", "nomad"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("Nomad service is not running: %w", err)
	}
	logger.Debug("Service status", zap.String("output", output))
	
	// Check Nomad version
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"version"},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("Nomad version check failed: %w", err)
	}
	logger.Info("Nomad version", zap.String("version", output))
	
	// Check if server is running (if configured as server)
	if config.NodeRole == NodeRoleServer || config.NodeRole == NodeRoleBoth {
		output, err = execute.Run(rc.Ctx, execute.Options{
			Command: "nomad",
			Args:    []string{"server", "members"},
			Capture: true,
		})
		if err != nil {
			return fmt.Errorf("Nomad server members check failed: %w", err)
		}
		logger.Debug("Server members", zap.String("output", output))
	}
	
	// Check if client is running (if configured as client)
	if config.NodeRole == NodeRoleClient || config.NodeRole == NodeRoleBoth {
		output, err = execute.Run(rc.Ctx, execute.Options{
			Command: "nomad",
			Args:    []string{"node", "status"},
			Capture: true,
		})
		if err != nil {
			return fmt.Errorf("Nomad node status check failed: %w", err)
		}
		logger.Debug("Node status", zap.String("output", output))
	}
	
	// Check if UI is accessible (if enabled)
	if config.EnableUI {
		_, err = execute.Run(rc.Ctx, execute.Options{
			Command: "curl",
			Args:    []string{"-f", "-s", fmt.Sprintf("http://localhost:%d/ui/", config.HTTPPort)},
			Capture: true,
		})
		if err != nil {
			logger.Warn("Nomad UI is not accessible", zap.Error(err))
		} else {
			logger.Info("Nomad UI is accessible")
		}
	}
	
	// Check API endpoint
	_, err = execute.Run(rc.Ctx, execute.Options{
		Command: "curl",
		Args:    []string{"-f", "-s", fmt.Sprintf("http://localhost:%d/v1/status/leader", config.HTTPPort)},
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("Nomad API is not accessible: %w", err)
	}
	
	logger.Info("Nomad verification completed successfully")
	return nil
}

// createNomadSaltState creates the Salt state files for Nomad installation
func createNomadSaltState(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating Nomad Salt state files")
	
	// ASSESS - Check if we can create Salt state files
	// Check if we have permission to write to Salt states directory
	statesDir := "/srv/salt"
	if _, err := os.Stat(statesDir); os.IsNotExist(err) {
		if err := os.MkdirAll(statesDir, 0755); err != nil {
			if os.IsPermission(err) {
				return eos_err.NewUserError("cannot create Salt states directory - insufficient permissions")
			}
			return fmt.Errorf("failed to create Salt states directory: %w", err)
		}
	}
	
	// INTERVENE - Create the Salt state file
	stateContent := `# Nomad installation state
nomad_prereqs:
  pkg.installed:
    - pkgs:
      - curl
      - unzip
      - gnupg

nomad_download:
  cmd.run:
    - name: |
        NOMAD_VERSION="{{ salt['pillar.get']('nomad:version', 'latest') }}"
        if [ "$NOMAD_VERSION" = "latest" ]; then
          NOMAD_VERSION=$(curl -s https://api.github.com/repos/hashicorp/nomad/releases/latest | grep -oP '"tag_name": "\K(.*)(?=")')
          NOMAD_VERSION=${NOMAD_VERSION#v}
        fi
        curl -sLo /tmp/nomad.zip https://releases.hashicorp.com/nomad/${NOMAD_VERSION}/nomad_${NOMAD_VERSION}_linux_amd64.zip
        unzip -o /tmp/nomad.zip -d /usr/local/bin
        chmod +x /usr/local/bin/nomad
        rm -f /tmp/nomad.zip
    - unless: test -f /usr/local/bin/nomad
    - require:
      - pkg: nomad_prereqs

nomad_directories:
  file.directory:
    - names:
      - {{ salt['pillar.get']('nomad:data_dir', '/var/lib/nomad') }}
      - {{ salt['pillar.get']('nomad:config_dir', '/etc/nomad') }}
      - /etc/nomad/certs
    - makedirs: True
    - mode: 755

nomad_config:
  file.managed:
    - name: /etc/nomad/nomad.hcl
    - contents: |
        datacenter = "{{ salt['pillar.get']('nomad:datacenter', 'dc1') }}"
        region = "{{ salt['pillar.get']('nomad:region', 'global') }}"
        data_dir = "{{ salt['pillar.get']('nomad:data_dir', '/var/lib/nomad') }}"
        log_level = "{{ salt['pillar.get']('nomad:log_level', 'INFO') }}"
        
        bind_addr = "0.0.0.0"
        
        advertise {
          http = "{{ salt['grains.get']('ipv4')[0] }}"
          rpc = "{{ salt['grains.get']('ipv4')[0] }}"
          serf = "{{ salt['grains.get']('ipv4')[0] }}"
        }
        
        ports {
          http = {{ salt['pillar.get']('nomad:http_port', 4646) }}
          rpc = {{ salt['pillar.get']('nomad:rpc_port', 4647) }}
          serf = {{ salt['pillar.get']('nomad:serf_port', 4648) }}
        }
        
        {%- if salt['pillar.get']('nomad:node_role') in ['server', 'both'] %}
        server {
          enabled = true
          bootstrap_expect = {{ salt['pillar.get']('nomad:server_bootstrap_expect', 1) }}
          
          {%- if salt['pillar.get']('nomad:enable_gossip', false) %}
          encrypt = "{{ salt['pillar.get']('nomad:gossip_key', '') }}"
          {%- endif %}
        }
        {%- endif %}
        
        {%- if salt['pillar.get']('nomad:node_role') in ['client', 'both'] %}
        client {
          enabled = true
          
          options {
            "driver.raw_exec.enable" = "{{ salt['pillar.get']('nomad:raw_exec_enabled', false)|lower }}"
            "docker.volumes.enabled" = "true"
          }
        }
        {%- endif %}
        
        {%- if salt['pillar.get']('nomad:enable_ui', true) %}
        ui {
          enabled = true
        }
        {%- endif %}
        
        {%- if salt['pillar.get']('nomad:enable_acl', false) %}
        acl {
          enabled = true
        }
        {%- endif %}
        
        {%- if salt['pillar.get']('nomad:consul_integration', true) %}
        consul {
          address = "{{ salt['pillar.get']('nomad:consul_address', '127.0.0.1:8500') }}"
        }
        {%- endif %}
        
        {%- if salt['pillar.get']('nomad:vault_integration', true) %}
        vault {
          enabled = true
          address = "{{ salt['pillar.get']('nomad:vault_address', 'http://127.0.0.1:8200') }}"
        }
        {%- endif %}
        
        {%- if salt['pillar.get']('nomad:enable_telemetry', false) %}
        telemetry {
          collection_interval = "1s"
          disable_hostname = true
          publish_allocation_metrics = true
          publish_node_metrics = true
          prometheus_metrics = true
        }
        {%- endif %}
        
        {%- if salt['pillar.get']('nomad:docker_enabled', true) %}
        plugin "docker" {
          config {
            volumes {
              enabled = true
            }
          }
        }
        {%- endif %}
        
        {%- if salt['pillar.get']('nomad:exec_enabled', true) %}
        plugin "exec" {
          config {
            allowed = true
          }
        }
        {%- endif %}
    - require:
      - file: nomad_directories

nomad_systemd_service:
  file.managed:
    - name: /etc/systemd/system/nomad.service
    - contents: |
        [Unit]
        Description=Nomad
        Documentation=https://www.nomadproject.io/docs/
        Wants=network-online.target
        After=network-online.target
        {%- if salt['pillar.get']('nomad:consul_integration', true) %}
        Wants=consul.service
        After=consul.service
        {%- endif %}
        
        [Service]
        Type=notify
        ExecStart=/usr/local/bin/nomad agent -config={{ salt['pillar.get']('nomad:config_dir', '/etc/nomad') }}
        ExecReload=/bin/kill -HUP $MAINPID
        KillMode=process
        Restart=on-failure
        LimitNOFILE=65536
        LimitNPROC=infinity
        TasksMax=infinity
        OOMScoreAdjust=-1000
        
        [Install]
        WantedBy=multi-user.target

nomad_service:
  service.running:
    - name: nomad
    - enable: True
    - watch:
      - file: nomad_config
      - file: nomad_systemd_service
    - require:
      - cmd: nomad_download
      - file: nomad_config
      - file: nomad_systemd_service
`
	
	// Write the state file
	stateFile := "/srv/salt/nomad.sls"
	if err := os.WriteFile(stateFile, []byte(stateContent), 0644); err != nil {
		if os.IsPermission(err) {
			return eos_err.NewUserError("cannot write Salt state file - insufficient permissions")
		}
		return fmt.Errorf("failed to write Nomad Salt state: %w", err)
	}
	
	// EVALUATE - Verify the state file was created
	if _, err := os.Stat(stateFile); os.IsNotExist(err) {
		return fmt.Errorf("Salt state file was not created successfully")
	}
	
	logger.Info("Nomad Salt state created successfully")
	return nil
}