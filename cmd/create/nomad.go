// cmd/create/nomad.go

package create

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hashicorp"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/nomad"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var CreateNomadCmd = &cobra.Command{
	Use:   "nomad",
	Short: "Install and configure HashiCorp Nomad using native installer",
	Long: `Install HashiCorp Nomad for workload orchestration using the native installer.

This installer provides:
- Server and/or client mode configuration
- Docker integration for containers
- Consul service discovery integration
- Vault secrets integration
- Automatic cluster bootstrapping

Examples:
  eos create nomad                              # Install as both server and client
  eos create nomad --server-only                # Server only
  eos create nomad --client-only --docker       # Client with Docker
  eos create nomad --consul --vault             # With integrations`,
	RunE: eos.Wrap(runCreateNomadNative),
}

var (
	nomadServerMode     bool
	nomadClientMode     bool
	nomadBootstrapExpect int
	nomadDatacenter     string
	nomadRegion         string
	nomadBindAddr       string
	nomadAdvertiseAddr  string
	nomadLogLevel       string
	nomadEnableACL      bool
	nomadForce          bool
	nomadClean          bool
	nomadJoinAddrs      []string
	nomadClientServers  []string
	nomadEnableDocker   bool
	nomadEnableRaw      bool
)

// NomadStatus represents the current state of Nomad installation
type NomadStatus struct {
	Installed       bool
	Running         bool
	Failed          bool
	ConfigValid     bool
	Version         string
	ServiceStatus   string
	ServerMode      bool
	ClientMode      bool
	ClusterLeader   string
	ClusterMembers  []string
	JobCount        int
	LastError       string
}

func checkNomadStatus(rc *eos_io.RuntimeContext) (*NomadStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)
	status := &NomadStatus{}

	// Check if Nomad binary exists
	if nomadPath, err := exec.LookPath("nomad"); err == nil {
		status.Installed = true
		logger.Debug("Nomad binary found", zap.String("path", nomadPath))
		
		// Get version
		if output, err := exec.Command("nomad", "version").Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			if len(lines) > 0 {
				status.Version = strings.TrimSpace(lines[0])
			}
		}
	}

	// Check service status
	if output, err := exec.Command("systemctl", "is-active", "nomad").Output(); err == nil {
		status.ServiceStatus = strings.TrimSpace(string(output))
		status.Running = (status.ServiceStatus == "active")
	} else {
		// Check if service is in failed state
		if exec.Command("systemctl", "is-failed", "nomad").Run() == nil {
			status.Failed = true
			status.ServiceStatus = "failed"
		}
	}

	// Check configuration validity
	if status.Installed {
		configPath := "/etc/nomad.d/nomad.hcl"
		if _, err := os.Stat(configPath); err == nil {
			if err := exec.Command("nomad", "config", "validate", configPath).Run(); err == nil {
				status.ConfigValid = true
			}
		}
	}

	// Check server/client mode and cluster status if running
	if status.Running {
		// Check agent info
		if output, err := exec.Command("nomad", "agent-info").Output(); err == nil {
			outputStr := string(output)
			status.ServerMode = strings.Contains(outputStr, "server = true")
			status.ClientMode = strings.Contains(outputStr, "client = true") || !status.ServerMode
		}

		// Get server members (for server mode)
		if status.ServerMode {
			if output, err := exec.Command("nomad", "server", "members").Output(); err == nil {
				lines := strings.Split(string(output), "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "Name") {
						status.ClusterMembers = append(status.ClusterMembers, line)
						// Extract leader info
						if strings.Contains(line, "leader=true") {
							parts := strings.Fields(line)
							if len(parts) > 0 {
								status.ClusterLeader = parts[0]
							}
						}
					}
				}
			}
		}

		// Get job count
		if output, err := exec.Command("nomad", "job", "status", "-short").Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			// Subtract header line and empty lines
			for _, line := range lines {
				if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "ID") {
					status.JobCount++
				}
			}
		}
	}

	return status, nil
}

func runCreateNomadNative(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Nomad using native installer")

	// Parse flags
	serverOnly := nomadServerMode && !nomadClientMode
	clientOnly := nomadClientMode && !nomadServerMode
	
	config := &nomad.NativeInstallConfig{
		InstallConfig: &hashicorp.InstallConfig{
			Version:        "latest",
			CleanInstall:   nomadClean,
			ForceReinstall: nomadForce,
		},
		ServerEnabled:     !clientOnly,
		ClientEnabled:     !serverOnly,
		Datacenter:        nomadDatacenter,
		Region:            nomadRegion,
		BootstrapExpect:   nomadBootstrapExpect,
		ConsulIntegration: true,  // Enable by default
		VaultIntegration:  false,  // Disabled by default
		DockerEnabled:     nomadEnableDocker,
	}

	// Set install method
	config.InstallConfig.InstallMethod = hashicorp.MethodBinary

	// Create and run installer
	installer := nomad.NewNativeInstaller(rc, config)
	if err := installer.Install(); err != nil {
		return fmt.Errorf("Nomad installation failed: %w", err)
	}

	logger.Info("Nomad installation completed successfully")
	logger.Info("terminal prompt: Nomad is installed. Check status with: nomad node status")
	return nil
}

// Legacy function kept for reference
func runCreateNomadLegacy(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Validate mode selection
	if !nomadServerMode && !nomadClientMode {
		// Default to client mode if neither specified
		nomadClientMode = true
		logger.Info("No mode specified, defaulting to client mode")
	}
	
	if nomadServerMode && nomadClientMode {
		return eos_err.NewUserError("cannot specify both --server and --client modes")
	}

	// Check if running as root
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("this command must be run as root")
	}

	// ASSESS - Check current Nomad status
	logger.Info("Checking current Nomad status")
	status, err := checkNomadStatus(rc)
	if err != nil {
		logger.Warn("Failed to check Nomad status", zap.Error(err))
		status = &NomadStatus{} // Use empty status
	}

	// Log detailed status
	logger.Info("Current Nomad installation status",
		zap.Bool("installed", status.Installed),
		zap.Bool("running", status.Running),
		zap.Bool("failed", status.Failed),
		zap.String("version", status.Version),
		zap.String("service_status", status.ServiceStatus),
		zap.Bool("config_valid", status.ConfigValid),
		zap.Bool("server_mode", status.ServerMode),
		zap.Bool("client_mode", status.ClientMode),
		zap.String("cluster_leader", status.ClusterLeader),
		zap.Int("cluster_members", len(status.ClusterMembers)),
		zap.Int("job_count", status.JobCount))

	// Determine if we should proceed
	shouldInstall := false
	shouldConfigure := false

	if !status.Installed {
		logger.Info("Nomad is not installed, will install")
		shouldInstall = true
		shouldConfigure = true
	} else if status.Failed {
		logger.Warn("Nomad service is in failed state, will reconfigure",
			zap.String("current_status", status.ServiceStatus))
		shouldConfigure = true
	} else if !status.ConfigValid {
		logger.Warn("Nomad configuration is invalid, will reconfigure")
		shouldConfigure = true
	} else if nomadForce {
		logger.Info("Force flag specified, will reinstall/reconfigure")
		shouldInstall = true
		shouldConfigure = true
	} else if status.Running {
		// Check if mode change is requested
		if (nomadServerMode && !status.ServerMode) || (nomadClientMode && !status.ClientMode) {
			logger.Info("Mode change requested",
				zap.Bool("current_server", status.ServerMode),
				zap.Bool("requested_server", nomadServerMode))
			shouldConfigure = true
		} else {
			logger.Info("Nomad is already installed and running properly")
			
			// Show current status
			logger.Info("terminal prompt: Nomad is already installed and running")
			logger.Info("terminal prompt: Version: " + status.Version)
			logger.Info("terminal prompt: Mode: " + func() string {
				if status.ServerMode {
					return "server"
				}
				return "client"
			}())
			if status.ServerMode && status.ClusterLeader != "" {
				logger.Info("terminal prompt: Cluster leader: " + status.ClusterLeader)
				logger.Info("terminal prompt: Cluster size: " + fmt.Sprintf("%d members", len(status.ClusterMembers)))
			}
			if status.JobCount > 0 {
				logger.Info("terminal prompt: Running jobs: " + fmt.Sprintf("%d", status.JobCount))
			}
			logger.Info("terminal prompt: Use --force to reinstall or --clean for clean install")
			return nil
		}
	}

	// Clean operation if requested
	if nomadClean && status.Installed {
		logger.Info("Clean flag specified, removing existing Nomad installation first")
		
		// Gracefully stop and drain if running
		if status.Running {
			if status.ClientMode {
				logger.Info("Draining Nomad client node")
				exec.Command("nomad", "node", "drain", "-enable", "-yes", "-self").Run()
				time.Sleep(5 * time.Second)
			}
		}
		
		// Stop service
		exec.Command("systemctl", "stop", "nomad").Run()
		
		// Remove data
		logger.Info("Removing Nomad data directory")
		os.RemoveAll("/var/lib/nomad")
		os.RemoveAll("/etc/nomad.d")
		
		shouldInstall = true
		shouldConfigure = true
	}

	// Check dependencies
	logger.Info("Checking dependencies")
	
	// Check for Consul
	consulRunning := false
	if output, err := exec.Command("systemctl", "is-active", "consul").Output(); err == nil {
		consulRunning = strings.TrimSpace(string(output)) == "active"
	}
	if !consulRunning {
		logger.Warn("Consul is not running - Nomad will have limited functionality without service discovery")
		logger.Info("terminal prompt: Warning: Consul is not running. Consider installing with 'eos create consul' first")
	}

	// Check for Vault
	vaultRunning := false
	if output, err := exec.Command("systemctl", "is-active", "vault").Output(); err == nil {
		vaultRunning = strings.TrimSpace(string(output)) == "active"
	}
	if !vaultRunning {
		logger.Warn("Vault is not running - Nomad will not have secrets management integration")
		logger.Info("terminal prompt: Warning: Vault is not running. Consider installing with 'eos create vault' first")
	}

	// Check if SaltStack REST API is available
	apiURL := "https://localhost:8000"
	restInstaller := nomad.NewRESTInstaller(apiURL, true) // Skip TLS verify for self-signed cert

	// Check authentication
	logger.Info("Authenticating with Salt REST API")
	if err := restInstaller.Authenticate(rc.Ctx, "salt", "saltpass"); err != nil {
		logger.Error("Failed to authenticate with Salt REST API", zap.Error(err))
		// Fallback to direct salt-call if API not available
		saltCallPath, err := exec.LookPath("salt-call")
		if err != nil {
			logger.Error("Neither Salt REST API nor salt-call is available")
			return eos_err.NewUserError("saltstack is required for nomad installation - install with: eos create saltstack")
		}
		logger.Info("Falling back to direct salt-call execution", zap.String("salt_call", saltCallPath))
		
		// Use direct salt-call execution
		return runCreateNomadDirectSalt(rc, nomadServerMode, nomadClientMode, nomadBootstrapExpect,
			nomadDatacenter, nomadRegion, nomadBindAddr, nomadAdvertiseAddr, nomadLogLevel,
			nomadEnableACL, nomadForce, nomadClean, nomadJoinAddrs, nomadClientServers,
			nomadEnableDocker, nomadEnableRaw, consulRunning, vaultRunning)
	}

	logger.Info("Successfully authenticated with Salt REST API")

	if !shouldInstall && !shouldConfigure {
		logger.Info("No changes needed")
		return nil
	}

	// INTERVENE - Install Nomad via REST API
	logger.Info("Installing Nomad via Salt REST API")

	// Prepare configuration
	config := &nomad.NomadInstallConfig{
		ServerMode:        nomadServerMode,
		ClientMode:        nomadClientMode,
		BootstrapExpect:   nomadBootstrapExpect,
		Datacenter:        nomadDatacenter,
		Region:            nomadRegion,
		BindAddr:          nomadBindAddr,
		AdvertiseAddr:     nomadAdvertiseAddr,
		LogLevel:          nomadLogLevel,
		EnableACL:         nomadEnableACL,
		Force:             nomadForce,
		Clean:             nomadClean,
		JoinAddrs:         nomadJoinAddrs,
		ClientServers:     nomadClientServers,
		EnableDocker:      nomadEnableDocker,
		EnableRawExec:     nomadEnableRaw,
		ConsulIntegration: consulRunning,
		VaultIntegration:  vaultRunning,
	}

	// Execute installation via REST API
	if err := restInstaller.InstallNomad(rc, config); err != nil {
		logger.Error("Nomad installation via REST API failed", zap.Error(err))
		return fmt.Errorf("nomad installation failed: %w", err)
	}

	// EVALUATE - Verify installation
	logger.Info("Verifying Nomad installation")

	// Wait for service to stabilize
	time.Sleep(5 * time.Second)

	// Re-check status
	finalStatus, err := checkNomadStatus(rc)
	if err != nil {
		return fmt.Errorf("failed to verify installation: %w", err)
	}

	if !finalStatus.Installed {
		return fmt.Errorf("nomad binary not found after installation")
	}

	if !finalStatus.Running {
		return fmt.Errorf("nomad service not running after installation")
	}

	// Log successful installation
	logger.Info("Nomad installed successfully",
		zap.String("version", finalStatus.Version),
		zap.Bool("server_mode", finalStatus.ServerMode),
		zap.Bool("client_mode", finalStatus.ClientMode))

	// Show post-installation information
	logger.Info("terminal prompt: Nomad installation completed successfully!")
	logger.Info("terminal prompt: Version: " + finalStatus.Version)
	logger.Info("terminal prompt: Mode: " + func() string {
		if finalStatus.ServerMode {
			return "server"
		}
		return "client"
	}())

	if finalStatus.ServerMode {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Nomad server is running. Access the UI at: http://localhost:4646")
		if nomadBootstrapExpect > 1 {
			logger.Info("terminal prompt: Expecting " + fmt.Sprintf("%d", nomadBootstrapExpect) + " servers for quorum")
			logger.Info("terminal prompt: Join other servers with: nomad server join " + nomadAdvertiseAddr)
		}
	} else {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Nomad client is running and ready to accept jobs")
		if len(nomadClientServers) > 0 {
			logger.Info("terminal prompt: Connected to servers: " + strings.Join(nomadClientServers, ", "))
		}
	}

	if consulRunning {
		logger.Info("terminal prompt: ✓ Consul integration enabled for service discovery")
	}
	if vaultRunning {
		logger.Info("terminal prompt: ✓ Vault integration enabled for secrets management")
	}

	// Show next steps
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Next steps:")
	logger.Info("terminal prompt: - Check status: nomad status")
	logger.Info("terminal prompt: - View members: nomad server members")
	logger.Info("terminal prompt: - Submit a job: nomad job run <job.nomad>")
	logger.Info("terminal prompt: - View logs: journalctl -u nomad -f")

	return nil
}

// runCreateNomadDirectSalt is a fallback function that uses direct salt-call execution
func runCreateNomadDirectSalt(rc *eos_io.RuntimeContext, serverMode, clientMode bool, 
	bootstrapExpect int, datacenter, region, bindAddr, advertiseAddr, logLevel string,
	enableACL, force, clean bool, joinAddrs, clientServers []string,
	enableDocker, enableRaw, consulRunning, vaultRunning bool) error {
	
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Using direct salt-call execution for Nomad installation")

	// Prepare pillar data
	pillarData := map[string]interface{}{
		"nomad": map[string]interface{}{
			"ensure":            "present",
			"server_mode":       serverMode,
			"client_mode":       clientMode,
			"bootstrap_expect":  bootstrapExpect,
			"datacenter":        datacenter,
			"region":            region,
			"bind_addr":         bindAddr,
			"advertise_addr":    advertiseAddr,
			"log_level":         logLevel,
			"enable_acl":        enableACL,
			"force":             force,
			"clean":             clean,
			"join_addrs":        joinAddrs,
			"client_servers":    clientServers,
			"enable_docker":     enableDocker,
			"enable_raw_exec":   enableRaw,
			"consul_integration": consulRunning,
			"vault_integration": vaultRunning,
		},
	}

	pillarJSON, err := json.Marshal(pillarData)
	if err != nil {
		return fmt.Errorf("failed to marshal pillar data: %w", err)
	}

	// Execute Salt state
	saltCmd := exec.Command("salt-call",
		"--local",
		"--file-root=/opt/eos/salt/states",
		"--pillar-root=/opt/eos/salt/pillar",
		"state.apply",
		"hashicorp.nomad",
		fmt.Sprintf("pillar=%s", string(pillarJSON)))

	saltCmd.Stdout = os.Stdout
	saltCmd.Stderr = os.Stderr

	logger.Info("Executing Salt state", 
		zap.String("state", "hashicorp.nomad"),
		zap.Bool("server_mode", serverMode))

	if err := saltCmd.Run(); err != nil {
		logger.Error("Salt state execution failed", zap.Error(err))
		return fmt.Errorf("salt state execution failed: %w", err)
	}

	return nil
}

func init() {
	CreateCmd.AddCommand(CreateNomadCmd)
	CreateCmd.AddCommand(createNomadIngressCmd)
	CreateCmd.AddCommand(migrateK3sCmd)
	
	// Mode flags
	CreateNomadCmd.Flags().BoolVar(&nomadServerMode, "server", false, "Install Nomad in server mode")
	CreateNomadCmd.Flags().BoolVar(&nomadClientMode, "client", false, "Install Nomad in client mode (default)")
	
	// Server configuration
	CreateNomadCmd.Flags().IntVar(&nomadBootstrapExpect, "bootstrap-expect", 1, "Number of servers to wait for before bootstrapping cluster")
	CreateNomadCmd.Flags().StringVar(&nomadDatacenter, "datacenter", "dc1", "Datacenter name")
	CreateNomadCmd.Flags().StringVar(&nomadRegion, "region", "global", "Region name")
	
	// Network configuration
	CreateNomadCmd.Flags().StringVar(&nomadBindAddr, "bind-addr", "0.0.0.0", "Address to bind to")
	CreateNomadCmd.Flags().StringVar(&nomadAdvertiseAddr, "advertise-addr", "", "Address to advertise (defaults to bind addr)")
	
	// Cluster joining
	CreateNomadCmd.Flags().StringSliceVar(&nomadJoinAddrs, "join", []string{}, "Addresses of servers to join (for server mode)")
	CreateNomadCmd.Flags().StringSliceVar(&nomadClientServers, "servers", []string{}, "Server addresses (for client mode)")
	
	// Client drivers
	CreateNomadCmd.Flags().BoolVar(&nomadEnableDocker, "enable-docker", true, "Enable Docker driver on clients")
	CreateNomadCmd.Flags().BoolVar(&nomadEnableRaw, "enable-raw-exec", false, "Enable raw_exec driver (security risk)")
	
	// Security
	CreateNomadCmd.Flags().BoolVar(&nomadEnableACL, "enable-acl", false, "Enable ACL system")
	
	// Operational flags
	CreateNomadCmd.Flags().StringVar(&nomadLogLevel, "log-level", "INFO", "Log level (DEBUG, INFO, WARN, ERROR)")
	CreateNomadCmd.Flags().BoolVar(&nomadForce, "force", false, "Force reinstall even if already installed")
	CreateNomadCmd.Flags().BoolVar(&nomadClean, "clean", false, "Clean install (removes existing data)")

	// Add flags for Nomad ingress
	createNomadIngressCmd.Flags().String("domain", "", "Primary domain for ingress")
	createNomadIngressCmd.Flags().Bool("enable-mail", false, "Include Nginx mail proxy")
	createNomadIngressCmd.MarkFlagRequired("domain")

	// Add flags for K3s migration
	migrateK3sCmd.Flags().String("domain", "", "Domain for migrated ingress")
	migrateK3sCmd.Flags().Bool("dry-run", false, "Preview migration without making changes")
	migrateK3sCmd.Flags().Bool("preserve-pvcs", true, "Preserve persistent volume claims")
	migrateK3sCmd.Flags().Bool("migrate-ingress", true, "Migrate ingress to Nomad")
	migrateK3sCmd.Flags().Bool("migrate-mail-proxy", false, "Migrate mail proxy to Nomad")
	migrateK3sCmd.Flags().String("datacenter", "dc1", "Target Nomad datacenter")
	migrateK3sCmd.Flags().String("region", "global", "Target Nomad region")
}

// createNomadIngressCmd sets up Nomad ingress to replace K3s ingress
var createNomadIngressCmd = &cobra.Command{
	Use:   "nomad-ingress",
	Short: "Deploy Nomad ingress with Caddy and Nginx (replaces K3s ingress)",
	Long: `Deploy ingress infrastructure using Nomad jobs with Caddy and Nginx.
This replaces K3s/Kubernetes ingress controllers with Nomad-based alternatives.

Components:
- Caddy for HTTP/HTTPS ingress and reverse proxy
- Nginx for mail proxy (SMTP/IMAP/POP3) 
- Consul Connect for service mesh (optional)
- Automatic SSL certificate management
- Load balancing and health checking

This provides the same ingress capabilities as K3s but using Nomad orchestration.

Prerequisites:
- Running Nomad cluster
- Running Consul cluster
- Domain DNS configured

Examples:
  eos create nomad-ingress --domain=example.com
  eos create nomad-ingress --domain=mail.example.com --enable-mail`,
	RunE: eos.Wrap(runCreateNomadIngress),
}

func runCreateNomadIngress(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Setting up Nomad ingress infrastructure")

	domain, _ := cmd.Flags().GetString("domain")
	enableMail, _ := cmd.Flags().GetBool("enable-mail")
	
	// Generate Nomad ingress jobs
	generator := nomad.NewJobGenerator(logger)
	
	// Setup Caddy ingress
	logger.Info("Generating Caddy ingress job specification")
	caddyConfig := nomad.GetDefaultCaddyConfig()
	caddyConfig.Domain = domain
	
	caddyJob, err := generator.GenerateCaddyIngressJob(rc, caddyConfig)
	if err != nil {
		logger.Error("Failed to generate Caddy ingress job", zap.Error(err))
		return err
	}
	
	// Deploy Caddy ingress job
	logger.Info("Deploying Caddy ingress to Nomad cluster")
	if err := generator.DeployNomadJob(rc, caddyJob); err != nil {
		logger.Error("Failed to deploy Caddy ingress", zap.Error(err))
		return err
	}
	
	// Setup Nginx mail proxy if requested
	if enableMail {
		logger.Info("Generating Nginx mail proxy job specification")
		nginxConfig := nomad.GetDefaultNginxConfig()
		nginxConfig.Domain = domain
		
		nginxJob, err := generator.GenerateNginxMailJob(rc, nginxConfig)
		if err != nil {
			logger.Error("Failed to generate Nginx mail proxy job", zap.Error(err))
			return err
		}
		
		// Deploy Nginx mail proxy job
		logger.Info("Deploying Nginx mail proxy to Nomad cluster")
		if err := generator.DeployNomadJob(rc, nginxJob); err != nil {
			logger.Error("Failed to deploy Nginx mail proxy", zap.Error(err))
			return err
		}
	}

	logger.Info("Nomad ingress deployment completed successfully")
	logger.Info("terminal prompt: ✅ Nomad Ingress Deployment Complete!")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Ingress Details:")
	logger.Info("terminal prompt:   - Domain: " + domain)
	logger.Info("terminal prompt:   - Caddy HTTP/HTTPS: Deployed")
	if enableMail {
		logger.Info("terminal prompt:   - Nginx Mail Proxy: Deployed")
	}
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Next Steps:")
	logger.Info("terminal prompt:   1. Check job status: nomad job status caddy-ingress")
	if enableMail {
		logger.Info("terminal prompt:   2. Check mail proxy: nomad job status nginx-mail-proxy")
	}
	logger.Info("terminal prompt:   3. Configure DNS: Point " + domain + " to Nomad cluster")
	logger.Info("terminal prompt:   4. Deploy backend services: nomad job run <service.hcl>")
	
	return nil
}

// migrateK3sCmd migrates existing K3s cluster to Nomad
var migrateK3sCmd = &cobra.Command{
	Use:   "migrate-k3s",
	Short: "Migrate K3s cluster to Nomad",
	Long: `Migrate an existing K3s/Kubernetes cluster to Nomad orchestration.
This command extracts workloads from K3s and converts them to equivalent Nomad jobs.

Migration process:
1. Extract K3s deployments, services, and configurations
2. Convert Kubernetes resources to Nomad job specifications
3. Setup Consul service discovery to replace Kubernetes services
4. Deploy Caddy/Nginx ingress to replace K3s ingress
5. Migrate persistent volumes and secrets
6. Verify migration and optionally remove K3s

The migration preserves application functionality while moving to simpler Nomad orchestration.

Prerequisites:
- Running K3s cluster (source)
- Running Nomad cluster (target)
- Running Consul cluster
- kubectl access to K3s cluster

Examples:
  eos create migrate-k3s --domain=example.com --dry-run
  eos create migrate-k3s --domain=example.com --migrate-ingress --migrate-mail-proxy
  eos create migrate-k3s --domain=example.com --datacenter=production`,
	RunE: eos.Wrap(runMigrateK3s),
}

func runMigrateK3s(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting K3s to Nomad migration")

	domain, _ := cmd.Flags().GetString("domain")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	preservePVCs, _ := cmd.Flags().GetBool("preserve-pvcs")
	migrateIngress, _ := cmd.Flags().GetBool("migrate-ingress")
	migrateMailProxy, _ := cmd.Flags().GetBool("migrate-mail-proxy")
	datacenter, _ := cmd.Flags().GetString("datacenter")
	region, _ := cmd.Flags().GetString("region")
	
	// Setup migration configuration
	migrationConfig := nomad.K3sMigrationConfig{
		Domain:              domain,
		DryRun:              dryRun,
		PreservePVCs:        preservePVCs,
		MigrateIngress:      migrateIngress,
		MigrateMailProxy:    migrateMailProxy,
		TargetDatacenter:    datacenter,
		TargetRegion:        region,
	}
	
	// Perform migration
	logger.Info("Initializing migration manager")
	migrationManager := nomad.NewMigrationManager(logger)
	
	logger.Info("Executing K3s to Nomad migration",
		zap.Bool("dry_run", dryRun),
		zap.String("target_datacenter", datacenter))
	
	result, err := migrationManager.MigrateK3sToNomad(rc, migrationConfig)
	if err != nil {
		logger.Error("K3s migration failed", zap.Error(err))
		return err
	}
	
	// Display migration results
	logger.Info("K3s to Nomad migration completed")
	logger.Info("terminal prompt: ✅ K3s Migration Complete!")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Migration Summary:")
	logger.Info("terminal prompt:   - Services converted: " + fmt.Sprintf("%d", result.ServicesConverted))
	logger.Info("terminal prompt:   - Nomad jobs created: " + fmt.Sprintf("%d", result.JobsCreated))
	logger.Info("terminal prompt:   - Ingress migrated: " + fmt.Sprintf("%t", result.IngressSetup))
	logger.Info("terminal prompt:   - Mail proxy migrated: " + fmt.Sprintf("%t", result.MailProxySetup))
	
	if len(result.Errors) > 0 {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Migration Warnings:")
		for _, errMsg := range result.Errors {
			logger.Info("terminal prompt:   - " + errMsg)
		}
	}
	
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Next Steps:")
	logger.Info("terminal prompt:   1. Verify services: nomad job status")
	logger.Info("terminal prompt:   2. Check Consul services: consul catalog services")
	if migrateIngress {
		logger.Info("terminal prompt:   3. Test ingress: curl " + domain)
	}
	if !dryRun {
		logger.Info("terminal prompt:   4. Remove K3s (after verification): eos delete k3s")
	}
	
	return nil
}