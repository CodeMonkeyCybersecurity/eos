package read

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/inspect"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
var (
	infraTerraformFlag bool
	infraOutputPath    string
)

var infraCmd = &cobra.Command{
	Use:   "infra",
	Short: "Inspect comprehensive infrastructure components",
	Long: `Performs a comprehensive audit of your infrastructure including:
- System information (CPU, memory, disk, network)
- Docker containers and configurations
- KVM/Libvirt virtual machines
- Hetzner Cloud resources
- Service configurations (nginx, databases, etc.)

The output can be saved in YAML format for human review or Terraform format
for infrastructure as code management.

The inspection process follows these phases:
1. System Discovery - Collect host information, CPU, memory, disk usage
2. Container Analysis - Enumerate Docker containers, images, networks, volumes
3. Virtualization Audit - Discover KVM/Libvirt VMs, networks, storage pools
4. Cloud Resources - Query Hetzner Cloud API for servers, networks, firewalls
5. Service Configuration - Analyze systemd services, nginx, databases
6. Report Generation - Compile findings into structured output

Output formats:
- YAML (default): Human-readable structured data for review and analysis
- Terraform: Infrastructure as Code format for version control and deployment

The tool automatically detects available components and gracefully handles
missing dependencies (Docker, libvirt, hcloud CLI) by logging warnings
and continuing with available data sources.`,
	Example: `  # Generate YAML infrastructure report
  eos read infra
  
  # Generate Terraform configuration from current infrastructure
  eos read infra --terraform
  
  # Save to custom location
  eos read infra --output /tmp/my-infrastructure.yml
  
  # Example output locations:
  # YAML: /etc/eos/20240309-143022_hostname_infra_status.yml
  # Terraform: /etc/eos/20240309-143022_hostname_terraform/ (directory)
  
  # The report includes detailed sections for:
  # - System information (OS, kernel, CPU, memory, uptime)
  # - Running containers with port mappings and volumes
  # - Virtual machines with resource allocations
  # - Cloud infrastructure with network topology
  # - Service configurations and health status`,
	Args: cobra.NoArgs,
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		start := time.Now()
		logger := otelzap.Ctx(rc.Ctx)

		// Get current working directory and user context for debugging
		pwd, _ := os.Getwd()
		user := os.Getenv("USER")
		if user == "" {
			user = os.Getenv("USERNAME") // Windows fallback
		}

		logger.Info(" Starting infrastructure inspection",
			zap.String("user", user),
			zap.String("pwd", pwd),
			zap.String("command_line", strings.Join(os.Args, " ")),
			zap.Bool("terraform", infraTerraformFlag),
			zap.String("output", infraOutputPath),
			zap.String("function", "runInspectInfra"))

		// Create inspector
		inspector := inspect.New(rc)

		// Run discovery with progress updates
		logger.Info(" Discovering system information",
			zap.String("phase", "system"),
			zap.Duration("timeout", 30*time.Second))

		systemStart := time.Now()
		systemInfo, err := inspector.DiscoverSystem()
		if err != nil {
			logger.Error(" Failed to discover system information",
				zap.Error(err),
				zap.String("phase", "system"),
				zap.Duration("duration", time.Since(systemStart)),
				zap.String("troubleshooting", "Check system commands availability (hostnamectl, free, df)"))
			return err
		}
		logger.Info(" System information collected",
			zap.String("hostname", systemInfo.Hostname),
			zap.String("os", systemInfo.OS),
			zap.String("kernel", systemInfo.Kernel),
			zap.String("architecture", systemInfo.Architecture),
			zap.Int("cpu_count", systemInfo.CPU.Count),
			zap.Int("cpu_cores", systemInfo.CPU.Cores),
			zap.String("memory_total", systemInfo.Memory.Total),
			zap.String("uptime", systemInfo.Uptime),
			zap.Duration("discovery_duration", time.Since(systemStart)))

		logger.Info(" Discovering Docker containers and configurations",
			zap.String("phase", "docker"),
			zap.Duration("timeout", 30*time.Second))

		dockerStart := time.Now()
		dockerInfo, err := inspector.DiscoverDocker()
		if err != nil {
			logger.Warn("Docker discovery failed (Docker might not be installed)",
				zap.Error(err),
				zap.String("phase", "docker"),
				zap.Duration("duration", time.Since(dockerStart)),
				zap.String("troubleshooting", "Install Docker or check if Docker daemon is running: sudo systemctl status docker"))
		} else {
			runningContainers := 0
			for _, container := range dockerInfo.Containers {
				if container.State == "running" {
					runningContainers++
				}
			}
			logger.Info(" Docker information collected",
				zap.Int("containers", len(dockerInfo.Containers)),
				zap.Int("running", runningContainers),
				zap.Int("images", len(dockerInfo.Images)),
				zap.Int("networks", len(dockerInfo.Networks)),
				zap.Int("volumes", len(dockerInfo.Volumes)),
				zap.Duration("discovery_duration", time.Since(dockerStart)))
		}

		logger.Info(" Discovering KVM/Libvirt virtual machines",
			zap.String("phase", "kvm"),
			zap.Duration("timeout", 30*time.Second))

		kvmStart := time.Now()
		kvmInfo, err := inspector.DiscoverKVM()
		if err != nil {
			logger.Warn("KVM discovery failed (libvirt might not be installed)",
				zap.Error(err),
				zap.String("phase", "kvm"),
				zap.Duration("duration", time.Since(kvmStart)),
				zap.String("troubleshooting", "Install libvirt-clients or check if libvirtd is running: sudo systemctl status libvirtd"))
		} else {
			runningVMs := 0
			for _, vm := range kvmInfo.VMs {
				if vm.State == "running" {
					runningVMs++
				}
			}
			logger.Info(" KVM information collected",
				zap.Int("vms", len(kvmInfo.VMs)),
				zap.Int("running", runningVMs),
				zap.Int("networks", len(kvmInfo.Networks)),
				zap.Int("pools", len(kvmInfo.StoragePools)),
				zap.Duration("discovery_duration", time.Since(kvmStart)))
		}

		logger.Info("☁️ Discovering Hetzner Cloud resources",
			zap.String("phase", "hetzner"),
			zap.Duration("timeout", 30*time.Second))

		hetznerStart := time.Now()
		hetznerInfo, err := inspector.DiscoverHetzner()
		if err != nil {
			logger.Warn("Hetzner discovery failed (hcloud CLI might not be configured)",
				zap.Error(err),
				zap.String("phase", "hetzner"),
				zap.Duration("duration", time.Since(hetznerStart)),
				zap.String("troubleshooting", "Install hcloud CLI and configure with 'hcloud auth' or set HCLOUD_TOKEN"))
		} else if hetznerInfo != nil {
			logger.Info(" Hetzner information collected",
				zap.Int("servers", len(hetznerInfo.Servers)),
				zap.Int("networks", len(hetznerInfo.Networks)),
				zap.Int("firewalls", len(hetznerInfo.Firewalls)),
				zap.Int("volumes", len(hetznerInfo.Volumes)),
				zap.Duration("discovery_duration", time.Since(hetznerStart)))
		}

		logger.Info(" Discovering service configurations",
			zap.String("phase", "services"),
			zap.Duration("timeout", 30*time.Second))

		servicesStart := time.Now()
		servicesInfo, err := inspector.DiscoverServices()
		if err != nil {
			logger.Warn("Services discovery partially failed",
				zap.Error(err),
				zap.String("phase", "services"),
				zap.Duration("duration", time.Since(servicesStart)),
				zap.String("troubleshooting", "Check systemctl availability and service configurations"))
		} else {
			logger.Info(" Service information collected",
				zap.Int("systemd_services", len(servicesInfo.SystemdServices)),
				zap.Bool("nginx_found", servicesInfo.Nginx != nil),
				zap.Bool("postgres_found", servicesInfo.PostgreSQL != nil),
				zap.Bool("mysql_found", servicesInfo.MySQL != nil),
				zap.Duration("discovery_duration", time.Since(servicesStart)))
		}

		// Compile all information
		infrastructure := &inspect.Infrastructure{
			Timestamp: time.Now(),
			Hostname:  systemInfo.Hostname,
			System:    systemInfo,
			Docker:    dockerInfo,
			KVM:       kvmInfo,
			Hetzner:   hetznerInfo,
			Services:  servicesInfo,
		}

		// Determine output path with detailed logging
		if infraOutputPath == "" {
			hostname, _ := os.Hostname()
			timestamp := time.Now().Format("20060102-150405")
			if infraTerraformFlag {
				// For modular Terraform, create a directory
				infraOutputPath = filepath.Join("/etc/eos", fmt.Sprintf("%s_%s_terraform", timestamp, hostname))
			} else {
				// For YAML, create a file
				infraOutputPath = filepath.Join("/etc/eos", fmt.Sprintf("%s_%s_infra_status.yml", timestamp, hostname))
			}
			logger.Info(" Generated output path",
				zap.String("path", infraOutputPath),
				zap.String("hostname", hostname),
				zap.String("timestamp", timestamp),
				zap.Bool("terraform_format", infraTerraformFlag),
				zap.String("output_type", map[bool]string{true: "directory", false: "file"}[infraTerraformFlag]))
		} else {
			logger.Info(" Using custom output path",
				zap.String("path", infraOutputPath),
				zap.Bool("terraform_format", infraTerraformFlag))
		}

		// Ensure output directory exists with logging
		var outputDir string
		if infraTerraformFlag {
			// For Terraform, the infraOutputPath is the directory itself
			outputDir = infraOutputPath
		} else {
			// For YAML, get the parent directory of the file
			outputDir = filepath.Dir(infraOutputPath)
		}

		logger.Info(" Creating output directory",
			zap.String("directory", outputDir),
			zap.String("permissions", "0755"))

		if err := os.MkdirAll(outputDir, shared.ServiceDirPerm); err != nil {
			logger.Error(" Failed to create output directory",
				zap.Error(err),
				zap.String("directory", outputDir))
			return err
		}

		logger.Info(" Output directory ready",
			zap.String("directory", outputDir))

		// Write output
		if infraTerraformFlag {
			logger.Info(" Generating Terraform configuration",
				zap.String("path", infraOutputPath))
			if err := inspect.WriteTerraform(rc.Ctx, infrastructure, infraOutputPath); err != nil {
				logger.Error(" Failed to write Terraform output",
					zap.Error(err),
					zap.String("path", infraOutputPath))
				return err
			}
		} else {
			logger.Info(" Generating YAML report",
				zap.String("path", infraOutputPath))
			if err := inspect.WriteYAML(rc.Ctx, infrastructure, infraOutputPath); err != nil {
				logger.Error(" Failed to write YAML output",
					zap.Error(err),
					zap.String("path", infraOutputPath))
				return err
			}
		}

		logger.Info(" Infrastructure inspection complete",
			zap.String("output_path", infraOutputPath),
			zap.String("format", map[bool]string{true: "terraform", false: "yaml"}[infraTerraformFlag]),
			zap.String("type", map[bool]string{true: "modular_directory", false: "single_file"}[infraTerraformFlag]),
			zap.Duration("total_duration", time.Since(start)))

		return nil
	}),
}

func init() {
	ReadCmd.AddCommand(infraCmd)

	infraCmd.Flags().BoolVar(&infraTerraformFlag, "terraform", false, "Output in Terraform format (.tf) instead of YAML")
	infraCmd.Flags().StringVar(&infraOutputPath, "output", "", "Custom output path (default: /etc/eos/<date>_<hostname>_infra_status.<ext>)")
}
