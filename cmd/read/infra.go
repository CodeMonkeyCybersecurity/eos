package read

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/inspect"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

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
for infrastructure as code management.`,
	Args: cobra.NoArgs,
	RunE: eos_cli.Wrap(runInspectInfra),
}

func init() {
	ReadCmd.AddCommand(infraCmd)

	infraCmd.Flags().BoolVar(&infraTerraformFlag, "terraform", false, "Output in Terraform format (.tf) instead of YAML")
	infraCmd.Flags().StringVar(&infraOutputPath, "output", "", "Custom output path (default: /etc/eos/<date>_<hostname>_infra_status.<ext>)")
}

func runInspectInfra(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("🔍 Starting infrastructure inspection",
		zap.Bool("terraform", infraTerraformFlag),
		zap.String("output", infraOutputPath))

	// Create inspector
	inspector := inspect.New(rc)

	// Run discovery with progress updates
	logger.Info("📊 Discovering system information")
	systemInfo, err := inspector.DiscoverSystem()
	if err != nil {
		logger.Error("❌ Failed to discover system information", 
			zap.Error(err),
			zap.String("phase", "system"))
		return err
	}
	logger.Info("✅ System information collected",
		zap.String("hostname", systemInfo.Hostname),
		zap.String("os", systemInfo.OS),
		zap.Int("cpu_count", systemInfo.CPU.Count))

	logger.Info("🐳 Discovering Docker containers and configurations")
	dockerInfo, err := inspector.DiscoverDocker()
	if err != nil {
		logger.Warn("⚠️ Docker discovery failed (Docker might not be installed)",
			zap.Error(err),
			zap.String("phase", "docker"))
	} else {
		logger.Info("✅ Docker information collected",
			zap.Int("containers", len(dockerInfo.Containers)),
			zap.Int("images", len(dockerInfo.Images)),
			zap.Int("networks", len(dockerInfo.Networks)))
	}

	logger.Info("🖥️ Discovering KVM/Libvirt virtual machines")
	kvmInfo, err := inspector.DiscoverKVM()
	if err != nil {
		logger.Warn("⚠️ KVM discovery failed (libvirt might not be installed)",
			zap.Error(err),
			zap.String("phase", "kvm"))
	} else {
		logger.Info("✅ KVM information collected",
			zap.Int("vms", len(kvmInfo.VMs)),
			zap.Int("networks", len(kvmInfo.Networks)),
			zap.Int("pools", len(kvmInfo.StoragePools)))
	}

	logger.Info("☁️ Discovering Hetzner Cloud resources")
	hetznerInfo, err := inspector.DiscoverHetzner()
	if err != nil {
		logger.Warn("⚠️ Hetzner discovery failed (hcloud CLI might not be configured)",
			zap.Error(err),
			zap.String("phase", "hetzner"))
	} else if hetznerInfo != nil {
		logger.Info("✅ Hetzner information collected",
			zap.Int("servers", len(hetznerInfo.Servers)),
			zap.Int("networks", len(hetznerInfo.Networks)),
			zap.Int("firewalls", len(hetznerInfo.Firewalls)))
	}

	logger.Info("⚙️ Discovering service configurations")
	servicesInfo, err := inspector.DiscoverServices()
	if err != nil {
		logger.Warn("⚠️ Services discovery partially failed",
			zap.Error(err),
			zap.String("phase", "services"))
	} else {
		logger.Info("✅ Service information collected",
			zap.Int("systemd_services", len(servicesInfo.SystemdServices)),
			zap.Bool("nginx_found", servicesInfo.Nginx != nil),
			zap.Bool("postgres_found", servicesInfo.PostgreSQL != nil))
	}

	// Compile all information
	infrastructure := &inspect.Infrastructure{
		Timestamp:   time.Now(),
		Hostname:    systemInfo.Hostname,
		System:      systemInfo,
		Docker:      dockerInfo,
		KVM:         kvmInfo,
		Hetzner:     hetznerInfo,
		Services:    servicesInfo,
	}

	// Determine output path
	if infraOutputPath == "" {
		hostname, _ := os.Hostname()
		timestamp := time.Now().Format("20060102-150405")
		ext := ".yml"
		if infraTerraformFlag {
			ext = ".tf"
		}
		infraOutputPath = filepath.Join("/etc/eos", fmt.Sprintf("%s_%s_infra_status%s", timestamp, hostname, ext))
	}

	// Ensure output directory exists
	outputDir := filepath.Dir(infraOutputPath)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		logger.Error("❌ Failed to create output directory",
			zap.Error(err),
			zap.String("directory", outputDir))
		return err
	}

	// Write output
	if infraTerraformFlag {
		logger.Info("📝 Generating Terraform configuration",
			zap.String("path", infraOutputPath))
		if err := inspect.WriteTerraform(infrastructure, infraOutputPath); err != nil {
			logger.Error("❌ Failed to write Terraform output",
				zap.Error(err),
				zap.String("path", infraOutputPath))
			return err
		}
	} else {
		logger.Info("📝 Generating YAML report",
			zap.String("path", infraOutputPath))
		if err := inspect.WriteYAML(infrastructure, infraOutputPath); err != nil {
			logger.Error("❌ Failed to write YAML output",
				zap.Error(err),
				zap.String("path", infraOutputPath))
			return err
		}
	}

	logger.Info("✨ Infrastructure inspection complete",
		zap.String("output_file", infraOutputPath),
		zap.String("format", map[bool]string{true: "terraform", false: "yaml"}[infraTerraformFlag]))

	return nil
}