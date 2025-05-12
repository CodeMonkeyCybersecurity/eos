// cmd/create/kvm_tenant.go

package create

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/templates"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

var sshKeyOverride string
var tenantDistro string
var userProvidedVMName string

var (
	vmPrefix = "vm-tenant-"
)

const (
	ksTemplatePath = "/home/henry/autoinstall-tenant.ks"
	isoDefaultPath = "/home/henry/CentOS-Stream-9-latest-x86_64-dvd1.iso"
	imageDir       = "/var/lib/libvirt/images"
	vmBaseIDFile   = "/var/lib/libvirt/next_vm_id"
)

type TemplateContext struct {
	SSHKey   string
	VMName   string
	Hostname string
}

var CreateKvmTenantCmd = &cobra.Command{
	Use:   "tenant",
	Short: "Provision a new KVM tenant VM using CentOS Stream 9 or cloud-init",
	Long: `Provision a new tenant virtual machine under KVM.

By default, this creates a CentOS Stream 9 VM using a Kickstart-based installation.
You can customize the VM name, injected SSH key, boot ISO, and target OS.

Each VM gets a unique incrementing ID unless you specify --vm-name.

Examples:
  # Create a new tenant VM with default settings
  eos create kvm tenant

  # Create a VM with a specific name and SSH key
  eos create kvm tenant --vm-name vm-tenant-alice --ssh-key ~/.ssh/alice.pub

  # Provision using a custom ISO
  eos create kvm tenant --iso /srv/iso/CentOS-Stream-9.iso

  # (Future) Use Ubuntu with cloud-init (WIP)
  eos create kvm tenant --distro ubuntu-cloud
`,
	RunE: eos.Wrap(runCreateKvmTenant),
}

var isoPathOverride string

func init() {
	defaultKey := filepath.Join(os.Getenv("HOME"), ".ssh", "id_ed25519.pub")
	CreateKvmTenantCmd.Flags().StringVar(&sshKeyOverride, "ssh-key", defaultKey, "Path to public SSH key to inject")
	CreateKvmCmd.AddCommand(CreateKvmTenantCmd)
	CreateKvmTenantCmd.Flags().StringVar(&tenantDistro, "distro", "centos-stream9", "Distro to provision (e.g. centos-stream9, ubuntu-cloud)")
	CreateKvmTenantCmd.Flags().StringVar(&isoPathOverride, "iso", isoDefaultPath, "Path to bootable ISO")
	CreateKvmTenantCmd.Flags().StringVar(&userProvidedVMName, "vm-name", "", "Optional custom name for the tenant VM")
}

func getOSVariant(distro string) string {
	switch distro {
	case "centos-stream9":
		return "centos-stream9"
	case "ubuntu-cloud":
		return "ubuntu20.04"
	default:
		return "generic"
	}
}

func runCreateKvmTenant(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
	log := ctx.Log.Named("kvm.tenant")

	var vmName string
	if userProvidedVMName != "" {
		if strings.ContainsAny(userProvidedVMName, " \t\n") {
			return fmt.Errorf("invalid VM name: must not contain whitespace")
		}
		vmName = userProvidedVMName
	} else {
		vmID, err := getNextVMID()
		if err != nil {
			log.Error("failed to determine VM ID", zap.Error(err))
			return err
		}
		vmName = vmPrefix + vmID
	}

	// Now that vmName is final, check for conflicts
	if checkVMExists(vmName) {
		return fmt.Errorf("a VM named %q already exists", vmName)
	}

	switch tenantDistro {
	case "centos-stream9":
		log.Info("Using Kickstart provisioning")
		return runKickstartProvisioning(ctx, vmName)
	case "ubuntu-cloud":
		log.Info("Using cloud-init provisioning")
		return runCloudInitProvisioning(ctx, vmName)
	default:
		return fmt.Errorf("unsupported distro: %s", tenantDistro)
	}
}

func checkVMExists(name string) bool {
	cmd := exec.Command("virsh", "dominfo", name)
	err := cmd.Run()
	return err == nil // dominfo succeeds → VM exists
}

func runKickstartProvisioning(ctx *eosio.RuntimeContext, vmName string) error {
	log := ctx.Log.Named("kvm.kickstart")

	diskPath := filepath.Join(imageDir, vmName+".qcow2")
	if _, err := os.Stat(sshKeyOverride); err != nil {
		return fmt.Errorf("missing SSH key at %s", sshKeyOverride)
	}

	ksPath, err := generateKickstartWithSSH(vmName, sshKeyOverride)
	if err != nil {
		log.Error("failed to prepare Kickstart", zap.Error(err))
		return err
	}
	defer func() {
		if err := os.Remove(ksPath); err != nil {
			log.Warn("Failed to remove temp Kickstart file", zap.String("path", ksPath), zap.Error(err))
		}
	}()

	if err := virtInstall(log, vmName, ksPath, diskPath); err != nil {
		log.Error("virt-install failed", zap.Error(err))
		return err
	}

	log.Info("✅ VM provisioned",
		zap.String("vm", vmName),
		zap.String("disk", diskPath),
		zap.String("kickstart", ksPath))
	return nil
}

func getNextVMID() (string, error) {
	fd, err := os.OpenFile(vmBaseIDFile, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return "", fmt.Errorf("cannot open ID file: %w", err)
	}
	defer fd.Close()

	// Apply exclusive lock (blocks until available)
	if err := unix.Flock(int(fd.Fd()), unix.LOCK_EX); err != nil {
		return "", fmt.Errorf("failed to lock ID file: %w", err)
	}
	defer unix.Flock(int(fd.Fd()), unix.LOCK_UN)

	id := 1
	data := make([]byte, 100)
	n, _ := fd.Read(data)
	if n > 0 {
		if parsed, err := strconv.Atoi(strings.TrimSpace(string(data[:n]))); err == nil {
			id = parsed
		}
	}

	next := id + 1
	if _, err := fd.Seek(0, 0); err != nil {
		return "", err
	}
	if err := fd.Truncate(0); err != nil {
		return "", err
	}
	if _, err := fd.Write([]byte(strconv.Itoa(next))); err != nil {
		return "", err
	}

	return fmt.Sprintf("%03d", id), nil
}

func generateKickstartWithSSH(vmName, pubkeyPath string) (string, error) {
	key, err := os.ReadFile(pubkeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read SSH key: %w", err)
	}

	tmpl, err := template.New("kickstart").Parse(templates.KickstartTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, TemplateContext{
		SSHKey:   strings.TrimSpace(string(key)),
		VMName:   vmName,
		Hostname: vmName,
	})
	if err != nil {
		return "", fmt.Errorf("failed to render kickstart: %w", err)
	}

	tempPath := filepath.Join(os.TempDir(), vmName+"-kickstart.ks")
	if err := os.WriteFile(tempPath, buf.Bytes(), 0644); err != nil {
		return "", err
	}
	return tempPath, nil
}

func virtInstall(log *zap.Logger, vmName, ksPath, diskPath string) error {
	log.Info("Starting virt-install", zap.String("ks", ksPath), zap.String("disk", diskPath))

	cmd := exec.Command("virt-install",
		"--name", vmName,
		"--ram", "2048",
		"--vcpus", "2",
		"--os-variant", getOSVariant(tenantDistro),
		"--disk", fmt.Sprintf("path=%s,size=20", diskPath),
		"--location", isoPathOverride,
		"--initrd-inject", sshKeyOverride,
		"--initrd-inject", ksPath,
		"--extra-args", "inst.ks=file:/"+filepath.Base(ksPath)+" console=ttyS0",
		"--graphics", "none",
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runCloudInitProvisioning(ctx *eosio.RuntimeContext, vmName string) error {
	log := ctx.Log.Named("kvm.cloudinit")
	log.Warn("cloud-init mode is not yet implemented")

	// TODO:
	// - Generate cloud-init `user-data` and `meta-data`
	// - Create ISO or seed.img using genisoimage or cloud-localds
	// - Inject via --disk or --cdrom into virt-install
	// - Run virt-install with Ubuntu cloud image as base disk

	return fmt.Errorf("cloud-init provisioning is not yet implemented — use --distro centos-stream9 instead")
}
