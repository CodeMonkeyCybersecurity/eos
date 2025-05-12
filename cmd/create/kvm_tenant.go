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
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/templates"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

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

func init() {
	defaultKey := filepath.Join(os.Getenv("HOME"), ".ssh", "id_ed25519.pub")
	CreateKvmTenantCmd.Flags().StringVar(&kvm.SshKeyOverride, "ssh-key", defaultKey, "Path to public SSH key to inject")
	CreateKvmCmd.AddCommand(CreateKvmTenantCmd)
	CreateKvmTenantCmd.Flags().StringVar(&kvm.TenantDistro, "distro", "centos-stream9", "Distro to provision (e.g. centos-stream9, ubuntu-cloud)")
	CreateKvmTenantCmd.Flags().StringVar(&kvm.IsoPathOverride, "iso", kvm.IsoDefaultPath, "Path to bootable ISO")
	CreateKvmTenantCmd.Flags().StringVar(&kvm.UserProvidedVMName, "vm-name", "", "Optional custom name for the tenant VM")
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
	if kvm.UserProvidedVMName != "" {
		if strings.ContainsAny(kvm.UserProvidedVMName, " \t\n") {
			return fmt.Errorf("invalid VM name: must not contain whitespace")
		}
		vmName = kvm.UserProvidedVMName
	} else {
		vmID, err := getNextVMID()
		if err != nil {
			log.Error("failed to determine VM ID", zap.Error(err))
			return err
		}
		vmName = kvm.VmPrefix + vmID
	}

	// Now that vmName is final, check for conflicts
	if checkVMExists(vmName) {
		return fmt.Errorf("a VM named %q already exists", vmName)
	}

	switch kvm.TenantDistro {
	case "centos-stream9":
		log.Info("Using Kickstart provisioning")
		return runKickstartProvisioning(ctx, vmName)
	case "ubuntu-cloud":
		log.Info("Using cloud-init provisioning")
		return runCloudInitProvisioning(ctx, vmName)
	default:
		return fmt.Errorf("unsupported distro: %s", kvm.TenantDistro)
	}
}

func checkVMExists(name string) bool {
	cmd := exec.Command("virsh", "dominfo", name)
	err := cmd.Run()
	return err == nil // dominfo succeeds → VM exists
}

func runKickstartProvisioning(ctx *eosio.RuntimeContext, vmName string) error {
	log := ctx.Log.Named("kvm.kickstart")

	diskPath := filepath.Join(kvm.ImageDir, vmName+".qcow2")
	if _, err := os.Stat(kvm.SshKeyOverride); err != nil {
		return fmt.Errorf("missing SSH key at %s", kvm.SshKeyOverride)
	}

	ksPath, err := generateKickstartWithSSH(vmName, kvm.SshKeyOverride)
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

	// Try to detect IP address
	ipAddr := waitForIP(vmName, 60*time.Second, log)
	if ipAddr == "" {
		mac := getMACFromDomiflist(vmName)
		log.Info("📡 Falling back to DHCP lease lookup", zap.String("mac", mac))
		ipAddr, _ = getIPFromDHCPLeases(mac)
	}
	sshUser := kvm.DefaultTenantUsername // e.g., "debugadmin"

	log.Info("✅ VM provisioned",
		zap.String("vm", vmName),
		zap.String("disk", diskPath),
		zap.String("kickstart", ksPath),
		zap.String("ssh_user", sshUser),
		zap.String("ip", ipAddr))

	fmt.Printf(`
✅ VM provisioned: %s

🔐 SSH access:
    ssh %s@%s

📁 You used this SSH key:
    %s

🖥️  Hostname: %s

`, vmName, sshUser, ipAddr, kvm.SshKeyOverride, vmName)

	return nil
}

func getMACFromDomiflist(vmName string) string {
	out, err := exec.Command("virsh", "domiflist", vmName).Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 5 && strings.Contains(fields[4], ":") {
			return fields[4] // MAC address is in the 5th column
		}
	}
	return ""
}

func getNextVMID() (string, error) {
	fd, err := os.OpenFile(kvm.VmBaseIDFile, os.O_RDWR|os.O_CREATE, 0644)
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
	err = tmpl.Execute(&buf, kvm.TemplateContext{
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

func getIPFromDHCPLeases(mac string) (string, error) {
	out, err := exec.Command("virsh", "net-dhcp-leases", "default").Output()
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, mac) {
			fields := strings.Fields(line)
			for _, f := range fields {
				if strings.Contains(f, "/") && strings.Contains(f, ".") {
					return strings.Split(f, "/")[0], nil
				}
			}
		}
	}
	return "", fmt.Errorf("IP not found in DHCP leases for MAC %s", mac)
}

func virtInstall(log *zap.Logger, vmName, ksPath, diskPath string) error {
	log.Info("Starting virt-install", zap.String("ks", ksPath), zap.String("disk", diskPath))

	cmd := exec.Command("virt-install",
		"--name", vmName,
		"--ram", "2048",
		"--vcpus", "2",
		"--os-variant", getOSVariant(kvm.TenantDistro),
		"--disk", fmt.Sprintf("path=%s,size=20", diskPath),
		"--location", kvm.IsoPathOverride,
		"--initrd-inject", kvm.SshKeyOverride,
		"--initrd-inject", ksPath,
		"--extra-args", "inst.ks=file:/"+filepath.Base(ksPath)+" console=ttyS0",
		"--graphics", "none",
		"--channel", "unix,mode=bind,target_type=virtio,name=org.qemu.guest_agent.0",
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runCloudInitProvisioning(ctx *eosio.RuntimeContext, vmName string) error {
	log := ctx.Log.Named("kvm.cloudinit")

	cfg := kvm.CloudInitConfig{
		VMName:    vmName,
		CloudImg:  "/srv/iso/ubuntu-22.04-server-cloudimg-amd64.img",
		PublicKey: kvm.SshKeyOverride, // use --ssh-key override path
	}

	if err := kvm.ProvisionCloudInitVM(log, cfg); err != nil {
		return err
	}

	log.Info("💡 TODO: virt-install the VM using cloud image + seed.img")
	return fmt.Errorf("virt-install not yet implemented")
}

func waitForIP(vmName string, maxWait time.Duration, log *zap.Logger) string {
	start := time.Now()
	for time.Since(start) < maxWait {
		ip, err := getTenantVMIP(vmName)
		if err == nil && ip != "" {
			log.Info("✅ VM IP address found", zap.String("vm", vmName), zap.String("ip", ip))
			return ip
		}
		log.Debug("⌛ Still waiting for IP...", zap.String("vm", vmName), zap.Error(err))
		time.Sleep(5 * time.Second)
	}
	log.Warn("⚠️ Timed out waiting for VM IP", zap.String("vm", vmName))
	return "unknown"
}

func getTenantVMIP(vmName string) (string, error) {
	out, err := exec.Command("virsh", "domifaddr", vmName, "--source", "agent").Output()
	if err != nil {
		return "", fmt.Errorf("virsh agent not available: %w", err)
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		for _, f := range fields {
			if strings.Contains(f, "/") {
				ip := strings.Split(f, "/")[0]
				return ip, nil
			}
		}
	}
	return "", fmt.Errorf("no IP address found in domifaddr output")
}
