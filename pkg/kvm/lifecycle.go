// pkg/kvm/lifecycle.go

package kvm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

func InstallKVM(rc *eos_io.RuntimeContext) error {
	if platform.IsCommandAvailable("apt") {
		return runInstall(rc, "apt-get update && apt-get install -y qemu-system-x86 libvirt-daemon-system libvirt-clients bridge-utils virt-manager virt-viewer")
	}
	if platform.IsCommandAvailable("dnf") {
		return runInstall(rc, "dnf install -y qemu-system-x86 libvirt libvirt-devel virt-install bridge-utils virt-viewer")
	}
	if platform.IsCommandAvailable("yum") {
		return runInstall(rc, "yum install -y qemu-system-x86 libvirt libvirt-devel virt-install bridge-utils virt-viewer")
	}
	return fmt.Errorf("no supported package manager found (apt, dnf, yum)")
}

// runInstall runs the given install command with stdout/stderr streaming.
func runInstall(rc *eos_io.RuntimeContext, cmd string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing KVM and dependencies")
	c := exec.Command("bash", "-c", cmd)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

// EnsureLibvirtd ensures libvirtd is started and enabled.
func EnsureLibvirtd(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Ensuring libvirtd service is running")
	if err := exec.Command("systemctl", "start", "libvirtd").Run(); err != nil {
		return fmt.Errorf("failed to start libvirtd: %w", err)
	}
	if err := exec.Command("systemctl", "enable", "libvirtd").Run(); err != nil {
		return fmt.Errorf("failed to enable libvirtd: %w", err)
	}
	logger.Info("libvirtd is active and enabled")
	return nil
}

func RunCreateKvmTenant(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

	var vmName string
	if UserProvidedVMName != "" {
		if strings.ContainsAny(UserProvidedVMName, " \t\n") {
			return fmt.Errorf("invalid VM name: must not contain whitespace")
		}
		vmName = UserProvidedVMName
	} else {
		vmID, err := getNextVMID(rc)
		if err != nil {
			otelzap.Ctx(rc.Ctx).Error("failed to determine VM ID", zap.Error(err))
			return err
		}
		vmName = VmPrefix + vmID
	}

	// Now that vmName is final, check for conflicts
	if checkVMExists(vmName) {
		return fmt.Errorf("a VM named %q already exists", vmName)
	}

	switch TenantDistro {
	case "centos-stream9":
		otelzap.Ctx(rc.Ctx).Info("Using Kickstart provisioning")
		return runKickstartProvisioning(rc, vmName)
	case "ubuntu-cloud":
		otelzap.Ctx(rc.Ctx).Info("Using cloud-init provisioning")
		return runCloudInitProvisioning(rc, vmName)
	default:
		return fmt.Errorf("unsupported distro: %s", TenantDistro)
	}
}

func checkVMExists(name string) bool {
	cmd := exec.Command("virsh", "dominfo", name)
	err := cmd.Run()
	return err == nil // dominfo succeeds → VM exists
}

func runKickstartProvisioning(rc *eos_io.RuntimeContext, vmName string) error {

	if err := ConfigureKVMBridge(rc); err != nil {
		otelzap.Ctx(rc.Ctx).Warn("Bridge setup failed; VM may not have external networking", zap.Error(err))
	}

	pubKeyPath, _, err := PrepareTenantSSHKey(vmName)
	if err != nil {
		return err
	}

	diskPath := filepath.Join(ImageDir, vmName+".qcow2")
	go StartInstallStatusTicker(rc.Ctx, zap.L(), vmName, diskPath)

	// Run provisioning
	err = ProvisionKickstartTenantVM(rc, vmName, pubKeyPath)

	// Stop ticker regardless of success
	return err
}

func getNextVMID(rc *eos_io.RuntimeContext) (string, error) {
	fd, err := os.OpenFile(VmBaseIDFile, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return "", fmt.Errorf("cannot open ID file: %w", err)
	}
	defer func() {
		if cerr := fd.Close(); cerr != nil {
			logger := otelzap.Ctx(rc.Ctx)
			logger.Error("failed to close vmid file", zap.String("path", VmBaseIDFile), zap.Error(cerr))
		}
	}()

	// Apply exclusive lock (blocks until available)
	if err := unix.Flock(int(fd.Fd()), unix.LOCK_EX); err != nil {
		return "", fmt.Errorf("failed to lock ID file: %w", err)
	}
	defer func() {
		if err := unix.Flock(int(fd.Fd()), unix.LOCK_UN); err != nil {
			otelzap.Ctx(rc.Ctx)
		}
	}()

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

func runCloudInitProvisioning(rc *eos_io.RuntimeContext, vmName string) error {

	cfg := CloudInitConfig{
		VMName:    vmName,
		CloudImg:  "/srv/iso/ubuntu-22.04-server-cloudimg-amd64.img",
		PublicKey: SshKeyOverride, // use --ssh-key override path
	}

	if err := ProvisionCloudInitVM(zap.L(), cfg); err != nil {
		return err
	}

	otelzap.Ctx(rc.Ctx).Info(" TODO: virt-install the VM using cloud image + seed.img")
	return fmt.Errorf("virt-install not yet implemented")
}

func RunCreateKvmInstall(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

	eos_unix.RequireRoot(rc.Ctx)

	nonInteractive, _ := cmd.Flags().GetBool("yes")
	isoOverride, _ := cmd.Flags().GetString("iso")
	enableBridge, _ := cmd.Flags().GetBool("network-bridge")
	autostartFlag, _ := cmd.Flags().GetBool("autostart")
	autostartExplicit := cmd.Flags().Changed("autostart")

	otelzap.Ctx(rc.Ctx).Info(" Installing KVM and libvirt packages...")
	if err := InstallKVM(rc); err != nil {
		otelzap.Ctx(rc.Ctx).Error("Failed to install KVM", zap.Error(err))
		return err
	}
	otelzap.Ctx(rc.Ctx).Info(" KVM installation complete")

	if enableBridge {
		otelzap.Ctx(rc.Ctx).Info("  Configuring network bridge...")
		if err := ConfigureKVMBridge(rc); err != nil {
			otelzap.Ctx(rc.Ctx).Error("Failed to configure network bridge", zap.Error(err))
			return err
		}
		otelzap.Ctx(rc.Ctx).Info(" Network bridge configured")
	}

	if err := EnsureLibvirtd(rc); err != nil {
		otelzap.Ctx(rc.Ctx).Error("libvirtd failed to start", zap.Error(err))
		return err
	}

	isoDir := resolveIsoDir(rc, nonInteractive, isoOverride)
	if info, err := os.Stat(isoDir); err == nil && info.IsDir() {
		otelzap.Ctx(rc.Ctx).Info(" Setting ACL for ISO directory", zap.String("path", isoDir))
		SetLibvirtACL(rc, isoDir)
	} else {
		otelzap.Ctx(rc.Ctx).Warn("ISO directory not found or invalid", zap.String("path", isoDir))
	}

	if resolveAutostart(rc, nonInteractive, autostartExplicit, autostartFlag) {
		otelzap.Ctx(rc.Ctx).Info("  Enabling autostart for default libvirt network")
		SetLibvirtDefaultNetworkAutostart()
	} else {
		otelzap.Ctx(rc.Ctx).Info("Skipping autostart — run 'virsh net-start default' manually if needed")
	}

	otelzap.Ctx(rc.Ctx).Info(" KVM setup completed successfully")
	return nil
}

func resolveIsoDir(rc *eos_io.RuntimeContext, nonInteractive bool, isoOverride string) string {
	if isoOverride != "" {
		otelzap.Ctx(rc.Ctx).Info("ISO path provided via flag", zap.String("iso_dir", isoOverride))
		return isoOverride
	}
	if nonInteractive {
		otelzap.Ctx(rc.Ctx).Info("Using default ISO directory (non-interactive)", zap.String("iso_dir", "/srv/iso"))
		return "/srv/iso"
	}
	val := interaction.PromptConfirmOrValue(rc.Ctx, "The hypervisor needs access to an ISO directory", "/srv/iso")
	otelzap.Ctx(rc.Ctx).Info("ISO directory selected", zap.String("iso_dir", val))
	return val
}

func resolveAutostart(rc *eos_io.RuntimeContext, nonInteractive, explicitlySet bool, value bool) bool {
	if explicitlySet {
		otelzap.Ctx(rc.Ctx).Info("Autostart explicitly provided via flag", zap.Bool("autostart", value))
		return value
	}
	if nonInteractive {
		otelzap.Ctx(rc.Ctx).Info("Assuming 'no' for autostart (non-interactive)")
		return false
	}
	resp := interaction.PromptYesNo(rc.Ctx, "Would you like to autostart the default libvirt network?", false)
	otelzap.Ctx(rc.Ctx).Info("User autostart choice", zap.Bool("autostart", resp))
	return resp
}

func RunCreateKvmTemplate(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	otelzap.Ctx(rc.Ctx).Info("Stub: KVM template provisioning logic goes here")
	return nil
}
