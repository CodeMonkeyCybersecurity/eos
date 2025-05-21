// pkg/kvm/lifecycle.go

package kvm

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

func InstallKVM() error {
	if platform.IsCommandAvailable("apt") {
		return runInstall("apt-get update && apt-get install -y qemu-system-x86 libvirt-daemon-system libvirt-clients bridge-utils virt-manager virt-viewer")
	}
	if platform.IsCommandAvailable("dnf") {
		return runInstall("dnf install -y qemu-system-x86 libvirt libvirt-devel virt-install bridge-utils virt-viewer")
	}
	if platform.IsCommandAvailable("yum") {
		return runInstall("yum install -y qemu-system-x86 libvirt libvirt-devel virt-install bridge-utils virt-viewer")
	}
	return fmt.Errorf("no supported package manager found (apt, dnf, yum)")
}

// runInstall runs the given install command with stdout/stderr streaming.
func runInstall(cmd string) error {
	fmt.Println("📦 Installing KVM and dependencies...")
	c := exec.Command("bash", "-c", cmd)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

// EnsureLibvirtd ensures libvirtd is started and enabled.
func EnsureLibvirtd() error {
	fmt.Println("🔧 Ensuring libvirtd service is running...")
	if err := exec.Command("systemctl", "start", "libvirtd").Run(); err != nil {
		return fmt.Errorf("failed to start libvirtd: %w", err)
	}
	if err := exec.Command("systemctl", "enable", "libvirtd").Run(); err != nil {
		return fmt.Errorf("failed to enable libvirtd: %w", err)
	}
	fmt.Println("✅ libvirtd is active and enabled.")
	return nil
}

func RunCreateKvmTenant(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
	log := ctx.Log.Named("tenant")

	var vmName string
	if UserProvidedVMName != "" {
		if strings.ContainsAny(UserProvidedVMName, " \t\n") {
			return fmt.Errorf("invalid VM name: must not contain whitespace")
		}
		vmName = UserProvidedVMName
	} else {
		vmID, err := getNextVMID()
		if err != nil {
			log.Error("failed to determine VM ID", zap.Error(err))
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
		log.Info("Using Kickstart provisioning")
		return runKickstartProvisioning(ctx, vmName)
	case "ubuntu-cloud":
		log.Info("Using cloud-init provisioning")
		return runCloudInitProvisioning(ctx, vmName)
	default:
		return fmt.Errorf("unsupported distro: %s", TenantDistro)
	}
}

func checkVMExists(name string) bool {
	cmd := exec.Command("virsh", "dominfo", name)
	err := cmd.Run()
	return err == nil // dominfo succeeds → VM exists
}

func runKickstartProvisioning(ctx *eosio.RuntimeContext, vmName string) error {
	log := ctx.Log.Named("kickstart")

	if err := ConfigureKVMBridge(); err != nil {
		log.Warn("Bridge setup failed; VM may not have external networking", zap.Error(err))
	}

	pubKeyPath, _, err := PrepareTenantSSHKey(vmName)
	if err != nil {
		return err
	}

	// Start ticker
	ctxWithCancel, cancel := context.WithCancel(context.Background())
	defer cancel()

	diskPath := filepath.Join(ImageDir, vmName+".qcow2")
	go StartInstallStatusTicker(ctxWithCancel, log, vmName, diskPath)

	// Run provisioning
	err = ProvisionKickstartTenantVM(ctx, vmName, pubKeyPath)

	// Stop ticker regardless of success
	cancel()
	return err
}

func getNextVMID() (string, error) {
	fd, err := os.OpenFile(VmBaseIDFile, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return "", fmt.Errorf("cannot open ID file: %w", err)
	}
	defer fd.Close()

	// Apply exclusive lock (blocks until available)
	if err := unix.Flock(int(fd.Fd()), unix.LOCK_EX); err != nil {
		return "", fmt.Errorf("failed to lock ID file: %w", err)
	}
	defer func() {
		if err := unix.Flock(int(fd.Fd()), unix.LOCK_UN); err != nil {
			log.Printf("unlock failed: %v", err)
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

func runCloudInitProvisioning(ctx *eosio.RuntimeContext, vmName string) error {
	log := ctx.Log.Named("cloudinit")

	cfg := CloudInitConfig{
		VMName:    vmName,
		CloudImg:  "/srv/iso/ubuntu-22.04-server-cloudimg-amd64.img",
		PublicKey: SshKeyOverride, // use --ssh-key override path
	}

	if err := ProvisionCloudInitVM(log, cfg); err != nil {
		return err
	}

	log.Info("💡 TODO: virt-install the VM using cloud image + seed.img")
	return fmt.Errorf("virt-install not yet implemented")
}

func RunCreateKvmInstall(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
	log := ctx.Log.Named("kvm")

	system.RequireRoot()

	nonInteractive, _ := cmd.Flags().GetBool("yes")
	isoOverride, _ := cmd.Flags().GetString("iso")
	enableBridge, _ := cmd.Flags().GetBool("network-bridge")
	autostartFlag, _ := cmd.Flags().GetBool("autostart")
	autostartExplicit := cmd.Flags().Changed("autostart")

	log.Info("📦 Installing KVM and libvirt packages...")
	if err := InstallKVM(); err != nil {
		log.Error("Failed to install KVM", zap.Error(err))
		return err
	}
	log.Info("✅ KVM installation complete")

	if enableBridge {
		log.Info("🛠️  Configuring network bridge...")
		if err := ConfigureKVMBridge(); err != nil {
			log.Error("Failed to configure network bridge", zap.Error(err))
			return err
		}
		log.Info("✅ Network bridge configured")
	}

	if err := EnsureLibvirtd(); err != nil {
		log.Error("libvirtd failed to start", zap.Error(err))
		return err
	}

	isoDir := resolveIsoDir(log, nonInteractive, isoOverride)
	if info, err := os.Stat(isoDir); err == nil && info.IsDir() {
		log.Info("🔐 Setting ACL for ISO directory", zap.String("path", isoDir))
		SetLibvirtACL(isoDir)
	} else {
		log.Warn("⚠️ ISO directory not found or invalid", zap.String("path", isoDir))
	}

	if resolveAutostart(log, nonInteractive, autostartExplicit, autostartFlag) {
		log.Info("⚙️  Enabling autostart for default libvirt network")
		SetLibvirtDefaultNetworkAutostart()
	} else {
		log.Info("Skipping autostart — run 'virsh net-start default' manually if needed")
	}

	log.Info("✅ KVM setup completed successfully")
	return nil
}

func resolveIsoDir(log *zap.Logger, nonInteractive bool, isoOverride string) string {
	if isoOverride != "" {
		log.Info("ISO path provided via flag", zap.String("iso_dir", isoOverride))
		return isoOverride
	}
	if nonInteractive {
		log.Info("Using default ISO directory (non-interactive)", zap.String("iso_dir", "/srv/iso"))
		return "/srv/iso"
	}
	val := interaction.PromptConfirmOrValue("The hypervisor needs access to an ISO directory", "/srv/iso")
	log.Info("ISO directory selected", zap.String("iso_dir", val))
	return val
}

func resolveAutostart(log *zap.Logger, nonInteractive, explicitlySet bool, value bool) bool {
	if explicitlySet {
		log.Info("Autostart explicitly provided via flag", zap.Bool("autostart", value))
		return value
	}
	if nonInteractive {
		log.Info("Assuming 'no' for autostart (non-interactive)")
		return false
	}
	resp := interaction.PromptYesNo("Would you like to autostart the default libvirt network?", false)
	log.Info("User autostart choice", zap.Bool("autostart", resp))
	return resp
}

func RunCreateKvmTemplate(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
	ctx.Log.Info("Stub: KVM template provisioning logic goes here")
	return nil
}
