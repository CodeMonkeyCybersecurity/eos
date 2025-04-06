package system

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
)

func InstallKVM() error {
	if platform.IsCommandAvailable("apt-get") {
		return runInstall("apt-get update && apt-get install -y qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virt-manager virt-viewer")
	}
	if platform.IsCommandAvailable("dnf") {
		return runInstall("dnf install -y qemu-kvm libvirt libvirt-devel virt-install bridge-utils virt-viewer")
	}
	if platform.IsCommandAvailable("yum") {
		return runInstall("yum install -y qemu-kvm libvirt libvirt-devel virt-install bridge-utils virt-viewer")
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
