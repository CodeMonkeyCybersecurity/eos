// pkg/kvm/provision_kickstart.go

package kvm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func ProvisionKickstartTenantVM(rc *eos_io.RuntimeContext, vmName, pubKeyPath string) error {
	log := otelzap.Ctx(rc.Ctx)
	diskPath := filepath.Join(ImageDir, vmName+".qcow2")

	ksPath, err := GenerateKickstartWithSSH(vmName, pubKeyPath)
	if err != nil {
		return fmt.Errorf("failed to generate kickstart: %w", err)
	}
	defer func() {
		if err := os.Remove(ksPath); err != nil {
			log.Warn("Failed to remove kickstart file", zap.String("path", ksPath), zap.Error(err))
		}
	}()
	log.Info("🟡 Kickstart file generated", zap.String("path", ksPath))

	if err := virtInstall(zap.L(), vmName, ksPath, diskPath); err != nil {
		return fmt.Errorf("virt-install failed: %w", err)
	}
	log.Info("🟡 virt-install finished; checking post-install VM status")

	if err := ensureDomainRunning(vmName, zap.L()); err != nil {
		log.Warn("VM not running post-install", zap.Error(err))
	}

	ipAddr := waitForIP(vmName, 60*time.Second, zap.L())
	if ipAddr == "" || ipAddr == "unknown" {
		log.Warn("IP not found via qemu-agent; falling back to DHCP lease")
		if mac := getMACFromDomiflist(vmName); mac != "" {
			if fallbackIP, _ := getIPFromDHCPLeases(mac); fallbackIP != "" {
				ipAddr = fallbackIP
				log.Info(" Found fallback DHCP IP", zap.String("ip", ipAddr))
			}
		}
	}

	if ipAddr == "unknown" {
		log.Warn("Provisioning finished but no IP could be determined")
	} else {
		log.Info(" Provisioning complete", zap.String("ip", ipAddr))
	}

	return nil
}

func ensureDomainRunning(vmName string, log *zap.Logger) error {
	out, err := exec.Command("virsh", "domstate", vmName).Output()
	if err != nil {
		return fmt.Errorf("could not determine domain state: %w", err)
	}
	state := strings.TrimSpace(string(out))
	log.Info(" VM current state", zap.String("state", state))

	if state == "shut off" {
		log.Info(" VM shut off — restarting manually")
		if err := exec.Command("virsh", "start", vmName).Run(); err != nil {
			return fmt.Errorf("failed to restart domain: %w", err)
		}
		log.Info(" VM restarted")
	}
	return nil
}

func waitForIP(vmName string, maxWait time.Duration, log *zap.Logger) string {
	start := time.Now()
	for time.Since(start) < maxWait {
		ip, err := getTenantVMIP(vmName)
		if err == nil && ip != "" {
			log.Info(" VM IP address found", zap.String("vm", vmName), zap.String("ip", ip))
			return ip
		}
		log.Debug("⌛ Still waiting for IP...", zap.String("vm", vmName), zap.Error(err))
		time.Sleep(5 * time.Second)
	}
	log.Warn("Timed out waiting for VM IP", zap.String("vm", vmName))
	return "unknown"
}

func virtInstall(log *zap.Logger, vmName, ksPath, diskPath string) error {
	log.Info("Starting virt-install", zap.String("ks", ksPath), zap.String("disk", diskPath))

	// Build args
	args := []string{
		"--name", vmName,
		"--ram", "2048",
		"--vcpus", "2",
		"--cpu", "host",
		"--network", "bridge=br0,model=virtio",
		"--os-variant", getOSVariant(TenantDistro),
		"--disk", fmt.Sprintf("path=%s,size=20", diskPath),
		"--location", IsoPathOverride,
		"--initrd-inject", ksPath,
		"--extra-args", fmt.Sprintf("inst.ks=file:/%s console=ttyS0", filepath.Base(ksPath)),
		"--graphics", "none",
		"--channel", "unix,target_type=virtio,name=org.qemu.guest_agent.0",
		"--noautoconsole",
		"--wait", "-1",
	}

	// If injecting SSH key separately is still needed
	if SshKeyOverride != "" && SshKeyOverride != ksPath {
		args = append(args, "--initrd-inject", SshKeyOverride)
	}

	// Log full command in debug mode
	log.Debug("virt-install args", zap.Strings("args", args))

	cmd := exec.Command("virt-install", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
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
