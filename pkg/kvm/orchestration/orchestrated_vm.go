//go:build linux

package orchestration

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/kvm"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// OrchestratedVMManager manages VMs with Consul and Nomad integration
type OrchestratedVMManager struct {
	consul *ConsulOrchestrator
	nomad  *NomadOrchestrator
	logger otelzap.LoggerWithCtx
	rc     *eos_io.RuntimeContext
}

// NewOrchestratedVMManager creates a new orchestrated VM manager
func NewOrchestratedVMManager(rc *eos_io.RuntimeContext, consulAddr, nomadAddr string) (*OrchestratedVMManager, error) {
	logger := otelzap.Ctx(rc.Ctx)

	consul, err := NewConsulOrchestrator(rc, consulAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Consul orchestrator: %w", err)
	}

	nomad, err := NewNomadOrchestrator(rc, nomadAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Nomad orchestrator: %w", err)
	}

	return &OrchestratedVMManager{
		consul: consul,
		nomad:  nomad,
		logger: logger,
		rc:     rc,
	}, nil
}

// CreateOrchestratedVM creates a VM with full orchestration
func (om *OrchestratedVMManager) CreateOrchestratedVM(vmName string, enableNomad bool) error {
	om.logger.Info("Creating orchestrated VM",
		zap.String("vm_name", vmName),
		zap.Bool("nomad_enabled", enableNomad))

	// Step 1: Allocate IP from Consul
	ip, err := om.consul.AllocateIP(vmName)
	if err != nil {
		return fmt.Errorf("failed to allocate IP: %w", err)
	}
	om.logger.Info("IP allocated from Consul", zap.String("ip", ip))

	// Step 2: Generate SSH keys
	sshDir := filepath.Join("/srv/iso", vmName, "ssh")
	publicKeyPath, privateKeyPath, err := kvm.GenerateEd25519Keys(sshDir)
	if err != nil {
		// Release IP on failure
		_ = om.consul.ReleaseIP(vmName)
		return fmt.Errorf("failed to generate SSH keys: %w", err)
	}

	// Step 3: Create cloud-init with allocated IP
	cloudInitConfig := om.createCloudInitWithStaticIP(vmName, ip, publicKeyPath)

	// Step 4: Create the VM with virsh
	if err := om.createVMWithVirsh(vmName, ip, cloudInitConfig); err != nil {
		// Cleanup on failure
		_ = om.consul.ReleaseIP(vmName)
		return fmt.Errorf("failed to create VM: %w", err)
	}

	// Step 5: Register with Consul
	registration := &VMRegistration{
		ID:        fmt.Sprintf("vm-%s", vmName),
		Name:      vmName,
		IPAddress: ip,
		Port:      22, // SSH port
		Tags:      []string{"kvm", "ubuntu", "orchestrated"},
		Meta: map[string]string{
			"created_at":  time.Now().Format(time.RFC3339),
			"ssh_key":     privateKeyPath,
			"consul_ip":   ip,
		},
		HealthCheck: &HealthCheck{
			TCP:                            fmt.Sprintf("%s:22", ip),
			Interval:                       30 * time.Second,
			Timeout:                        10 * time.Second,
			DeregisterCriticalServiceAfter: 5 * time.Minute,
		},
	}

	if err := om.consul.RegisterVM(registration); err != nil {
		om.logger.Warn("Failed to register VM with Consul",
			zap.String("vm_name", vmName),
			zap.Error(err))
	}

	// Step 6: Create Nomad job if enabled
	if enableNomad {
		vmJob := &NomadVMJob{
			ID:          fmt.Sprintf("vm-%s-monitor", vmName),
			Name:        fmt.Sprintf("Monitor for %s", vmName),
			VMName:      vmName,
			Type:        "service",
			Priority:    50,
			Datacenters: []string{"dc1"},
			Meta: map[string]string{
				"vm_name":  vmName,
				"vm_ip":    ip,
				"created":  time.Now().Format(time.RFC3339),
			},
		}

		if err := om.nomad.CreateVMJob(vmJob); err != nil {
			om.logger.Warn("Failed to create Nomad job for VM",
				zap.String("vm_name", vmName),
				zap.Error(err))
		}
	}

	// SECURITY P2 #6: Don't log SSH key paths - information disclosure
	om.logger.Info("Orchestrated VM created successfully",
		zap.String("vm_name", vmName),
		zap.String("ip", ip),
		zap.String("ssh_key_status", "configured"))

	// Log completion (user-facing output should be handled by caller or dedicated output package)
	om.logger.Info("Orchestrated VM created successfully",
		zap.String("vm_name", vmName),
		zap.String("ip_address", ip),
		zap.Bool("nomad_enabled", enableNomad),
		zap.String("consul_service", fmt.Sprintf("vm-%s", vmName)),
		zap.String("ssh_command", fmt.Sprintf("ssh -i <key> ubuntu@%s", ip)))

	return nil
}

// createCloudInitWithStaticIP creates cloud-init config with static IP
func (om *OrchestratedVMManager) createCloudInitWithStaticIP(vmName, ip, publicKeyPath string) string {
	// Read the public key using os.ReadFile instead of exec.Command("cat")
	pubKeyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		om.logger.Warn("Failed to read public key",
			zap.Error(err))
		pubKeyBytes = []byte("ssh-ed25519 PLACEHOLDER")
	}

	// Extract network from IP (assuming /24)
	ipParts := strings.Split(ip, ".")
	if len(ipParts) == 4 {
		ipParts[3] = "1"
	}
	gateway := strings.Join(ipParts, ".")

	return fmt.Sprintf(`#cloud-config
hostname: %s
manage_etc_hosts: true
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: sudo
    home: /home/ubuntu
    shell: /bin/bash
    ssh_authorized_keys:
      - %s

# Static IP configuration
network:
  version: 2
  ethernets:
    ens3:
      dhcp4: false
      addresses:
        - %s/24
      gateway4: %s
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4

# Install Consul agent and QEMU guest agent
runcmd:
  - curl -fsSL https://apt.releases.hashicorp.com/gpg | apt-key add -
  - apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
  - apt-get update && apt-get install -y consul qemu-guest-agent
  - |
    cat > /etc/consul.d/consul.hcl <<EOF
    datacenter = "dc1"
    data_dir = "/opt/consul"
    log_level = "INFO"
    node_name = "%s"
    server = false

    bind_addr = "%s"
    client_addr = "0.0.0.0"

    retry_join = ["192.168.122.1"]

    services {
      name = "vm-%s"
      port = 22
      tags = ["kvm", "ubuntu"]
      check {
        id = "ssh"
        name = "SSH TCP on port 22"
        tcp = "localhost:22"
        interval = "10s"
        timeout = "2s"
      }
    }
    EOF
  - systemctl enable consul
  - systemctl start consul
  - systemctl enable qemu-guest-agent
  - systemctl start qemu-guest-agent

# System updates
package_update: true
package_upgrade: false

# Final message
final_message: "Orchestrated VM %s is ready!"
`, vmName, strings.TrimSpace(string(pubKeyBytes)), ip, gateway, vmName, ip, vmName, vmName)
}

// createVMWithVirsh creates the VM using virt-install
func (om *OrchestratedVMManager) createVMWithVirsh(vmName, _ /* ip */, cloudInit string) error {
	workDir := filepath.Join("/srv/iso", vmName)

	// Create working directory
	if err := exec.Command("mkdir", "-p", workDir).Run(); err != nil {
		return fmt.Errorf("failed to create working directory: %w", err)
	}

	// Write cloud-init files
	userDataPath := filepath.Join(workDir, "user-data")
	metaDataPath := filepath.Join(workDir, "meta-data")

	// SECURITY P0 #1: Use os.WriteFile instead of shell to prevent command injection
	if err := os.WriteFile(userDataPath, []byte(cloudInit), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write user-data: %w", err)
	}

	// Write meta-data
	metaData := fmt.Sprintf("instance-id: %s\nlocal-hostname: %s\n", vmName, vmName)
	if err := os.WriteFile(metaDataPath, []byte(metaData), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write meta-data: %w", err)
	}

	// Create cloud-init ISO
	seedPath := filepath.Join(workDir, "seed.iso")
	cloudLocaldsCmd := exec.Command("cloud-localds", seedPath, userDataPath, metaDataPath)
	if output, err := cloudLocaldsCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create seed ISO: %w\nOutput: %s", err, output)
	}

	// Download Ubuntu base image if not exists
	baseImage := "/srv/iso/ubuntu-24.04-server-cloudimg-amd64.img"
	if err := exec.Command("test", "-f", baseImage).Run(); err != nil {
		om.logger.Info("Downloading Ubuntu 24.04 base image...")
		downloadCmd := exec.Command("wget", "-O", baseImage,
			"https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img")
		if output, err := downloadCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to download base image: %w\nOutput: %s", err, output)
		}
	}

	// Create VM disk as qcow2 overlay
	vmDisk := filepath.Join(workDir, fmt.Sprintf("%s.qcow2", vmName))
	qemuCmd := exec.Command("qemu-img", "create", "-f", "qcow2", "-b", baseImage, "-F", "qcow2", vmDisk, "40G")
	if output, err := qemuCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create VM disk: %w\nOutput: %s", err, output)
	}

	// Create VM with virt-install
	virtInstallCmd := exec.Command("virt-install",
		"--name", vmName,
		"--memory", "4096",
		"--vcpus", "2",
		"--disk", fmt.Sprintf("path=%s,format=qcow2", vmDisk),
		"--disk", fmt.Sprintf("path=%s,device=cdrom", seedPath),
		"--os-variant", "ubuntu24.04",
		"--network", "network=default",
		"--channel", "unix,target_type=virtio,name=org.qemu.guest_agent.0",
		"--graphics", "none",
		"--console", "pty,target_type=serial",
		"--import",
		"--noautoconsole",
	)

	om.logger.Info("Creating VM with virt-install",
		zap.String("vm_name", vmName),
		zap.String("command", strings.Join(virtInstallCmd.Args, " ")))

	if output, err := virtInstallCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("virt-install failed: %w\nOutput: %s", err, output)
	}

	return nil
}

// DestroyOrchestratedVM destroys an orchestrated VM
func (om *OrchestratedVMManager) DestroyOrchestratedVM(vmName string) error {
	om.logger.Info("Destroying orchestrated VM", zap.String("vm_name", vmName))

	var errors []string

	// Deregister from Consul
	if err := om.consul.DeregisterVM(vmName); err != nil {
		errors = append(errors, fmt.Sprintf("Consul deregistration failed: %v", err))
	}

	// Delete Nomad job if exists
	jobID := fmt.Sprintf("vm-%s-monitor", vmName)
	if err := om.nomad.DeleteVMJob(jobID); err != nil {
		// Ignore if job doesn't exist
		om.logger.Debug("Nomad job deletion failed (may not exist)",
			zap.String("job_id", jobID),
			zap.Error(err))
	}

	// Destroy the VM with virsh
	// First stop it
	stopCmd := exec.Command("virsh", "destroy", vmName)
	_ = stopCmd.Run() // Ignore error if already stopped

	// Then undefine it
	undefineCmd := exec.Command("virsh", "undefine", vmName, "--nvram")
	if output, err := undefineCmd.CombinedOutput(); err != nil {
		errors = append(errors, fmt.Sprintf("VM undefine failed: %v\nOutput: %s", err, output))
	}

	// Clean up files
	workDir := filepath.Join("/srv/iso", vmName)
	cleanupCmd := exec.Command("rm", "-rf", workDir)
	if err := cleanupCmd.Run(); err != nil {
		errors = append(errors, fmt.Sprintf("Cleanup failed: %v", err))
	}

	if len(errors) > 0 {
		return fmt.Errorf("destruction completed with errors: %s", strings.Join(errors, "; "))
	}

	om.logger.Info("Orchestrated VM destroyed successfully", zap.String("vm_name", vmName))
	return nil
}

// ListOrchestratedVMs lists all orchestrated VMs
func (om *OrchestratedVMManager) ListOrchestratedVMs() ([]*OrchestratedVM, error) {
	return om.consul.ListVMs()
}

// GetVMStatus gets the status of an orchestrated VM
func (om *OrchestratedVMManager) GetVMStatus(vmName string) (*OrchestratedVM, error) {
	vms, err := om.consul.ListVMs()
	if err != nil {
		return nil, fmt.Errorf("failed to list VMs: %w", err)
	}

	for _, vm := range vms {
		if vm.Name == vmName {
			// Get Nomad job status if exists
			jobID := fmt.Sprintf("vm-%s-monitor", vmName)
			if status, err := om.nomad.GetJobStatus(jobID); err == nil {
				vm.NomadJobID = jobID
				vm.Meta["nomad_job_status"] = status
			}

			return vm, nil
		}
	}

	return nil, fmt.Errorf("VM not found: %s", vmName)
}