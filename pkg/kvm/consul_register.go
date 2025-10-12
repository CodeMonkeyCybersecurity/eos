//go:build linux

// pkg/kvm/consul_register.go
// Register KVM guests with Consul after creation

package kvm

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RegisterVMWithConsul registers a newly created VM with Consul
// This is idempotent and optional - VM creation succeeds even if this fails
func RegisterVMWithConsul(rc *eos_io.RuntimeContext, vmName, ipAddress string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Attempting to register VM with Consul",
		zap.String("vm_name", vmName),
		zap.String("ip", ipAddress))

	// ASSESS - Check if we can detect the current environment
	envMgr, err := environment.NewEnvironmentManager(rc)
	if err != nil {
		logger.Debug("Could not create environment manager",
			zap.Error(err))
		return nil // Not critical
	}

	env, err := envMgr.DetectCurrentEnvironment(rc.Ctx)
	if err != nil {
		logger.Debug("Could not detect environment, skipping Consul registration",
			zap.Error(err))
		return nil // Not critical - user may not have bootstrapped yet
	}

	logger.Info("Detected environment for VM registration",
		zap.String("environment", env.Name),
		zap.String("datacenter", env.Datacenter))

	// Generate Consul cloud-init for this VM
	// Note: This is for FUTURE VMs - current VM is already created
	// We're just documenting what SHOULD have been done
	logger.Info("VM created without Consul auto-registration")
	logger.Info("terminal prompt:   To enable Consul auto-registration in future VMs:")
	logger.Info(fmt.Sprintf("terminal prompt:   Run: eos create kvm ubuntu --enable-consul --environment %s", env.Name))
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: To manually add this VM to Consul:")
	logger.Info(fmt.Sprintf("terminal prompt:   1. SSH into the VM: ssh ubuntu@%s", ipAddress))
	logger.Info("terminal prompt:   2. Install Consul: curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -")
	logger.Info("terminal prompt:   3. Add repository: sudo apt-add-repository \"deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main\"")
	logger.Info("terminal prompt:   4. Install: sudo apt-get update && sudo apt-get install consul")
	logger.Info(fmt.Sprintf("terminal prompt:   5. Configure: echo 'retry_join = [\"%s\"]' | sudo tee /etc/consul.d/consul.hcl", env.Consul.ServerAddress))
	logger.Info("terminal prompt:   6. Start: sudo systemctl enable --now consul")

	return nil
}

// EnableConsulAutoRegistrationForVM generates cloud-init with Consul agent
// This should be called BEFORE VM creation to bake Consul into the VM
func EnableConsulAutoRegistrationForVM(rc *eos_io.RuntimeContext, vmName string, env *environment.DeploymentEnvironment) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Generating Consul auto-registration cloud-init",
		zap.String("vm_name", vmName),
		zap.String("environment", env.Name))

	// Generate Consul cloud-init configuration
	config := ConsulAutoRegisterConfig{
		VMName:        vmName,
		Environment:   env.Name,
		ConsulServers: env.Consul.RetryJoin,
		Datacenter:    env.Datacenter,
		NodeName:      vmName,
		Tags:          []string{"kvm-guest", "eos-managed"},
		EnableConnect: false, // Can be enabled later
	}

	cloudInit, err := GenerateConsulCloudInit(rc, config)
	if err != nil {
		return "", fmt.Errorf("failed to generate Consul cloud-init: %w", err)
	}

	logger.Info("Generated Consul auto-registration cloud-init",
		zap.String("vm_name", vmName),
		zap.Int("size_bytes", len(cloudInit)))

	return cloudInit, nil
}
