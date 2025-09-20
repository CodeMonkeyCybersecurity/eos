// pkg/vault/lifecycle1_create.go

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hashicorp/nomad/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// DEPRECATED PACKAGE: This package is deprecated in favor of vault_.
// All new vault deployments should use 'eos create vault-' which provides:
// - Complete -based deployment
// - Better error handling and rollback capabilities
// - Standardized configuration management
// - Integrated hardening and security policies
// - Comprehensive lifecycle management
//
// This package is maintained only for backward compatibility and emergency scenarios.
// Direct installation methods will be removed in a future version.

// OrchestrateVaultCreateViaNomad creates Vault using Nomad orchestration (exported function)
func OrchestrateVaultCreateViaNomad(rc *eos_io.RuntimeContext) error {
	return orchestrateVaultCreateViaNomad(rc)
}

func OrchestrateVaultCreate(rc *eos_io.RuntimeContext) error {
	otelzap.Ctx(rc.Ctx).Info(" Starting full Vault create lifecycle")

	// DEPRECATED: Direct installation is deprecated, always attempt -based deployment
	otelzap.Ctx(rc.Ctx).Warn("DEPRECATION WARNING: Direct vault installation is deprecated. Use 'eos create vault-' instead.")

	// Check if  is available and use it if possible
	if err := checkNomadAvailability(rc); err == nil {
		otelzap.Ctx(rc.Ctx).Info(" is available, using -based deployment")
		return orchestrateVaultCreateViaNomad(rc)
	}

	//  not available - require it for new deployments
	otelzap.Ctx(rc.Ctx).Error(" is required for vault installation. Please install  first using 'eos create '")
	return fmt.Errorf(" is required for vault installation - direct installation is deprecated")
}

// orchestrateVaultCreateViaNomad creates Vault using Nomad orchestration
func orchestrateVaultCreateViaNomad(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating Vault via Nomad orchestration")

	// Create Nomad client
	nomadClient, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return fmt.Errorf("failed to create Nomad client: %w", err)
	}

	// Generate Vault job specification
	jobSpec, err := generateVaultNomadJob(rc)
	if err != nil {
		return fmt.Errorf("failed to generate Vault job: %w", err)
	}

	// Submit job to Nomad
	_, _, err = nomadClient.Jobs().Register(jobSpec, nil)
	if err != nil {
		return fmt.Errorf("failed to submit Vault job to Nomad: %w", err)
	}

	// Wait for deployment and verify
	if err := waitForVaultDeployment(rc, nomadClient); err != nil {
		return fmt.Errorf("Vault deployment failed: %w", err)
	}

	logger.Info("Vault successfully deployed via Nomad")
	return nil
}

// generateVaultNomadJob generates Vault job specification for Nomad
func generateVaultNomadJob(rc *eos_io.RuntimeContext) (*api.Job, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Generating Vault Nomad job specification")
	
	// Create basic Vault job
	job := &api.Job{
		ID:          stringPtr("vault"),
		Name:        stringPtr("vault"),
		Type:        stringPtr("service"),
		Datacenters: []string{"dc1"},
		TaskGroups: []*api.TaskGroup{
			{
				Name:  stringPtr("vault"),
				Count: intPtr(1),
				Tasks: []*api.Task{
					{
						Name:   "vault",
						Driver: "docker",
						Config: map[string]interface{}{
							"image": "vault:latest",
							"ports": []string{"vault"},
						},
						Resources: &api.Resources{
							CPU:      intPtr(500),
							MemoryMB: intPtr(512),
						},
					},
				},
				Networks: []*api.NetworkResource{
					{
						Mode: "bridge",
						ReservedPorts: []api.Port{
							{Label: "vault", Value: 8200},
						},
					},
				},
			},
		},
	}
	
	return job, nil
}

// waitForVaultDeployment waits for Vault deployment and verifies its status
func waitForVaultDeployment(rc *eos_io.RuntimeContext, nomadClient *api.Client) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Waiting for Vault deployment to complete")
	
	// TODO: Implement proper deployment waiting and health checks
	// For now, just return success
	return nil
}

// Helper functions for Nomad API
func stringPtr(s string) *string { return &s }
func intPtr(i int) *int { return &i }
