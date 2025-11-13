package minio

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VerifyDeployment performs comprehensive verification of MinIO deployment
func VerifyDeployment(rc *eos_io.RuntimeContext, opts *DeploymentOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check what needs to be verified
	logger.Info("Assessing MinIO deployment status")

	// INTERVENE - Perform verification checks
	checks := []struct {
		name string
		fn   func(*eos_io.RuntimeContext, *DeploymentOptions) error
	}{
		{"Nomad job status", verifyNomadJob},
		{"Service registration", verifyServiceRegistration},
		{"MinIO health", verifyMinIOHealth},
		{"Vault integration", verifyVaultIntegration},
		{"Storage accessibility", verifyStorageAccess},
	}

	var errors []string
	for _, check := range checks {
		logger.Info("Running verification check",
			zap.String("check", check.name))

		if err := check.fn(rc, opts); err != nil {
			logger.Error("Verification check failed",
				zap.String("check", check.name),
				zap.Error(err))
			errors = append(errors, fmt.Sprintf("%s: %v", check.name, err))
		} else {
			logger.Info("Verification check passed",
				zap.String("check", check.name))
		}
	}

	// EVALUATE - Determine overall status
	if len(errors) > 0 {
		return eos_err.NewUserError(
			"MinIO deployment verification failed:\n%s\n\n"+
				"Troubleshooting steps:\n"+
				"1. Check Nomad job status: nomad job status minio\n"+
				"2. Check Nomad allocation logs: nomad alloc logs <alloc-id>\n"+
				"3. Verify Consul service: consul catalog services\n"+
				"4. Check system logs: journalctl -u nomad -u consul",
			strings.Join(errors, "\n"))
	}

	logger.Info("All verification checks passed successfully")
	return nil
}

// verifyNomadJob checks if the Nomad job is running
func verifyNomadJob(rc *eos_io.RuntimeContext, opts *DeploymentOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"job", "status", "-json", "minio"},
		Timeout: HealthCheckTimeout,
	})
	if err != nil {
		return fmt.Errorf("failed to get Nomad job status: %w", err)
	}

	var jobStatus map[string]interface{}
	if err := json.Unmarshal([]byte(output), &jobStatus); err != nil {
		return fmt.Errorf("failed to parse job status: %w", err)
	}

	// Check job is running
	if status, ok := jobStatus["Status"].(string); ok {
		if status != "running" {
			return fmt.Errorf("job status is '%s', expected 'running'", status)
		}
	}

	// Check allocations
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"job", "allocs", "-json", "minio"},
		Timeout: HealthCheckTimeout,
	})
	if err != nil {
		return fmt.Errorf("failed to get job allocations: %w", err)
	}

	var allocs []map[string]interface{}
	if err := json.Unmarshal([]byte(output), &allocs); err != nil {
		return fmt.Errorf("failed to parse allocations: %w", err)
	}

	if len(allocs) == 0 {
		return fmt.Errorf("no allocations found for MinIO job")
	}

	// Check at least one allocation is running
	runningFound := false
	for _, alloc := range allocs {
		if status, ok := alloc["ClientStatus"].(string); ok && status == "running" {
			runningFound = true
			break
		}
	}

	if !runningFound {
		return fmt.Errorf("no running allocations found")
	}

	logger.Debug("Nomad job verification passed",
		zap.Int("allocation_count", len(allocs)))

	return nil
}

// verifyServiceRegistration checks Consul service registration
func verifyServiceRegistration(rc *eos_io.RuntimeContext, opts *DeploymentOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if MinIO service is registered
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "consul",
		Args:    []string{"catalog", "services"},
		Timeout: HealthCheckTimeout,
	})
	if err != nil {
		return fmt.Errorf("failed to query Consul services: %w", err)
	}

	if !strings.Contains(output, "minio") {
		return fmt.Errorf("MinIO service not found in Consul catalog")
	}

	// Get service details
	output, err = execute.Run(rc.Ctx, execute.Options{
		Command: "consul",
		Args:    []string{"catalog", "service", "-json", "minio"},
		Timeout: HealthCheckTimeout,
	})
	if err != nil {
		return fmt.Errorf("failed to get MinIO service details: %w", err)
	}

	var services []map[string]interface{}
	if err := json.Unmarshal([]byte(output), &services); err != nil {
		return fmt.Errorf("failed to parse service details: %w", err)
	}

	if len(services) == 0 {
		return fmt.Errorf("no MinIO service instances found")
	}

	logger.Debug("Consul service verification passed",
		zap.Int("instance_count", len(services)))

	return nil
}

// verifyMinIOHealth checks MinIO health endpoints
func verifyMinIOHealth(rc *eos_io.RuntimeContext, opts *DeploymentOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Try health check with retries
	healthURL := fmt.Sprintf("http://localhost:%d/minio/health/live", opts.APIPort)

	for i := 0; i < HealthCheckRetries; i++ {
		logger.Debug("Attempting MinIO health check",
			zap.Int("attempt", i+1),
			zap.String("url", healthURL))

		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "curl",
			Args:    []string{"-f", "-s", "-m", "5", healthURL},
			Timeout: HealthCheckTimeout,
		})

		if err == nil {
			logger.Debug("MinIO health check passed",
				zap.String("response", output))
			return nil
		}

		if i < HealthCheckRetries-1 {
			logger.Debug("Health check failed, retrying",
				zap.Error(err),
				zap.Duration("retry_delay", HealthCheckRetryDelay))
			time.Sleep(HealthCheckRetryDelay)
		}
	}

	return fmt.Errorf("MinIO health check failed after %d attempts", HealthCheckRetries)
}

// verifyVaultIntegration checks if credentials are accessible from Vault
func verifyVaultIntegration(rc *eos_io.RuntimeContext, opts *DeploymentOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "vault",
		Args:    []string{"kv", "get", "-format=json", VaultMinIOPath},
		Timeout: HealthCheckTimeout,
	})
	if err != nil {
		return fmt.Errorf("failed to retrieve MinIO credentials from Vault: %w", err)
	}

	var vaultData map[string]interface{}
	if err := json.Unmarshal([]byte(output), &vaultData); err != nil {
		return fmt.Errorf("failed to parse Vault response: %w", err)
	}

	// Check if data exists
	if data, ok := vaultData["data"].(map[string]interface{}); ok {
		if secretData, ok := data["data"].(map[string]interface{}); ok {
			if _, hasUser := secretData["root_user"]; !hasUser {
				return fmt.Errorf("root_user not found in Vault secret")
			}
			if _, hasPass := secretData["root_password"]; !hasPass {
				return fmt.Errorf("root_password not found in Vault secret")
			}
		} else {
			return fmt.Errorf("secret data not found in Vault response")
		}
	} else {
		return fmt.Errorf("invalid Vault response format")
	}

	logger.Debug("Vault integration verification passed")
	return nil
}

// verifyStorageAccess checks if MinIO can access its storage path
func verifyStorageAccess(rc *eos_io.RuntimeContext, opts *DeploymentOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if MinIO has created its data directory structure
	minioDataPath := fmt.Sprintf("%s/.minio.sys", opts.StoragePath)

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ls",
		Args:    []string{"-la", minioDataPath},
		Timeout: HealthCheckTimeout,
	})

	if err != nil {
		logger.Warn("MinIO system directory not found (may not have been accessed yet)",
			zap.String("path", minioDataPath),
			zap.Error(err))
		// This is not a critical error as MinIO might not have written data yet
		return nil
	}

	logger.Debug("Storage access verification passed",
		zap.String("output", output))

	return nil
}

// DisplayAccessInfo shows how to access and use MinIO
func DisplayAccessInfo(rc *eos_io.RuntimeContext, opts *DeploymentOptions) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("=== MinIO Deployment Successful ===")
	logger.Info("Access Information:",
		zap.String("API_Endpoint", fmt.Sprintf("http://localhost:%d", opts.APIPort)),
		zap.String("Console_URL", fmt.Sprintf("http://localhost:%d", opts.ConsolePort)))

	logger.Info("To retrieve credentials:")
	logger.Info("terminal prompt: vault kv get kv/minio/root")

	logger.Info("To configure MinIO client (mc):")
	logger.Info("terminal prompt: export MINIO_ROOT_USER=$(vault kv get -field=root_user kv/minio/root)")
	logger.Info("terminal prompt: export MINIO_ROOT_PASSWORD=$(vault kv get -field=root_password kv/minio/root)")
	logger.Info("terminal prompt: mc alias set local http://localhost:9123 $MINIO_ROOT_USER $MINIO_ROOT_PASSWORD")

	logger.Info("To create a bucket:")
	logger.Info("terminal prompt: mc mb local/my-bucket")

	logger.Info("To monitor MinIO:")
	logger.Info("terminal prompt: nomad alloc logs -f $(nomad job allocs -json minio | jq -r '.[0].ID')")
}
