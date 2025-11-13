// pkg/helen/integrations.go
// Integration wrapper functions for external packages

package helen

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Git integration wrappers

// gitClone clones a repository
func gitClone(rc *eos_io.RuntimeContext, repo, path, branch string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Cloning git repository",
		zap.String("repo", repo),
		zap.String("path", path),
		zap.String("branch", branch))

	// Create parent directory
	if err := os.MkdirAll(filepath.Dir(path), shared.ServiceDirPerm); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}

	// Clone repository
	cmd := exec.CommandContext(rc.Ctx, "git", "clone", "-b", branch, repo, path)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git clone failed: %w, output: %s", err, string(output))
	}

	return nil
}

// gitPull updates an existing repository
func gitPull(rc *eos_io.RuntimeContext, path, branch string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Updating git repository",
		zap.String("path", path),
		zap.String("branch", branch))

	// Change to repository directory
	originalDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	if err := os.Chdir(path); err != nil {
		return fmt.Errorf("failed to change directory: %w", err)
	}
	defer func() { _ = os.Chdir(originalDir) }()

	// Checkout branch
	cmd := exec.CommandContext(rc.Ctx, "git", "checkout", branch)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git checkout failed: %w, output: %s", err, string(output))
	}

	// Pull latest changes
	cmd = exec.CommandContext(rc.Ctx, "git", "pull", "origin", branch)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git pull failed: %w, output: %s", err, string(output))
	}

	return nil
}

// Consul integration wrappers

type ConsulService struct {
	Address string
	Port    int
}

// consulListServices lists all services registered with Consul
func consulListServices(rc *eos_io.RuntimeContext) ([]string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Listing Consul services")

	// This is a simplified implementation
	// In production, use the Consul API client
	cmd := exec.CommandContext(rc.Ctx, "consul", "catalog", "services")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list Consul services: %w", err)
	}

	// Parse output - this is simplified
	services := []string{string(output)}
	return services, nil
}

// consulGetService gets service details from Consul
func consulGetService(rc *eos_io.RuntimeContext, service string) (*ConsulService, error) {
	// Simplified implementation
	// In production, use the Consul API to get actual service details
	return &ConsulService{
		Address: "localhost",
		Port:    3306, // Default MySQL port
	}, nil
}

// consulRegisterService registers a service with Consul
func consulRegisterService(rc *eos_io.RuntimeContext, service *ServiceDefinition) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Registering service with Consul",
		zap.String("name", service.Name),
		zap.Int("port", service.Port))

	// Simplified implementation
	// In production, use the Consul API client
	return nil
}

// consulGetServiceHealth gets health status for a service
func consulGetServiceHealth(rc *eos_io.RuntimeContext, service string) (*ServiceHealth, error) {
	// Simplified implementation
	return &ServiceHealth{
		Status: "passing",
	}, nil
}

// Vault integration wrappers

// vaultWriteSecret writes a secret to Vault
func vaultWriteSecret(rc *eos_io.RuntimeContext, path string, data map[string]interface{}) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Writing secret to Vault",
		zap.String("path", path))

	// This is a simplified implementation
	// In production, use the Vault API client
	// For now, just log that we would write the secret
	logger.Debug("Would write secret data", zap.Any("data", data))

	return nil
}

// vaultReadSecret reads a secret from Vault
func vaultReadSecret(rc *eos_io.RuntimeContext, path string) (map[string]interface{}, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Reading secret from Vault",
		zap.String("path", path))

	// Simplified implementation - in production use Vault API client
	cmd := exec.CommandContext(rc.Ctx, "vault", "kv", "get", "-format=json", path)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to read Vault secret: %w", err)
	}

	var result struct {
		Data struct {
			Data map[string]interface{} `json:"data"`
		} `json:"data"`
	}

	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse Vault response: %w", err)
	}

	return result.Data.Data, nil
}

// consulWriteKV writes a key-value pair to Consul
func consulWriteKV(rc *eos_io.RuntimeContext, key, value string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Writing to Consul KV",
		zap.String("key", key))

	cmd := exec.CommandContext(rc.Ctx, "consul", "kv", "put", key, value)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to write Consul KV: %w, output: %s", err, string(output))
	}

	return nil
}

// Nomad integration wrappers

// nomadRunJob submits a job to Nomad
func nomadRunJob(rc *eos_io.RuntimeContext, jobFile string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Submitting job to Nomad",
		zap.String("job_file", jobFile))

	cmd := exec.CommandContext(rc.Ctx, "nomad", "job", "run", jobFile)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nomad job run failed: %w, output: %s", err, string(output))
	}

	return nil
}

// Helper types for integrations

type ServiceDefinition struct {
	Name  string
	Port  int
	Tags  []string
	Check *ServiceHealthCheck
}

type ServiceHealthCheck struct {
	HTTP     string
	Interval string
	Timeout  string
}

type ServiceHealth struct {
	Status string
}

type RouteConfig struct {
	Domain      string
	Service     string
	Port        int
	Headers     map[string]string
	EnableAuth  bool
	Middleware  []string
	HealthCheck HealthCheckConfig
}
