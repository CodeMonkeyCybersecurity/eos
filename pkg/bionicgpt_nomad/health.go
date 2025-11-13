// pkg/bionicgpt_nomad/health.go - Phase 8: Health checks

package bionicgpt_nomad

import (
	"fmt"
	"net/http"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/nomad"
	consulapi "github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// WaitForHealthy waits for all services to become healthy
func (ei *EnterpriseInstaller) WaitForHealthy(timeout time.Duration) error {
	logger := otelzap.Ctx(ei.rc.Ctx)

	logger.Info("Phase 8: Waiting for services to become healthy")

	deadline := time.Now().Add(timeout)

	// Step 1: Check Nomad allocations
	logger.Info("  [1/3] Checking Nomad allocations")
	if err := ei.checkNomadAllocations(deadline); err != nil {
		return fmt.Errorf("Nomad allocation check failed: %w", err)
	}
	logger.Info("    ✓ All Nomad allocations running")

	// Step 2: Check Consul health checks
	logger.Info("  [2/3] Checking Consul service health")
	if err := ei.checkConsulHealth(deadline); err != nil {
		return fmt.Errorf("Consul health check failed: %w", err)
	}
	logger.Info("    ✓ All Consul health checks passing")

	// Step 3: Check HTTP endpoint
	logger.Info("  [3/3] Checking HTTP endpoint")
	if err := ei.checkHTTPEndpoint(deadline); err != nil {
		return fmt.Errorf("HTTP endpoint check failed: %w", err)
	}
	logger.Info("    ✓ HTTP endpoint responding")

	logger.Info("✓ All services healthy")
	return nil
}

// checkNomadAllocations verifies all Nomad jobs have running allocations
func (ei *EnterpriseInstaller) checkNomadAllocations(deadline time.Time) error {
	logger := otelzap.Ctx(ei.rc.Ctx)

	zapLogger := zap.NewNop()
	nomadClient, err := nomad.NewClient(ei.config.NomadAddress, zapLogger)
	if err != nil {
		return fmt.Errorf("failed to create Nomad client: %w", err)
	}

	// Jobs to check
	jobs := []string{JobPostgreSQL, JobBionicGPT}
	if ei.config.AzureEndpoint != "" && ei.config.AzureChatDeployment != "" {
		jobs = append(jobs, JobLiteLLM)
	}
	if ei.config.UseLocalEmbeddings {
		jobs = append(jobs, JobOllama)
	}

	// Check each job
	for _, jobID := range jobs {
		logger.Debug("Checking allocations for job", zap.String("job_id", jobID))

		for time.Now().Before(deadline) {
			allocs, err := nomadClient.GetAllocations(ei.rc.Ctx, jobID)
			if err != nil {
				logger.Warn("Failed to get allocations", zap.String("job_id", jobID), zap.Error(err))
				time.Sleep(5 * time.Second)
				continue
			}

			// Check if all allocations are running
			allRunning := true
			for _, alloc := range allocs {
				if alloc.ClientStatus != "running" {
					allRunning = false
					break
				}
			}

			if allRunning && len(allocs) > 0 {
				logger.Debug("Job allocations running", zap.String("job_id", jobID), zap.Int("count", len(allocs)))
				break
			}

			time.Sleep(5 * time.Second)
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for job %s allocations to be running", jobID)
		}
	}

	return nil
}

// checkConsulHealth verifies Consul health checks are passing
func (ei *EnterpriseInstaller) checkConsulHealth(deadline time.Time) error {
	logger := otelzap.Ctx(ei.rc.Ctx)

	// Create Consul client
	config := consulapi.DefaultConfig()
	config.Address = ei.config.ConsulAddress
	consulClient, err := consulapi.NewClient(config)
	if err != nil {
		return fmt.Errorf("failed to create Consul client: %w", err)
	}

	// Services to check
	services := []string{
		ServiceBionicGPT,
		ServiceOAuth2Proxy,
		ServicePostgreSQL,
	}
	if ei.config.AzureEndpoint != "" && ei.config.AzureChatDeployment != "" {
		services = append(services, ServiceLiteLLM)
	}
	if ei.config.UseLocalEmbeddings {
		services = append(services, ServiceOllama)
	}

	// Check each service
	for _, serviceName := range services {
		logger.Debug("Checking Consul health for service", zap.String("service", serviceName))

		for time.Now().Before(deadline) {
			checks, _, err := consulClient.Health().Checks(serviceName, nil)
			if err != nil {
				logger.Warn("Failed to get health checks", zap.String("service", serviceName), zap.Error(err))
				time.Sleep(5 * time.Second)
				continue
			}

			if len(checks) == 0 {
				logger.Debug("No health checks registered yet", zap.String("service", serviceName))
				time.Sleep(5 * time.Second)
				continue
			}

			// Check if all checks are passing
			allPassing := true
			for _, check := range checks {
				if check.Status != "passing" {
					allPassing = false
					logger.Debug("Health check not passing",
						zap.String("service", serviceName),
						zap.String("check", check.Name),
						zap.String("status", check.Status))
					break
				}
			}

			if allPassing {
				logger.Debug("Service healthy in Consul", zap.String("service", serviceName), zap.Int("checks", len(checks)))
				break
			}

			time.Sleep(5 * time.Second)
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for service %s health checks to pass", serviceName)
		}
	}

	return nil
}

// checkHTTPEndpoint verifies the public endpoint is responding
func (ei *EnterpriseInstaller) checkHTTPEndpoint(deadline time.Time) error {
	logger := otelzap.Ctx(ei.rc.Ctx)

	url := fmt.Sprintf("https://%s/", ei.config.Domain)
	logger.Debug("Checking HTTP endpoint", zap.String("url", url))

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Follow redirects (Authentik will redirect to login)
			return nil
		},
	}

	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err != nil {
			logger.Debug("HTTP request failed", zap.Error(err))
			time.Sleep(5 * time.Second)
			continue
		}
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
			logger.Debug("HTTP endpoint responding", zap.Int("status_code", resp.StatusCode))
			return nil
		}

		logger.Debug("HTTP endpoint returned non-success status", zap.Int("status_code", resp.StatusCode))
		time.Sleep(5 * time.Second)
	}

	return fmt.Errorf("timeout waiting for HTTP endpoint %s to respond", url)
}
