// Package bionicgpt provides post-deployment verification for shift-left quality assurance
//
// This module implements comprehensive verification after deployment completes.
// Following shift-left principles: verify immediately, report comprehensively, fail clearly.
//
// Verification Checks:
//   1. All containers running
//   2. Database user creation succeeded
//   3. LiteLLM proxy responding
//   4. Application web interface accessible
//   5. Health endpoints working
//   6. Log files for errors
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."
package bionicgpt

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PostDeploymentVerification performs comprehensive checks after deployment
type PostDeploymentVerification struct {
	ContainersRunning       bool
	DatabaseUserExists      bool
	LiteLLMResponding       bool
	AppWebInterfaceUp       bool
	HealthEndpointsWorking  bool
	NoErrorsInLogs          bool
	Issues                  []string
	Warnings                []string
}

// runPostDeploymentVerification performs comprehensive verification after deployment
func (bgi *BionicGPTInstaller) runPostDeploymentVerification(ctx context.Context) (*PostDeploymentVerification, error) {
	logger := otelzap.Ctx(ctx)

	logger.Info("════════════════════════════════════════════════════════════════")
	logger.Info("Post-Deployment Verification")
	logger.Info("Verifying deployment completed successfully...")
	logger.Info("════════════════════════════════════════════════════════════════")

	verification := &PostDeploymentVerification{
		Issues:   []string{},
		Warnings: []string{},
	}

	// Check 1: All containers running
	logger.Info("CHECK 1: Container Status")
	verification.ContainersRunning = bgi.verifyContainersRunning(ctx, verification)

	// Check 2: Database user exists
	logger.Info("CHECK 2: Database User Creation")
	verification.DatabaseUserExists = bgi.verifyDatabaseUser(ctx, verification)

	// Check 3: LiteLLM proxy responding
	logger.Info("CHECK 3: LiteLLM Proxy")
	verification.LiteLLMResponding = bgi.verifyLiteLLMProxy(ctx, verification)

	// Check 4: Application web interface
	logger.Info("CHECK 4: Web Interface")
	verification.AppWebInterfaceUp = bgi.verifyWebInterface(ctx, verification)

	// Check 5: Health endpoints
	logger.Info("CHECK 5: Health Endpoints")
	verification.HealthEndpointsWorking = bgi.verifyHealthEndpoints(ctx, verification)

	// Check 6: Scan logs for errors
	logger.Info("CHECK 6: Error Log Scan")
	verification.NoErrorsInLogs = bgi.scanLogsForErrors(ctx, verification)

	// Summary
	logger.Info("────────────────────────────────────────────────────────────────")

	allPassed := verification.ContainersRunning &&
		verification.DatabaseUserExists &&
		verification.LiteLLMResponding &&
		verification.AppWebInterfaceUp

	if allPassed {
		logger.Info("✓ All post-deployment checks passed",
			zap.Int("warnings", len(verification.Warnings)))
	} else {
		logger.Error("✗ Some post-deployment checks failed",
			zap.Int("issues", len(verification.Issues)),
			zap.Int("warnings", len(verification.Warnings)))

		logger.Info("")
		logger.Error("Issues Found:")
		for _, issue := range verification.Issues {
			logger.Error(fmt.Sprintf("  • %s", issue))
		}
	}

	if len(verification.Warnings) > 0 {
		logger.Info("")
		logger.Info("Warnings:")
		for _, warn := range verification.Warnings {
			logger.Warn(fmt.Sprintf("  • %s", warn))
		}
	}

	logger.Info("════════════════════════════════════════════════════════════════")

	return verification, nil
}

// verifyContainersRunning checks that all expected containers are running
func (bgi *BionicGPTInstaller) verifyContainersRunning(ctx context.Context, v *PostDeploymentVerification) bool {
	logger := otelzap.Ctx(ctx)

	requiredContainers := []string{
		ContainerApp,
		ContainerPostgres,
		ContainerEmbeddings,
		ContainerChunking,
		ContainerLiteLLM,
		ContainerRAGEngine,
	}

	allRunning := true
	for _, container := range requiredContainers {
		output, err := execute.Run(ctx, execute.Options{
			Command: "docker",
			Args:    []string{"ps", "--filter", fmt.Sprintf("name=%s", container), "--format", "{{.Status}}"},
			Capture: true,
		})

		if err != nil || strings.TrimSpace(output) == "" {
			logger.Error(fmt.Sprintf("  ✗ %s: not running", container))
			v.Issues = append(v.Issues, fmt.Sprintf("Container %s not running", container))
			allRunning = false
		} else if strings.Contains(strings.TrimSpace(output), "Up") {
			logger.Info(fmt.Sprintf("  ✓ %s: running", container))
		} else {
			logger.Warn(fmt.Sprintf("  ⚠ %s: %s", container, strings.TrimSpace(output)))
			v.Warnings = append(v.Warnings, fmt.Sprintf("Container %s in unexpected state: %s", container, output))
		}
	}

	return allRunning
}

// verifyDatabaseUser checks that bionic_application user was created
func (bgi *BionicGPTInstaller) verifyDatabaseUser(ctx context.Context, v *PostDeploymentVerification) bool {
	logger := otelzap.Ctx(ctx)

	// Query PostgreSQL for the bionic_application user
	output, err := execute.Run(ctx, execute.Options{
		Command: "docker",
		Args: []string{
			"exec", ContainerPostgres,
			"psql", "-U", "postgres", "-d", bgi.config.PostgresDB,
			"-tAc", "SELECT 1 FROM pg_user WHERE usename='bionic_application'",
		},
		Capture: true,
		Timeout: 10 * time.Second,
	})

	if err != nil {
		logger.Error("  ✗ Could not verify database user", zap.Error(err))
		v.Issues = append(v.Issues, "Could not verify bionic_application user exists")
		return false
	}

	if strings.TrimSpace(output) == "1" {
		logger.Info("  ✓ bionic_application user exists")
		return true
	}

	logger.Error("  ✗ bionic_application user does not exist")
	v.Issues = append(v.Issues, "Database user bionic_application not created")
	return false
}

// verifyLiteLLMProxy checks that LiteLLM proxy is responding
func (bgi *BionicGPTInstaller) verifyLiteLLMProxy(ctx context.Context, v *PostDeploymentVerification) bool {
	logger := otelzap.Ctx(ctx)

	// Try to reach LiteLLM health endpoint
	output, err := execute.Run(ctx, execute.Options{
		Command: "curl",
		Args:    []string{"-s", "-f", fmt.Sprintf("http://localhost:%d/health", bgi.config.LiteLLMPort)},
		Capture: true,
		Timeout: 10 * time.Second,
	})

	if err != nil {
		logger.Warn(fmt.Sprintf("  ⚠ LiteLLM health endpoint not responding (this may be normal during startup)"))
		v.Warnings = append(v.Warnings, "LiteLLM proxy not responding to health checks yet")
		return false
	}

	logger.Info(fmt.Sprintf("  ✓ LiteLLM proxy responding on port %d", bgi.config.LiteLLMPort))
	logger.Debug("LiteLLM health response", zap.String("response", output))
	return true
}

// verifyWebInterface checks that the application web interface is accessible
func (bgi *BionicGPTInstaller) verifyWebInterface(ctx context.Context, v *PostDeploymentVerification) bool {
	logger := otelzap.Ctx(ctx)

	// Try to reach the application
	output, err := execute.Run(ctx, execute.Options{
		Command: "curl",
		Args:    []string{"-s", "-o", "/dev/null", "-w", "%{http_code}", fmt.Sprintf("http://localhost:%d", bgi.config.Port)},
		Capture: true,
		Timeout: 10 * time.Second,
	})

	httpCode := strings.TrimSpace(output)

	if err != nil || (httpCode != "200" && httpCode != "302" && httpCode != "301") {
		logger.Warn(fmt.Sprintf("  ⚠ Web interface not responding yet (HTTP %s)", httpCode))
		v.Warnings = append(v.Warnings, fmt.Sprintf("Web interface not accessible yet (HTTP %s)", httpCode))
		return false
	}

	logger.Info(fmt.Sprintf("  ✓ Web interface accessible on port %d (HTTP %s)", bgi.config.Port, httpCode))
	return true
}

// verifyHealthEndpoints checks container health endpoints
func (bgi *BionicGPTInstaller) verifyHealthEndpoints(ctx context.Context, v *PostDeploymentVerification) bool {
	logger := otelzap.Ctx(ctx)

	containersWithHealth := []string{ContainerApp, ContainerPostgres, ContainerLiteLLM}
	allHealthy := true

	for _, container := range containersWithHealth {
		output, err := execute.Run(ctx, execute.Options{
			Command: "docker",
			Args:    []string{"inspect", "--format", "{{.State.Health.Status}}", container},
			Capture: true,
		})

		healthStatus := strings.TrimSpace(output)

		if err != nil || healthStatus == "<no value>" || healthStatus == "" {
			logger.Debug(fmt.Sprintf("  • %s: no health check configured", container))
			continue
		}

		if healthStatus == "healthy" {
			logger.Info(fmt.Sprintf("  ✓ %s: healthy", container))
		} else if healthStatus == "starting" {
			logger.Info(fmt.Sprintf("  ⏳ %s: still starting", container))
			v.Warnings = append(v.Warnings, fmt.Sprintf("%s still starting", container))
		} else {
			logger.Warn(fmt.Sprintf("  ⚠ %s: %s", container, healthStatus))
			v.Warnings = append(v.Warnings, fmt.Sprintf("%s health check: %s", container, healthStatus))
			allHealthy = false
		}
	}

	return allHealthy
}

// scanLogsForErrors checks container logs for obvious errors
func (bgi *BionicGPTInstaller) scanLogsForErrors(ctx context.Context, v *PostDeploymentVerification) bool {
	logger := otelzap.Ctx(ctx)

	criticalContainers := []string{ContainerApp, ContainerLiteLLM, ContainerPostgres}
	foundErrors := false

	for _, container := range criticalContainers {
		// Get last 50 lines of logs
		output, err := execute.Run(ctx, execute.Options{
			Command: "docker",
			Args:    []string{"logs", "--tail", "50", container},
			Capture: true,
			Timeout: 10 * time.Second,
		})

		if err != nil {
			continue
		}

		// Scan for common error patterns
		errorPatterns := []string{
			"FATAL",
			"ERROR",
			"panic:",
			"failed to connect",
			"connection refused",
			"authentication failed",
		}

		for _, pattern := range errorPatterns {
			if strings.Contains(strings.ToLower(output), strings.ToLower(pattern)) {
				logger.Warn(fmt.Sprintf("  ⚠ %s: found '%s' in logs", container, pattern))
				v.Warnings = append(v.Warnings, fmt.Sprintf("%s logs contain '%s'", container, pattern))
				foundErrors = true
				break // Only report once per container
			}
		}
	}

	if !foundErrors {
		logger.Info("  ✓ No critical errors found in logs")
	}

	return !foundErrors
}
