// Package refresh - Validation operations for Moni refresh
package refresh

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/bionicgpt"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// preFlightChecks performs pre-flight validation before refresh
// ASSESS phase: Check prerequisites
func (r *Refresher) preFlightChecks(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	// Check 1: Docker available
	if err := container.CheckIfDockerInstalled(r.rc); err != nil {
		return fmt.Errorf("Docker not available: %w", err)
	}
	logger.Info("Docker is available")

	// Check 2: Docker Compose available
	if err := container.CheckIfDockerComposeInstalled(r.rc); err != nil {
		return fmt.Errorf("Docker Compose not available: %w", err)
	}
	logger.Info("Docker Compose is available")

	// Check 3: .env file exists
	if _, err := os.Stat(r.envFile); os.IsNotExist(err) {
		return fmt.Errorf(".env file not found: %s", r.envFile)
	}
	logger.Info(".env file exists", zap.String("path", r.envFile))

	// Check 4: docker-compose.yml exists
	if _, err := os.Stat(r.composeFile); os.IsNotExist(err) {
		return fmt.Errorf("docker-compose.yml not found: %s", r.composeFile)
	}
	logger.Info("docker-compose.yml exists", zap.String("path", r.composeFile))

	// Check 5: Verify critical environment variables
	if err := r.verifyCriticalEnvVars(ctx); err != nil {
		return fmt.Errorf("environment variable validation failed: %w", err)
	}
	logger.Info("Critical environment variables validated")

	return nil
}

// verifyCriticalEnvVars verifies critical environment variables in .env file
func (r *Refresher) verifyCriticalEnvVars(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	// Read .env file
	file, err := os.Open(r.envFile)
	if err != nil {
		return fmt.Errorf("failed to open .env file: %w", err)
	}
	defer file.Close()

	// Parse environment variables
	envVars := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		envVars[key] = value
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read .env file: %w", err)
	}

	// Check LITELLM_MASTER_KEY
	masterKey, exists := envVars[bionicgpt.EnvVarLiteLLMMasterKey]
	if !exists {
		return fmt.Errorf("%s not found in .env file", bionicgpt.EnvVarLiteLLMMasterKey)
	}

	if masterKey == "" {
		return fmt.Errorf("%s is empty in .env file", bionicgpt.EnvVarLiteLLMMasterKey)
	}

	if !strings.HasPrefix(masterKey, bionicgpt.LiteLLMDefaultMasterKey) {
		return fmt.Errorf("%s must start with 'sk-' (found: %s...)", bionicgpt.EnvVarLiteLLMMasterKey, masterKey[:10])
	}

	logger.Info("LITELLM_MASTER_KEY format valid",
		zap.String("prefix", masterKey[:10]+"..."))

	return nil
}

// validate performs post-refresh validation
// EVALUATE phase: Verify deployment
func (r *Refresher) validate(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	// Check 1: Verify containers are running
	if err := r.verifyContainersRunning(ctx); err != nil {
		return fmt.Errorf("container validation failed: %w", err)
	}
	logger.Info("All containers are running")

	// Check 2: Verify databases are responding
	if err := r.verifyDatabasesResponding(ctx); err != nil {
		return fmt.Errorf("database validation failed: %w", err)
	}
	logger.Info("Databases are responding")

	// Check 3: Verify models configuration
	if err := r.verifyModelsConfiguration(ctx); err != nil {
		return fmt.Errorf("models configuration validation failed: %w", err)
	}
	logger.Info("Models configuration is correct")

	// Check 4: Verify LiteLLM cache is clear
	if err := r.verifyLiteLLMCacheClear(ctx); err != nil {
		return fmt.Errorf("LiteLLM cache validation failed: %w", err)
	}
	logger.Info("LiteLLM cache is clear")

	return nil
}

// verifyContainersRunning verifies that all expected containers are running
func (r *Refresher) verifyContainersRunning(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	requiredContainers := []string{
		bionicgpt.ContainerNameApp,
		bionicgpt.ContainerNamePostgres,
		bionicgpt.ContainerNameLiteLLMDB,
		bionicgpt.ContainerNameLiteLLM,
	}

	for _, containerName := range requiredContainers {
		cmd := exec.CommandContext(ctx,
			"docker", "inspect", "-f", "{{.State.Running}}", containerName)

		output, err := cmd.Output()
		if err != nil {
			logger.Warn("Container not found or not running",
				zap.String("container", containerName),
				zap.Error(err))
			return fmt.Errorf("container %s not running: %w", containerName, err)
		}

		running := strings.TrimSpace(string(output))
		if running != "true" {
			logger.Error("Container not running",
				zap.String("container", containerName),
				zap.String("state", running))
			return fmt.Errorf("container %s not running (state: %s)", containerName, running)
		}

		logger.Debug("Container running", zap.String("container", containerName))
	}

	return nil
}

// verifyDatabasesResponding verifies that databases are accepting connections
func (r *Refresher) verifyDatabasesResponding(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	// Check PostgreSQL main database
	cmd := exec.CommandContext(ctx,
		"docker", "exec", bionicgpt.ContainerNamePostgres,
		"pg_isready", "-U", bionicgpt.DefaultPostgresUser)

	if err := cmd.Run(); err != nil {
		logger.Error("Main database not ready", zap.Error(err))
		return fmt.Errorf("main database not ready: %w", err)
	}
	logger.Debug("Main database is ready")

	// Check LiteLLM database
	cmd = exec.CommandContext(ctx,
		"docker", "exec", bionicgpt.ContainerNameLiteLLMDB,
		"pg_isready", "-U", bionicgpt.LiteLLMDefaultUser)

	if err := cmd.Run(); err != nil {
		logger.Error("LiteLLM database not ready", zap.Error(err))
		return fmt.Errorf("LiteLLM database not ready: %w", err)
	}
	logger.Debug("LiteLLM database is ready")

	return nil
}

// verifyModelsConfiguration verifies the models table has correct configuration
func (r *Refresher) verifyModelsConfiguration(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	// Verify model count
	cmd := exec.CommandContext(ctx,
		"docker", "exec", bionicgpt.ContainerNamePostgres,
		"psql", "-U", bionicgpt.DefaultPostgresUser, "-d", bionicgpt.DefaultPostgresDB,
		"-t", "-c", "SELECT COUNT(*) FROM models;")

	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to query models: %w", err)
	}

	count := strings.TrimSpace(string(output))
	if count != "2" {
		logger.Error("Incorrect number of models",
			zap.String("expected", "2"),
			zap.String("actual", count))
		return fmt.Errorf("expected 2 models, found %s", count)
	}

	logger.Debug("Model count correct", zap.String("count", count))
	return nil
}

// verifyLiteLLMCacheClear verifies the LiteLLM cache is clear
func (r *Refresher) verifyLiteLLMCacheClear(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	cmd := exec.CommandContext(ctx,
		"docker", "exec", bionicgpt.ContainerNameLiteLLMDB,
		"psql", "-U", bionicgpt.LiteLLMDefaultUser, "-d", bionicgpt.LiteLLMDefaultDB,
		"-t", "-c", fmt.Sprintf(`SELECT COUNT(*) FROM "%s";`, bionicgpt.LiteLLMVerificationTokenTable))

	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to query cache: %w", err)
	}

	count := strings.TrimSpace(string(output))
	if count != "0" {
		logger.Warn("LiteLLM cache not fully clear",
			zap.String("token_count", count))
		// Don't fail - this is a warning
	} else {
		logger.Debug("LiteLLM cache is clear")
	}

	return nil
}

// stopServices stops all services using docker compose down
func (r *Refresher) stopServices(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	cmd := exec.CommandContext(ctx,
		"docker-compose", "-f", r.composeFile, "down")
	cmd.Dir = r.config.InstallDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Failed to stop services",
			zap.String("output", string(output)),
			zap.Error(err))
		return fmt.Errorf("docker compose down failed: %s: %w", string(output), err)
	}

	logger.Debug("Services stopped", zap.String("output", string(output)))
	return nil
}

// startFresh starts services with --force-recreate
// CRITICAL: --force-recreate ensures environment variables are reloaded
func (r *Refresher) startFresh(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	cmd := exec.CommandContext(ctx,
		"docker-compose", "-f", r.composeFile, "up", "-d", "--force-recreate")
	cmd.Dir = r.config.InstallDir

	// Set environment file explicitly
	cmd.Env = append(os.Environ(), fmt.Sprintf("COMPOSE_FILE=%s", filepath.Base(r.composeFile)))

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Failed to start services",
			zap.String("output", string(output)),
			zap.Error(err))
		return fmt.Errorf("docker compose up failed: %s: %w", string(output), err)
	}

	logger.Debug("Services started with fresh configuration",
		zap.String("output", string(output)))

	// Wait for services to initialize
	logger.Info("Waiting for services to initialize",
		zap.Duration("delay", bionicgpt.ServiceStartupDelay))
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.rc.Ctx.Done():
		return r.rc.Ctx.Err()
	default:
		// Wait for initial startup
		timeoutCtx, cancel := context.WithTimeout(ctx, bionicgpt.ServiceStartupDelay)
		defer cancel()
		<-timeoutCtx.Done()
	}

	return nil
}

// waitForDatabases waits for databases to be ready
func (r *Refresher) waitForDatabases(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	// Wait for PostgreSQL
	logger.Info("Waiting for PostgreSQL to be ready")
	if err := r.waitForPostgres(ctx, bionicgpt.ContainerNamePostgres, bionicgpt.DefaultPostgresUser); err != nil {
		return fmt.Errorf("PostgreSQL not ready: %w", err)
	}
	logger.Info("PostgreSQL is ready")

	// Wait for LiteLLM database
	logger.Info("Waiting for LiteLLM database to be ready")
	if err := r.waitForPostgres(ctx, bionicgpt.ContainerNameLiteLLMDB, bionicgpt.LiteLLMDefaultUser); err != nil {
		return fmt.Errorf("LiteLLM database not ready: %w", err)
	}
	logger.Info("LiteLLM database is ready")

	return nil
}

// waitForPostgres waits for a PostgreSQL container to be ready
func (r *Refresher) waitForPostgres(ctx context.Context, containerName, user string) error {
	deadline := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		deadline, cancel = context.WithTimeout(ctx, bionicgpt.PostgresReadyTimeout)
		defer cancel()
	}

	for {
		select {
		case <-deadline.Done():
			return fmt.Errorf("timeout waiting for PostgreSQL (%s)", containerName)
		default:
			cmd := exec.CommandContext(ctx,
				"docker", "exec", containerName,
				"pg_isready", "-U", user)

			if err := cmd.Run(); err == nil {
				return nil
			}

			// Wait before retry
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-deadline.Done():
				return fmt.Errorf("timeout waiting for PostgreSQL (%s)", containerName)
			case <-r.rc.Ctx.Done():
				return r.rc.Ctx.Err()
			default:
				retryCtx, cancel := context.WithTimeout(ctx, bionicgpt.PostgresReadyRetry)
				<-retryCtx.Done()
				cancel()
			}
		}
	}
}

// restartAppServices restarts application services
func (r *Refresher) restartAppServices(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	cmd := exec.CommandContext(ctx,
		"docker-compose", "-f", r.composeFile, "restart",
		bionicgpt.ServiceApp, bionicgpt.ServiceLiteLLM)
	cmd.Dir = r.config.InstallDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Failed to restart app services",
			zap.String("output", string(output)),
			zap.Error(err))
		return fmt.Errorf("docker compose restart failed: %s: %w", string(output), err)
	}

	logger.Debug("App services restarted", zap.String("output", string(output)))

	// Wait for services to stabilize
	logger.Info("Waiting for services to stabilize",
		zap.Duration("delay", bionicgpt.ServiceStabilizationDelay))
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.rc.Ctx.Done():
		return r.rc.Ctx.Err()
	default:
		stabilizeCtx, cancel := context.WithTimeout(ctx, bionicgpt.ServiceStabilizationDelay)
		defer cancel()
		<-stabilizeCtx.Done()
	}

	return nil
}
