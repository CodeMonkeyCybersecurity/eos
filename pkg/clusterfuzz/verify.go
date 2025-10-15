package clusterfuzz

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VerifyDeployment verifies that ClusterFuzz deployment is functioning correctly
// following the Assess → Intervene → Evaluate pattern
func VerifyDeployment(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS
	logger.Info("Starting deployment verification")

	// INTERVENE - Run verification checks
	checks := []struct {
		name string
		fn   func(*eos_io.RuntimeContext, *Config) error
	}{
		{"Nomad Jobs", verifyNomadJobs},
		{"Database Connection", verifyDatabaseConnection},
		{"Queue Service", verifyQueueService},
		{"Web UI", verifyWebUI},
		{"Bot Registration", verifyBotRegistration},
	}

	var failed []string
	for _, check := range checks {
		logger.Info("Running verification check", zap.String("check", check.name))
		if err := check.fn(rc, config); err != nil {
			logger.Error("Verification check failed",
				zap.String("check", check.name),
				zap.Error(err))
			failed = append(failed, fmt.Sprintf("%s: %v", check.name, err))
		} else {
			logger.Info("Verification check passed", zap.String("check", check.name))
		}
	}

	// EVALUATE
	if len(failed) > 0 {
		return fmt.Errorf("deployment verification failed:\n%s", strings.Join(failed, "\n"))
	}

	logger.Info("All deployment verification checks passed")
	return nil
}

func verifyNomadJobs(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if all expected jobs are running
	expectedJobs := []string{
		"clusterfuzz-core",
		"clusterfuzz-app",
		"clusterfuzz-bots",
	}

	for _, jobName := range expectedJobs {
		output, err := execute.Run(rc.Ctx, execute.Options{
			Command: "nomad",
			Args:    []string{"job", "status", "-address=" + config.NomadAddress, jobName},
		})
		if err != nil {
			return fmt.Errorf("job %s not found: %w", jobName, err)
		}

		// Check if job is running
		if !strings.Contains(output, "running") {
			return fmt.Errorf("job %s is not in running state", jobName)
		}

		logger.Debug("Nomad job verified",
			zap.String("job", jobName),
			zap.String("status", "running"))
	}

	return nil
}

func verifyDatabaseConnection(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Try to connect to the database
	logger.Debug("Verifying database connection",
		zap.String("host", config.DatabaseConfig.Host),
		zap.Int("port", config.DatabaseConfig.Port))

	// Use psql to test connection (for PostgreSQL)
	if config.DatabaseConfig.Type == "postgresql" {
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "psql",
			Args: []string{
				"-h", config.DatabaseConfig.Host,
				"-p", fmt.Sprintf("%d", config.DatabaseConfig.Port),
				"-U", config.DatabaseConfig.Username,
				"-d", config.DatabaseConfig.Database,
				"-c", "SELECT 1",
			},
		})
		if err != nil {
			return fmt.Errorf("database connection failed: %w", err)
		}
	}

	return nil
}

func verifyQueueService(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if queue service is accessible
	logger.Debug("Verifying queue service",
		zap.String("type", config.QueueConfig.Type),
		zap.String("host", config.QueueConfig.Host),
		zap.Int("port", config.QueueConfig.Port))

	// For Redis, use redis-cli to ping
	if config.QueueConfig.Type == "redis" {
		_, err := execute.Run(rc.Ctx, execute.Options{
			Command: "redis-cli",
			Args: []string{
				"-h", config.QueueConfig.Host,
				"-p", fmt.Sprintf("%d", config.QueueConfig.Port),
				"ping",
			},
		})
		if err != nil {
			return fmt.Errorf("redis connection failed: %w", err)
		}
	}

	return nil
}

func verifyWebUI(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if web UI is accessible
	webURL := fmt.Sprintf("http://localhost:9000")
	logger.Debug("Verifying web UI accessibility", zap.String("url", webURL))

	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "curl",
		Args:    []string{"-f", "-s", "-o", "/dev/null", webURL},
	})
	if err != nil {
		return fmt.Errorf("web UI not accessible at %s: %w", webURL, err)
	}

	return nil
}

func verifyBotRegistration(rc *eos_io.RuntimeContext, config *Config) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if bots have registered with the system
	logger.Debug("Verifying bot registration",
		zap.Int("expected_bots", config.BotCount+config.PreemptibleBotCount))

	// This would typically check the ClusterFuzz API or database
	// For now, we'll just check if the bot jobs are running
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "nomad",
		Args:    []string{"job", "status", "-address=" + config.NomadAddress, "clusterfuzz-bots"},
	})
	if err != nil {
		return fmt.Errorf("failed to check bot status: %w", err)
	}

	if !strings.Contains(output, "running") {
		return fmt.Errorf("bots are not running")
	}

	return nil
}

// DisplaySuccessInfo displays deployment success information to the user
func DisplaySuccessInfo(config *Config) {
	logger := zap.NewNop() // Use a no-op logger for display

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt:  ClusterFuzz Deployment Successful!")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Access Points:")
	logger.Info(fmt.Sprintf("terminal prompt:   Web UI: http://%s:9000", config.Domain))
	logger.Info("terminal prompt:   Admin: http://localhost:9000/admin")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Default Credentials:")
	logger.Info("terminal prompt:   Username: admin@example.com")
	logger.Info("terminal prompt:   Password: admin123")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Next Steps:")
	logger.Info("terminal prompt:   1. Access the web UI and change default password")
	logger.Info("terminal prompt:   2. Configure fuzzing targets")
	logger.Info("terminal prompt:   3. Upload test corpus")
	logger.Info("terminal prompt:   4. Monitor fuzzing progress")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Useful Commands:")
	logger.Info("terminal prompt:   View jobs:     nomad job status")
	logger.Info("terminal prompt:   View logs:     nomad alloc logs <alloc-id>")
	logger.Info("terminal prompt:   Scale bots:    nomad job scale clusterfuzz-bots <count>")
}
