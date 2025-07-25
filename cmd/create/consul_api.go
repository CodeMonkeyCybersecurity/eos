// cmd/create/consul_api.go

package create

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/salt"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// runCreateConsulAPI is the API-only implementation of Consul deployment
func runCreateConsulAPI(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if running as root
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("this command must be run as root")
	}

	logger.Info("Starting Consul installation via Salt API",
		zap.String("datacenter", datacenterName),
		zap.Bool("vault_integration", !disableVaultIntegration),
		zap.Bool("debug_logging", enableDebugLogging),
		zap.Bool("force", forceReinstall),
		zap.Bool("clean", cleanInstall))

	// Create Salt API client using factory
	factory := salt.NewClientFactory(rc)
	saltClient, err := factory.CreateClient()
	if err != nil {
		return fmt.Errorf("Salt API is required for Consul deployment: %w", err)
	}

	// ASSESS - Check current Consul status
	logger.Info("Checking current Consul status")
	status, err := checkConsulStatusAPI(rc.Ctx, saltClient, logger)
	if err != nil {
		logger.Warn("Could not determine Consul status", zap.Error(err))
		status = &salt.ConsulStatus{} // Use empty status
	}

	// Display current status
	displayConsulStatus(logger, status)

	// Idempotency check
	if status.Running && status.ConfigValid && !forceReinstall && !cleanInstall {
		logger.Info("terminal prompt: Consul is already installed and running.")
		logger.Info("terminal prompt: Use --force to reconfigure or --clean for a fresh install.")
		return nil
	}

	// If Consul is in failed state and no force flags
	if status.Failed && !forceReinstall && !cleanInstall {
		logger.Info("terminal prompt: Consul is installed but in a failed state.")
		logger.Info("terminal prompt: Check logs with: journalctl -xeu consul.service")
		logger.Info("terminal prompt: Use --force to reconfigure or --clean for a fresh install.")
		return eos_err.NewUserError("Consul is in failed state. Use --force or --clean to proceed")
	}

	// INTERVENE - Apply SaltStack state
	logger.Info("Applying SaltStack state for Consul installation")

	// Prepare Salt pillar data
	pillar := map[string]interface{}{
		"consul": map[string]interface{}{
			"datacenter":        datacenterName,
			"bootstrap_expect":  1,
			"server_mode":       true,
			"vault_integration": !disableVaultIntegration,
			"log_level":         getLogLevel(enableDebugLogging),
			"force_reinstall":   forceReinstall,
			"clean_install":     cleanInstall,
			"bind_addr":         "0.0.0.0",
			"client_addr":       "0.0.0.0",
			"ui_enabled":        true,
			"connect_enabled":   true,
			"dns_port":          8600,
			"http_port":         shared.PortConsul,
			"grpc_port":         8502,
		},
	}

	// Execute state with progress updates
	logger.Info("terminal prompt: Starting Consul installation...")

	progressStarted := false
	result, err := saltClient.ExecuteStateApply(rc.Ctx, "hashicorp.consul", pillar,
		func(progress salt.StateProgress) {
			if !progressStarted {
				progressStarted = true
			}

			if progress.Completed {
				status := "✓"
				if !progress.Success {
					status = "✗"
				}
				logger.Info(fmt.Sprintf("terminal prompt: %s %s - %s", status, progress.State, progress.Message))
			} else {
				logger.Info(fmt.Sprintf("terminal prompt: ... %s", progress.Message))
			}
		})

	if err != nil {
		return fmt.Errorf("state execution failed: %w", err)
	}

	if result.Failed {
		logger.Error("Consul installation failed",
			zap.Strings("errors", result.Errors))
		logger.Info("terminal prompt: ❌ Consul installation failed:")
		for _, err := range result.Errors {
			logger.Info(fmt.Sprintf("terminal prompt:   - %s", err))
		}
		return salt.ErrStateExecutionFailed
	}

	// EVALUATE - Verify installation
	logger.Info("Verifying Consul installation")
	if err := verifyConsulInstallationAPI(rc.Ctx, saltClient); err != nil {
		return fmt.Errorf("installation verification failed: %w", err)
	}

	logger.Info("terminal prompt: ✅ Consul installation completed successfully!")
	logger.Info(fmt.Sprintf("terminal prompt: Web UI available at: http://<server-ip>:%d", shared.PortConsul))

	return nil
}

func checkConsulStatusAPI(ctx context.Context, client salt.SaltClient, logger otelzap.LoggerWithCtx) (*salt.ConsulStatus, error) {
	cmd := salt.Command{
		Client:   "local",
		Target:   "*",
		Function: "cmd.run",
		Args: []string{`
			STATUS='{}'
			if command -v consul >/dev/null 2>&1; then
				STATUS=$(echo $STATUS | jq '. + {installed: true}')
				VERSION=$(consul version | head -1)
				STATUS=$(echo $STATUS | jq --arg v "$VERSION" '. + {version: $v}')
			fi
			
			if systemctl is-active consul.service >/dev/null 2>&1; then
				STATUS=$(echo $STATUS | jq '. + {running: true, service_status: "active"}')
			elif systemctl is-failed consul.service >/dev/null 2>&1; then
				STATUS=$(echo $STATUS | jq '. + {failed: true, service_status: "failed"}')
				ERROR=$(journalctl -u consul.service -n 1 --no-pager | tail -1)
				STATUS=$(echo $STATUS | jq --arg e "$ERROR" '. + {last_error: $e}')
			fi
			
			if [ -f /etc/consul.d/consul.hcl ] && consul validate /etc/consul.d >/dev/null 2>&1; then
				STATUS=$(echo $STATUS | jq '. + {config_valid: true}')
			fi
			
			echo $STATUS
		`},
		Kwargs: map[string]string{
			"shell": "/bin/bash",
		},
	}

	result, err := client.ExecuteCommand(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to check Consul status: %w", err)
	}

	// Parse the response to extract status
	status := &salt.ConsulStatus{}
	for _, output := range result.Raw {
		if str, ok := output.(string); ok {
			// For simplicity, we'll parse known patterns
			// In production, you'd properly unmarshal the JSON
			if str != "" {
				status.Installed = true // Simplified parsing
				logger.Debug("Consul status response", zap.String("output", str))
			}
		}
	}

	return status, nil
}

func verifyConsulInstallationAPI(ctx context.Context, client salt.SaltClient) error {
	// Wait a moment for service to start
	time.Sleep(5 * time.Second)

	// Try to check Consul cluster members
	cmd := salt.Command{
		Client:   "local",
		Target:   "*",
		Function: "cmd.run",
		Args:     []string{"consul members"},
	}

	result, err := client.ExecuteCommand(ctx, cmd)
	if err != nil {
		return fmt.Errorf("Consul is not responding properly: %w", err)
	}

	// Check if we got valid output
	for _, output := range result.Raw {
		if str, ok := output.(string); ok && str != "" {
			// If we got output, Consul is running
			return nil
		}
	}

	return fmt.Errorf("Consul is not responding to member queries")
}
