// cmd/debug/openwebui.go
// OpenWebUI installation and runtime diagnostic command

package debug

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var openwebuiDebugCmd = &cobra.Command{
	Use:   "openwebui",
	Short: "Diagnose OpenWebUI installation and runtime issues",
	Long: `Run comprehensive diagnostics on OpenWebUI installation and runtime.

This command tests:
- Container status (OpenWebUI, LiteLLM, PostgreSQL)
- Port bindings and network connectivity
- Health endpoints (OpenWebUI and LiteLLM)
- PostgreSQL readiness
- Container logs (last 50 lines)
- Environment variable configuration
- File permissions

This helps identify issues with the 'eos create openwebui' installation process
and runtime failures.

EXAMPLES:
  # Run diagnostics
  sudo eos debug openwebui

  # Run and save output
  sudo eos debug openwebui > /tmp/openwebui-diagnostic.txt`,

	RunE: eos_cli.Wrap(runOpenWebUIDebug),
}

func runOpenWebUIDebug(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting OpenWebUI installation diagnostics")

	installDir := "/opt/openwebui"
	composeFile := installDir + "/docker-compose.yml"

	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║      OpenWebUI Diagnostic Report                          ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Printf("Generated: %s\n", time.Now().Format(time.RFC1123))
	fmt.Println()

	// Test 1: Container Status
	fmt.Println("══════════════════════════════════════════════════════════")
	fmt.Println("1. CONTAINER STATUS")
	fmt.Println("══════════════════════════════════════════════════════════")
	logger.Debug("Checking container status")

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "-f", composeFile, "ps", "--format", "table"},
		Capture: true,
	})

	if err != nil {
		logger.Warn("Failed to get container status", zap.Error(err), zap.String("output", output))
		fmt.Printf("❌ Failed to get container status: %v\n", err)
		fmt.Println("   Possible causes:")
		fmt.Println("   - OpenWebUI not installed yet (run: sudo eos create openwebui)")
		fmt.Println("   - docker-compose.yml missing or corrupted")
		fmt.Println()
	} else {
		fmt.Println(output)
		logger.Info("Container status retrieved successfully")
	}
	fmt.Println()

	// Test 2: Port Bindings
	fmt.Println("══════════════════════════════════════════════════════════")
	fmt.Println("2. PORT BINDINGS")
	fmt.Println("══════════════════════════════════════════════════════════")
	fmt.Println("Checking if services are listening on expected ports...")
	logger.Debug("Checking port bindings")

	portOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ss",
		Args:    []string{"-tlnp"},
		Capture: true,
	})

	if err != nil {
		logger.Warn("Failed to check ports", zap.Error(err))
		fmt.Printf("❌ Failed to check ports: %v\n", err)
		fmt.Println()
	} else {
		// Filter for relevant ports
		lines := strings.Split(portOutput, "\n")
		found := false
		for _, line := range lines {
			if strings.Contains(line, "8501") || strings.Contains(line, "4000") || strings.Contains(line, "5432") {
				if !found {
					fmt.Println("Port       Status")
					fmt.Println("----       ------")
					found = true
				}
				if strings.Contains(line, "8501") {
					fmt.Println(" 8501    OpenWebUI listening")
				} else if strings.Contains(line, "4000") {
					fmt.Println(" 4000    LiteLLM listening")
				} else if strings.Contains(line, "5432") {
					fmt.Println(" 5432    PostgreSQL listening")
				}
			}
		}
		if !found {
			fmt.Println("❌ No services listening on expected ports (8501, 4000, 5432)")
			fmt.Println("   Containers may not be running or still initializing")
		}
		logger.Info("Port check completed")
	}
	fmt.Println()

	// Test 3: Health Endpoints
	fmt.Println("══════════════════════════════════════════════════════════")
	fmt.Println("3. HEALTH ENDPOINT TESTS")
	fmt.Println("══════════════════════════════════════════════════════════")
	logger.Debug("Testing health endpoints")

	// Test OpenWebUI health
	fmt.Println("Testing OpenWebUI health endpoint (http://localhost:8501/health)...")
	healthOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "curl",
		Args:    []string{"-s", "-o", "/dev/null", "-w", "%{http_code}", "http://localhost:8501/health"},
		Capture: true,
		Timeout: 5 * time.Second,
	})

	if err != nil || healthOutput != "200" {
		logger.Warn("OpenWebUI health check failed",
			zap.Error(err),
			zap.String("status_code", healthOutput))
		fmt.Printf("❌ OpenWebUI health endpoint not responding (HTTP %s)\n", healthOutput)
		fmt.Println("   OpenWebUI may still be initializing or failed to start")
	} else {
		logger.Info("OpenWebUI health check passed")
		fmt.Println(" OpenWebUI health endpoint responding (HTTP 200)")
	}
	fmt.Println()

	// Test LiteLLM health
	fmt.Println("Testing LiteLLM health endpoint (http://localhost:4000/health)...")
	litellmOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "curl",
		Args:    []string{"-s", "-o", "/dev/null", "-w", "%{http_code}", "http://localhost:4000/health"},
		Capture: true,
		Timeout: 5 * time.Second,
	})

	if err != nil || litellmOutput != "200" {
		logger.Warn("LiteLLM health check failed",
			zap.Error(err),
			zap.String("status_code", litellmOutput))
		fmt.Printf("❌ LiteLLM health endpoint not responding (HTTP %s)\n", litellmOutput)
		fmt.Println("   LiteLLM may be crashing or unable to connect to PostgreSQL")
		fmt.Println("   Check logs below for connection errors")
	} else {
		logger.Info("LiteLLM health check passed")
		fmt.Println(" LiteLLM health endpoint responding (HTTP 200)")
	}
	fmt.Println()

	// Test 4: PostgreSQL Readiness
	fmt.Println("══════════════════════════════════════════════════════════")
	fmt.Println("4. DATABASE CONNECTION TEST")
	fmt.Println("══════════════════════════════════════════════════════════")
	logger.Debug("Testing PostgreSQL readiness")

	pgOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"compose", "-f", composeFile, "exec", "-T", "litellmproxy_db", "pg_isready", "-U", "litellm", "-d", "litellm"},
		Capture: true,
		Timeout: 5 * time.Second,
	})

	if err != nil {
		logger.Warn("PostgreSQL readiness check failed",
			zap.Error(err),
			zap.String("output", pgOutput))
		fmt.Printf("❌ PostgreSQL not ready: %s\n", pgOutput)
		fmt.Println("   Database may still be initializing")
	} else {
		logger.Info("PostgreSQL readiness check passed")
		fmt.Println(" PostgreSQL accepting connections")
	}
	fmt.Println()

	// Test 5: Container Logs
	fmt.Println("══════════════════════════════════════════════════════════")
	fmt.Println("5. CONTAINER LOGS (Last 30 lines each)")
	fmt.Println("══════════════════════════════════════════════════════════")
	logger.Debug("Gathering container logs")

	containers := []struct {
		name    string
		service string
	}{
		{"PostgreSQL", "litellmproxy_db"},
		{"LiteLLM", "litellm-proxy"},
		{"OpenWebUI", "openwebui"},
	}

	for _, container := range containers {
		fmt.Printf("\n--- %s Logs ---\n", container.name)
		logsOutput, err := execute.Run(rc.Ctx, execute.Options{
			Command: "docker",
			Args:    []string{"compose", "-f", composeFile, "logs", "--tail", "30", container.service},
			Capture: true,
			Timeout: 10 * time.Second,
		})

		if err != nil {
			logger.Warn("Failed to get container logs",
				zap.String("container", container.name),
				zap.Error(err))
			fmt.Printf("❌ Failed to retrieve logs: %v\n", err)
		} else {
			// Filter for important log lines
			lines := strings.Split(logsOutput, "\n")
			importantLines := 0
			for _, line := range lines {
				if strings.Contains(line, "ERROR") || strings.Contains(line, "WARN") ||
					strings.Contains(line, "Failed") || strings.Contains(line, "Connection") ||
					strings.Contains(line, "ready") || strings.Contains(line, "Starting") ||
					strings.Contains(line, "Listening") || strings.Contains(line, "Uvicorn") {
					fmt.Println(line)
					importantLines++
				}
			}
			if importantLines == 0 {
				fmt.Println("(No significant log entries found)")
			}
			logger.Debug("Container logs retrieved",
				zap.String("container", container.name),
				zap.Int("lines_shown", importantLines))
		}
	}
	fmt.Println()

	// Test 6: File Permissions
	fmt.Println("══════════════════════════════════════════════════════════")
	fmt.Println("6. FILE PERMISSIONS")
	fmt.Println("══════════════════════════════════════════════════════════")
	logger.Debug("Checking file permissions")

	envFile := installDir + "/.env"
	fmt.Printf("Checking %s permissions...\n", envFile)

	lsOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "ls",
		Args:    []string{"-la", envFile},
		Capture: true,
	})

	if err != nil {
		logger.Warn("Failed to check file permissions", zap.Error(err))
		fmt.Printf("❌ Failed to check file: %v\n", err)
	} else {
		fmt.Println(lsOutput)
		if strings.Contains(lsOutput, "rw-------") || strings.Contains(lsOutput, "600") {
			logger.Warn(".env file has restrictive permissions",
				zap.String("permissions", "0600"))
			fmt.Println("  .env file is only readable by owner (0600)")
			fmt.Println("   Docker Compose may fail to read environment variables")
			fmt.Println("   Recommended: chmod 640 .env && chgrp docker .env")
		} else {
			logger.Info(".env file permissions look correct")
			fmt.Println(" .env file permissions look correct")
		}
	}
	fmt.Println()

	// Summary
	fmt.Println("══════════════════════════════════════════════════════════")
	fmt.Println("NEXT STEPS")
	fmt.Println("══════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Println("If you see issues above:")
	fmt.Println()
	fmt.Println("1. Container not running:")
	fmt.Println("   cd /opt/openwebui && sudo docker compose up -d")
	fmt.Println()
	fmt.Println("2. LiteLLM not responding:")
	fmt.Println("   sudo docker compose -f /opt/openwebui/docker-compose.yml logs litellm-proxy")
	fmt.Println()
	fmt.Println("3. PostgreSQL not ready:")
	fmt.Println("   sudo docker compose -f /opt/openwebui/docker-compose.yml logs litellmproxy_db")
	fmt.Println()
	fmt.Println("4. Health checks failing after 2+ minutes:")
	fmt.Println("   Check logs above for specific errors")
	fmt.Println()
	fmt.Println("5. Permission issues:")
	fmt.Println("   sudo chmod 640 /opt/openwebui/.env")
	fmt.Println("   sudo chgrp docker /opt/openwebui/.env")
	fmt.Println()

	logger.Info("Diagnostics completed")
	return nil
}
