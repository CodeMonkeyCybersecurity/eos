// cmd/debug/bionicgpt.go
// BionicGPT installation and runtime diagnostic command

package debug

import (
	"fmt"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/bionicgpt"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var bionicgptDebugCmd = &cobra.Command{
	Use:   "bionicgpt",
	Short: "Diagnose BionicGPT installation and runtime issues",
	Long: `Run comprehensive diagnostics on BionicGPT installation and runtime.

This command tests:
- Container status (app, postgres, embeddings, RAG, chunking, migrations)
- Port bindings and network connectivity
- PostgreSQL readiness and connection
- Docker volume mounts
- Container logs (last 50 lines)
- Resource utilization
- Health endpoints

This helps identify issues with the 'eos create bionicgpt' installation process
and runtime failures.

EXAMPLES:
  # Run diagnostics
  sudo eos debug bionicgpt

  # Run and save output
  sudo eos debug bionicgpt > /tmp/bionicgpt-diagnostic.txt`,

	RunE: eos_cli.Wrap(runBionicGPTDebug),
}

func init() {
	debugCmd.AddCommand(bionicgptDebugCmd)
}

func runBionicGPTDebug(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting BionicGPT installation diagnostics")

	installDir := bionicgpt.DefaultInstallDir
	composeFile := installDir + "/docker-compose.yml"

	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║      BionicGPT Diagnostic Report                          ║")
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
		fmt.Printf(" Failed to get container status: %v\n", err)
		fmt.Println("   Possible causes:")
		fmt.Println("   - BionicGPT not installed yet (run: sudo eos create bionicgpt)")
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
		fmt.Printf(" Failed to check ports: %v\n", err)
		fmt.Println()
	} else {
		// Filter for BionicGPT port (3000)
		lines := strings.Split(portOutput, "\n")
		found := false
		for _, line := range lines {
			if strings.Contains(line, ":3000") || strings.Contains(line, fmt.Sprintf(":%d", bionicgpt.DefaultPort)) {
				if !found {
					fmt.Println("Port       Status")
					fmt.Println("----       ------")
					found = true
				}
				fmt.Printf(" %d    BionicGPT listening\n", bionicgpt.DefaultPort)
			}
		}
		if !found {
			fmt.Printf(" BionicGPT not listening on expected port %d\n", bionicgpt.DefaultPort)
			fmt.Println("   Containers may not be running or still initializing")
		}
		logger.Info("Port check completed")
	}
	fmt.Println()

	// Test 3: Docker Volumes
	fmt.Println("══════════════════════════════════════════════════════════")
	fmt.Println("3. DOCKER VOLUMES")
	fmt.Println("══════════════════════════════════════════════════════════")
	logger.Debug("Checking Docker volumes")

	volumes := []string{
		bionicgpt.VolumePostgresData,
		bionicgpt.VolumeDocuments,
	}

	for _, vol := range volumes {
		volOutput, err := execute.Run(rc.Ctx, execute.Options{
			Command: "docker",
			Args:    []string{"volume", "inspect", vol, "--format", "{{.Mountpoint}} ({{.Driver}})"},
			Capture: true,
		})

		if err != nil {
			fmt.Printf(" Volume %s: Not found\n", vol)
		} else {
			fmt.Printf("✓ Volume %s: %s\n", vol, strings.TrimSpace(volOutput))
		}
	}
	fmt.Println()

	// Test 4: PostgreSQL Readiness
	fmt.Println("══════════════════════════════════════════════════════════")
	fmt.Println("4. DATABASE CONNECTION TEST")
	fmt.Println("══════════════════════════════════════════════════════════")
	logger.Debug("Testing PostgreSQL readiness")

	pgOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"exec", bionicgpt.ContainerPostgres, "pg_isready", "-U", "postgres"},
		Capture: true,
		Timeout: 5 * time.Second,
	})

	if err != nil {
		logger.Warn("PostgreSQL readiness check failed",
			zap.Error(err),
			zap.String("output", pgOutput))
		fmt.Printf(" PostgreSQL not ready: %s\n", pgOutput)
		fmt.Println("   Database may still be initializing")
	} else {
		logger.Info("PostgreSQL readiness check passed")
		fmt.Printf("✓ PostgreSQL ready: %s\n", strings.TrimSpace(pgOutput))
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
		{"PostgreSQL", "postgres"},
		{"Migrations", "migrations"},
		{"RAG Engine", "rag-engine"},
		{"Embeddings API", "embeddings-api"},
		{"Chunking Engine", "chunking-engine"},
		{"BionicGPT App", "app"},
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
			fmt.Printf(" Failed to retrieve logs: %v\n", err)
		} else {
			// Filter for important log lines
			lines := strings.Split(logsOutput, "\n")
			importantLines := 0
			for _, line := range lines {
				if strings.Contains(line, "ERROR") || strings.Contains(line, "WARN") ||
					strings.Contains(line, "Failed") || strings.Contains(line, "Connection") ||
					strings.Contains(line, "ready") || strings.Contains(line, "Starting") ||
					strings.Contains(line, "Listening") || strings.Contains(line, "Accepting") {
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

	// Test 6: Resource Usage
	fmt.Println("══════════════════════════════════════════════════════════")
	fmt.Println("6. RESOURCE USAGE")
	fmt.Println("══════════════════════════════════════════════════════════")
	logger.Debug("Checking resource usage")

	statsOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"stats", "--no-stream", "--format", "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"},
		Capture: true,
		Timeout: 10 * time.Second,
	})

	if err != nil {
		logger.Warn("Failed to get resource stats", zap.Error(err))
		fmt.Printf(" Failed to get resource stats: %v\n", err)
	} else {
		fmt.Println(statsOutput)
		logger.Info("Resource stats retrieved")
	}
	fmt.Println()

	// Summary
	fmt.Println("══════════════════════════════════════════════════════════")
	fmt.Println("NEXT STEPS")
	fmt.Println("══════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Println("If you see issues above:")
	fmt.Println()
	fmt.Println("1. Containers not running:")
	fmt.Println("   cd /opt/bionicgpt && sudo docker compose up -d")
	fmt.Println()
	fmt.Println("2. PostgreSQL not ready:")
	fmt.Println("   sudo docker compose -f /opt/bionicgpt/docker-compose.yml logs postgres")
	fmt.Println()
	fmt.Println("3. Azure OpenAI connection issues:")
	fmt.Println("   Check Azure OpenAI credentials in .env file")
	fmt.Println("   Verify Azure OpenAI endpoint is accessible")
	fmt.Println()
	fmt.Println("4. RAG engine issues:")
	fmt.Println("   sudo docker compose -f /opt/bionicgpt/docker-compose.yml logs rag-engine")
	fmt.Println()
	fmt.Println("5. Embeddings API not responding:")
	fmt.Println("   sudo docker compose -f /opt/bionicgpt/docker-compose.yml logs embeddings-api")
	fmt.Println()
	fmt.Println("6. Service fails after 5+ minutes:")
	fmt.Println("   Check logs above for specific errors")
	fmt.Println()

	logger.Info("Diagnostics completed")
	return nil
}
