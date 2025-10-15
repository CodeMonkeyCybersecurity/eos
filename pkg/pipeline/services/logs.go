package services

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ShowRecentLogs displays recent service logs
// Migrated from cmd/read/pipeline_services.go showRecentLogs
func ShowRecentLogs(rc *eos_io.RuntimeContext, serviceName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Prepare recent logs display
	logger.Info("Assessing recent logs display",
		zap.String("service", serviceName))

	logger.Info(" Recent Logs (last 10 lines)")

	// INTERVENE - Retrieve and display logs
	logger.Debug("Retrieving service logs from journalctl")

	cmd := exec.Command("journalctl", "-u", serviceName, "-n", "10", "--no-pager")
	output, err := cmd.Output()
	if err != nil {
		logger.Error("Failed to retrieve service logs",
			zap.String("service", serviceName),
			zap.Error(err))
		return fmt.Errorf("failed to retrieve logs for service %s: %w", serviceName, err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			logger.Info("  " + line)
		}
	}

	// EVALUATE - Log successful logs display
	logger.Info("Recent logs displayed successfully",
		zap.String("service", serviceName),
		zap.Int("lines_displayed", len(lines)))

	return nil
}
