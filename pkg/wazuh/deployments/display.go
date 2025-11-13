package deployments

import (
	"fmt"
	"strings"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// OutputDeploymentTable formats and displays deployment list as a table.
func OutputDeploymentTable(logger otelzap.LoggerWithCtx, list DeploymentList) error {
	logger.Info("terminal prompt: Deployments", zap.Int("total", list.Total))
	logger.Info("terminal prompt:", zap.String("output", strings.Repeat("-", 120)))
	logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%-30s %-15s %-20s %-10s %-10s %-5s %-10s %-10s",
		"Job Name", "Customer ID", "Company", "Type", "Status", "Inst", "CPU%", "Mem%")))
	logger.Info("terminal prompt:", zap.String("output", strings.Repeat("-", 120)))

	for _, deployment := range list.Deployments {
		logger.Info("terminal prompt:", zap.String("output", fmt.Sprintf("%-30s %-15s %-20s %-10s %-10s %-5d %-10.1f %-10.1f",
			truncate(deployment.JobName, 30),
			deployment.CustomerID,
			truncate(deployment.CompanyName, 20),
			deployment.Type,
			deployment.Status,
			deployment.Instances,
			deployment.CPUUsage,
			deployment.MemoryUsage)))
	}

	logger.Info("terminal prompt: Summary:")
	logger.Info("terminal prompt: Total Jobs:",
		zap.Int("total", list.Summary.TotalJobs),
		zap.Int("running", list.Summary.RunningJobs),
		zap.Int("failed", list.Summary.FailedJobs))
	logger.Info("terminal prompt: Total Instances:", zap.Int("instances", list.Summary.TotalInstances))

	return nil
}

// truncate truncates a string to maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
