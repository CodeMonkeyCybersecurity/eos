// pkg/system_display/display.go
package system_display

import (
	"encoding/json"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/config_loader"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DisplaySystemState shows the system state configuration in a user-friendly format
func DisplaySystemState(rc *eos_io.RuntimeContext, systemState *config_loader.SystemState) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("System State Configuration Summary",
		zap.Int("services_count", len(systemState.Services)),
		zap.Int("cron_jobs_count", len(systemState.CronJobs)),
		zap.Int("users_count", len(systemState.Users)),
		zap.Int("packages_count", len(systemState.Packages)),
		zap.Int("files_count", len(systemState.Files)))

	// Display services
	if len(systemState.Services) > 0 {
		logger.Info("Services to be managed")
		for _, service := range systemState.Services {
			logger.Info("Service",
				zap.String("name", service.Name),
				zap.String("state", service.State),
				zap.Bool("enable", service.Enable))
		}
	}

	// Display cron jobs
	if len(systemState.CronJobs) > 0 {
		logger.Info("Cron jobs to be managed")
		for _, job := range systemState.CronJobs {
			logger.Info("Cron job",
				zap.String("name", job.Name),
				zap.String("command", job.Command),
				zap.String("user", job.User),
				zap.String("schedule", job.Minute+" "+job.Hour+" "+job.Day+" "+job.Month+" "+job.Weekday))
		}
	}

	// Display users
	if len(systemState.Users) > 0 {
		logger.Info("Users to be managed")
		for _, user := range systemState.Users {
			logger.Info("User",
				zap.String("name", user.Name),
				zap.Strings("groups", user.Groups),
				zap.String("shell", user.Shell),
				zap.Bool("present", user.Present))
		}
	}

	return nil
}

// DisplayStateApplication shows the result of applying system state
func DisplayStateApplication(rc *eos_io.RuntimeContext, result *system.StateApplication) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("System State Application Results",
		zap.String("target", result.Target),
		zap.Int("states_applied", len(result.States)),
		zap.Int("results_count", len(result.Results)),
		zap.Int("changes_count", len(result.Changes)),
		zap.Duration("duration", result.Duration),
		zap.Bool("success", result.Success))

	// Display errors if any
	if len(result.Errors) > 0 {
		logger.Error("State application errors occurred")
		for _, err := range result.Errors {
			logger.Error("Application error", zap.String("error", err))
		}
	}

	// Display individual state results
	for stateName, stateResult := range result.Results {
		if stateResult.Result {
			logger.Info("State applied successfully",
				zap.String("state", stateName),
				zap.String("comment", stateResult.Comment),
				zap.Float64("duration", stateResult.Duration))
		} else {
			logger.Error("State application failed",
				zap.String("state", stateName),
				zap.String("comment", stateResult.Comment))
		}
	}

	// Log detailed results as JSON for machine parsing
	if resultJSON, err := json.MarshalIndent(result, "", "  "); err == nil {
		logger.Debug("Complete state application result", zap.String("result_json", string(resultJSON)))
	}

	return nil
}
