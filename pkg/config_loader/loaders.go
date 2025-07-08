// pkg/config_loader/loaders.go
package config_loader

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SystemState represents comprehensive system state configuration
type SystemState struct {
	Services []system.ServiceConfig   `json:"services"`
	CronJobs []system.CronJobConfig   `json:"cron_jobs"`
	Users    []system.UserConfig      `json:"users"`
	Packages []system.PackageConfig   `json:"packages"`
	Files    []system.FileConfig      `json:"files"`
	Security map[string]interface{}   `json:"security"`
	Metadata map[string]interface{}   `json:"metadata"`
}

// StateApplicationResult represents the result of applying system state
type StateApplicationResult struct {
	ServicesChanged int                    `json:"services_changed"`
	CronJobsChanged int                    `json:"cron_jobs_changed"`
	UsersChanged    int                    `json:"users_changed"`
	PackagesChanged int                    `json:"packages_changed"`
	FilesChanged    int                    `json:"files_changed"`
	Errors          []string               `json:"errors"`
	Details         map[string]interface{} `json:"details"`
	Success         bool                   `json:"success"`
}

// LoadServicesFromFile loads service configurations from a JSON file
// This follows the Assess → Intervene → Evaluate pattern
func LoadServicesFromFile(rc *eos_io.RuntimeContext, configFile string) ([]system.ServiceConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check file prerequisites
	logger.Info("Assessing services configuration file",
		zap.String("config_file", configFile))

	if configFile == "" {
		return nil, fmt.Errorf("configuration file path is required")
	}

	if !filepath.IsAbs(configFile) {
		configFile, _ = filepath.Abs(configFile)
	}

	// INTERVENE - Load and parse the file
	logger.Info("Loading services configuration from file")

	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read services config file: %w", err)
	}

	var services []system.ServiceConfig
	if err := json.Unmarshal(data, &services); err != nil {
		return nil, fmt.Errorf("failed to parse services config: %w", err)
	}

	// EVALUATE - Validate the loaded configuration
	logger.Info("Validating services configuration")

	if err := validateServicesConfig(services); err != nil {
		return nil, fmt.Errorf("services configuration validation failed: %w", err)
	}

	logger.Info("Services configuration loaded successfully",
		zap.Int("service_count", len(services)))

	return services, nil
}

// LoadCronJobsFromFile loads cron job configurations from a JSON file
func LoadCronJobsFromFile(rc *eos_io.RuntimeContext, configFile string) ([]system.CronJobConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check file prerequisites
	logger.Info("Assessing cron jobs configuration file",
		zap.String("config_file", configFile))

	if configFile == "" {
		return nil, fmt.Errorf("configuration file path is required")
	}

	if !filepath.IsAbs(configFile) {
		configFile, _ = filepath.Abs(configFile)
	}

	// INTERVENE - Load and parse the file
	logger.Info("Loading cron jobs configuration from file")

	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read cron jobs config file: %w", err)
	}

	var cronJobs []system.CronJobConfig
	if err := json.Unmarshal(data, &cronJobs); err != nil {
		return nil, fmt.Errorf("failed to parse cron jobs config: %w", err)
	}

	// EVALUATE - Validate the loaded configuration
	logger.Info("Validating cron jobs configuration")

	if err := validateCronJobsConfig(cronJobs); err != nil {
		return nil, fmt.Errorf("cron jobs configuration validation failed: %w", err)
	}

	logger.Info("Cron jobs configuration loaded successfully",
		zap.Int("cron_job_count", len(cronJobs)))

	return cronJobs, nil
}

// LoadUsersFromFile loads user configurations from a JSON file
func LoadUsersFromFile(rc *eos_io.RuntimeContext, configFile string) ([]system.UserConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check file prerequisites
	logger.Info("Assessing users configuration file",
		zap.String("config_file", configFile))

	if configFile == "" {
		return nil, fmt.Errorf("configuration file path is required")
	}

	if !filepath.IsAbs(configFile) {
		configFile, _ = filepath.Abs(configFile)
	}

	// INTERVENE - Load and parse the file
	logger.Info("Loading users configuration from file")

	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read users config file: %w", err)
	}

	var users []system.UserConfig
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, fmt.Errorf("failed to parse users config: %w", err)
	}

	// EVALUATE - Validate the loaded configuration
	logger.Info("Validating users configuration")

	if err := validateUsersConfig(users); err != nil {
		return nil, fmt.Errorf("users configuration validation failed: %w", err)
	}

	logger.Info("Users configuration loaded successfully",
		zap.Int("user_count", len(users)))

	return users, nil
}

// LoadSystemStateFromFile loads comprehensive system state from a JSON file
func LoadSystemStateFromFile(rc *eos_io.RuntimeContext, configFile string) (*SystemState, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check file prerequisites
	logger.Info("Assessing system state configuration file",
		zap.String("config_file", configFile))

	if configFile == "" {
		return nil, fmt.Errorf("configuration file path is required")
	}

	if !filepath.IsAbs(configFile) {
		configFile, _ = filepath.Abs(configFile)
	}

	// INTERVENE - Load and parse the file
	logger.Info("Loading system state configuration from file")

	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read system state config file: %w", err)
	}

	var systemState SystemState
	if err := json.Unmarshal(data, &systemState); err != nil {
		return nil, fmt.Errorf("failed to parse system state config: %w", err)
	}

	// EVALUATE - Validate the loaded configuration
	logger.Info("Validating system state configuration")

	if err := validateSystemStateConfig(&systemState); err != nil {
		return nil, fmt.Errorf("system state configuration validation failed: %w", err)
	}

	logger.Info("System state configuration loaded successfully",
		zap.Int("services_count", len(systemState.Services)),
		zap.Int("cron_jobs_count", len(systemState.CronJobs)),
		zap.Int("users_count", len(systemState.Users)))

	return &systemState, nil
}

// validateServicesConfig validates service configurations
func validateServicesConfig(services []system.ServiceConfig) error {
	for i, service := range services {
		if service.Name == "" {
			return fmt.Errorf("service %d: name is required", i)
		}
		if service.State != "" && service.State != "running" && service.State != "stopped" {
			return fmt.Errorf("service %s: invalid state '%s'", service.Name, service.State)
		}
	}
	return nil
}

// validateCronJobsConfig validates cron job configurations
func validateCronJobsConfig(cronJobs []system.CronJobConfig) error {
	for i, job := range cronJobs {
		if job.Name == "" {
			return fmt.Errorf("cron job %d: name is required", i)
		}
		if job.Command == "" {
			return fmt.Errorf("cron job %s: command is required", job.Name)
		}
		if job.User == "" {
			job.User = "root" // Set default user
		}
	}
	return nil
}

// validateUsersConfig validates user configurations
func validateUsersConfig(users []system.UserConfig) error {
	for i, user := range users {
		if user.Name == "" {
			return fmt.Errorf("user %d: name is required", i)
		}
		if user.Shell == "" {
			user.Shell = "/bin/bash" // Set default shell
		}
	}
	return nil
}

// validateSystemStateConfig validates system state configuration
func validateSystemStateConfig(state *SystemState) error {
	if err := validateServicesConfig(state.Services); err != nil {
		return fmt.Errorf("services validation: %w", err)
	}
	if err := validateCronJobsConfig(state.CronJobs); err != nil {
		return fmt.Errorf("cron jobs validation: %w", err)
	}
	if err := validateUsersConfig(state.Users); err != nil {
		return fmt.Errorf("users validation: %w", err)
	}
	return nil
}

// ConvertToSystemState converts config_loader.SystemState to system.SystemState
func ConvertToSystemState(state *SystemState) *system.SystemState {
	return &system.SystemState{
		Services:    state.Services,
		CronJobs:    state.CronJobs,
		Users:       state.Users,
		Packages:    state.Packages,
		Files:       state.Files,
		Environment: make(map[string]string),
	}
}