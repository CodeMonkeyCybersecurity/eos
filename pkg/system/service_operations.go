// Package system provides system service management operations following the AIE pattern
package system

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/patterns"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ServiceOperation implements AIE pattern for systemd service operations
type ServiceOperation struct {
	ServiceName string
	Action      string // start, stop, enable, disable, mask, unmask
	Target      string
	SaltClient  *saltstack.Client
	Logger      otelzap.LoggerWithCtx
}

// Assess checks if service operation can proceed
func (s *ServiceOperation) Assess(ctx context.Context) (*patterns.AssessmentResult, error) {
	s.Logger.Info("Assessing service operation",
		zap.String("service", s.ServiceName),
		zap.String("action", s.Action),
		zap.String("target", s.Target))

	prerequisites := make(map[string]bool)

	// Check if systemd is available
	_, err := s.SaltClient.CmdRun(ctx, s.Target, "systemctl --version")
	if err != nil {
		return &patterns.AssessmentResult{
			CanProceed: false,
			Reason:     "systemd not available on target",
		}, nil
	}
	prerequisites["systemd_available"] = true

	// Check if service exists (for most operations)
	if s.Action != "mask" {
		output, err := s.SaltClient.CmdRun(ctx, s.Target, 
			fmt.Sprintf("systemctl cat %s >/dev/null 2>&1 && echo exists || echo notfound", s.ServiceName))
		if err != nil || strings.TrimSpace(output) == "notfound" {
			prerequisites["service_exists"] = false
			return &patterns.AssessmentResult{
				CanProceed: false,
				Reason:     fmt.Sprintf("service %s not found", s.ServiceName),
				Prerequisites: prerequisites,
			}, nil
		}
		prerequisites["service_exists"] = true
	}

	// Check current state
	currentState, _ := s.SaltClient.CmdRun(ctx, s.Target, 
		fmt.Sprintf("systemctl is-active %s 2>/dev/null || echo inactive", s.ServiceName))
	currentState = strings.TrimSpace(currentState)

	enabledState, _ := s.SaltClient.CmdRun(ctx, s.Target, 
		fmt.Sprintf("systemctl is-enabled %s 2>/dev/null || echo disabled", s.ServiceName))
	enabledState = strings.TrimSpace(enabledState)

	// Validate operation makes sense
	context := map[string]interface{}{
		"current_state":  currentState,
		"enabled_state":  enabledState,
	}

	switch s.Action {
	case "start":
		if currentState == "active" {
			return &patterns.AssessmentResult{
				CanProceed: false,
				Reason:     "service is already active",
				Context:    context,
			}, nil
		}
	case "stop":
		if currentState == "inactive" {
			return &patterns.AssessmentResult{
				CanProceed: false,
				Reason:     "service is already inactive",
				Context:    context,
			}, nil
		}
	case "enable":
		if enabledState == "enabled" {
			return &patterns.AssessmentResult{
				CanProceed: false,
				Reason:     "service is already enabled",
				Context:    context,
			}, nil
		}
	case "disable":
		if enabledState == "disabled" || enabledState == "masked" {
			return &patterns.AssessmentResult{
				CanProceed: false,
				Reason:     "service is already disabled",
				Context:    context,
			}, nil
		}
	}

	return &patterns.AssessmentResult{
		CanProceed:    true,
		Prerequisites: prerequisites,
		Context:       context,
	}, nil
}

// Intervene performs the service operation
func (s *ServiceOperation) Intervene(ctx context.Context, assessment *patterns.AssessmentResult) (*patterns.InterventionResult, error) {
	s.Logger.Info("Performing service operation",
		zap.String("service", s.ServiceName),
		zap.String("action", s.Action))

	cmd := fmt.Sprintf("systemctl %s %s", s.Action, s.ServiceName)
	output, err := s.SaltClient.CmdRun(ctx, s.Target, cmd)
	if err != nil {
		return &patterns.InterventionResult{
			Success: false,
			Message: fmt.Sprintf("service operation failed: %v", err),
		}, err
	}

	return &patterns.InterventionResult{
		Success: true,
		Message: fmt.Sprintf("service %s %s completed", s.ServiceName, s.Action),
		Changes: []patterns.Change{
			{
				Type:        "service_operation",
				Description: fmt.Sprintf("Executed %s on service %s", s.Action, s.ServiceName),
				Before:      assessment.Context,
				After:       output,
			},
		},
	}, nil
}

// Evaluate verifies the service operation was successful
func (s *ServiceOperation) Evaluate(ctx context.Context, intervention *patterns.InterventionResult) (*patterns.EvaluationResult, error) {
	if !intervention.Success {
		return &patterns.EvaluationResult{
			Success: false,
			Message: "service operation failed",
		}, nil
	}

	validations := make(map[string]patterns.ValidationResult)

	// Verify expected state
	switch s.Action {
	case "start":
		state, _ := s.SaltClient.CmdRun(ctx, s.Target, 
			fmt.Sprintf("systemctl is-active %s", s.ServiceName))
		if strings.TrimSpace(state) == "active" {
			validations["service_active"] = patterns.ValidationResult{
				Passed:  true,
				Message: "service is active",
			}
		} else {
			validations["service_active"] = patterns.ValidationResult{
				Passed:  false,
				Message: fmt.Sprintf("service is not active: %s", state),
			}
		}

	case "stop":
		state, _ := s.SaltClient.CmdRun(ctx, s.Target, 
			fmt.Sprintf("systemctl is-active %s", s.ServiceName))
		if strings.TrimSpace(state) == "inactive" {
			validations["service_inactive"] = patterns.ValidationResult{
				Passed:  true,
				Message: "service is inactive",
			}
		} else {
			validations["service_inactive"] = patterns.ValidationResult{
				Passed:  false,
				Message: fmt.Sprintf("service is not inactive: %s", state),
			}
		}

	case "enable":
		state, _ := s.SaltClient.CmdRun(ctx, s.Target, 
			fmt.Sprintf("systemctl is-enabled %s", s.ServiceName))
		if strings.TrimSpace(state) == "enabled" {
			validations["service_enabled"] = patterns.ValidationResult{
				Passed:  true,
				Message: "service is enabled",
			}
		} else {
			validations["service_enabled"] = patterns.ValidationResult{
				Passed:  false,
				Message: fmt.Sprintf("service is not enabled: %s", state),
			}
		}

	case "disable":
		state, _ := s.SaltClient.CmdRun(ctx, s.Target, 
			fmt.Sprintf("systemctl is-enabled %s", s.ServiceName))
		if strings.TrimSpace(state) == "disabled" {
			validations["service_disabled"] = patterns.ValidationResult{
				Passed:  true,
				Message: "service is disabled",
			}
		} else {
			validations["service_disabled"] = patterns.ValidationResult{
				Passed:  false,
				Message: fmt.Sprintf("service is not disabled: %s", state),
			}
		}

	case "mask":
		state, _ := s.SaltClient.CmdRun(ctx, s.Target, 
			fmt.Sprintf("systemctl is-enabled %s", s.ServiceName))
		if strings.TrimSpace(state) == "masked" {
			validations["service_masked"] = patterns.ValidationResult{
				Passed:  true,
				Message: "service is masked",
			}
		} else {
			validations["service_masked"] = patterns.ValidationResult{
				Passed:  false,
				Message: fmt.Sprintf("service is not masked: %s", state),
			}
		}
	}

	// Check if all validations passed
	allPassed := true
	for _, v := range validations {
		if !v.Passed {
			allPassed = false
			break
		}
	}

	return &patterns.EvaluationResult{
		Success:     allPassed,
		Message:     "service operation validated",
		Validations: validations,
	}, nil
}

// SleepDisableOperation implements AIE pattern for disabling system sleep
type SleepDisableOperation struct {
	Target     string
	SaltClient *saltstack.Client
	Logger     otelzap.LoggerWithCtx
}

// Assess checks if sleep can be disabled
func (s *SleepDisableOperation) Assess(ctx context.Context) (*patterns.AssessmentResult, error) {
	s.Logger.Info("Assessing sleep disable capability",
		zap.String("target", s.Target))

	// Check systemd availability
	_, err := s.SaltClient.CmdRun(ctx, s.Target, "systemctl --version")
	if err != nil {
		return &patterns.AssessmentResult{
			CanProceed: false,
			Reason:     "systemd not available",
		}, nil
	}

	// Get current sleep targets
	sleepTargets := []string{
		"sleep.target",
		"suspend.target", 
		"hibernate.target",
		"hybrid-sleep.target",
	}

	prerequisites := make(map[string]bool)
	for _, target := range sleepTargets {
		state, _ := s.SaltClient.CmdRun(ctx, s.Target, 
			fmt.Sprintf("systemctl is-enabled %s 2>/dev/null || echo not-found", target))
		prerequisites[fmt.Sprintf("%s_exists", target)] = !strings.Contains(state, "not-found")
	}

	return &patterns.AssessmentResult{
		CanProceed:    true,
		Prerequisites: prerequisites,
	}, nil
}

// Intervene disables sleep functionality
func (s *SleepDisableOperation) Intervene(ctx context.Context, assessment *patterns.AssessmentResult) (*patterns.InterventionResult, error) {
	s.Logger.Info("Disabling system sleep functionality")

	changes := []patterns.Change{}

	// Mask sleep targets
	sleepTargets := []string{
		"sleep.target",
		"suspend.target", 
		"hibernate.target",
		"hybrid-sleep.target",
	}

	for _, target := range sleepTargets {
		_, err := s.SaltClient.CmdRun(ctx, s.Target, fmt.Sprintf("systemctl mask %s", target))
		if err != nil {
			s.Logger.Warn("Failed to mask target", 
				zap.String("target", target),
				zap.Error(err))
		} else {
			changes = append(changes, patterns.Change{
				Type:        "mask_target",
				Description: fmt.Sprintf("Masked %s", target),
			})
		}
	}

	// Disable logind sleep
	logindConf := `[Login]
HandleLidSwitch=ignore
HandleLidSwitchExternalPower=ignore
HandleLidSwitchDocked=ignore
HandleSuspendKey=ignore
HandleHibernateKey=ignore
HandlePowerKey=poweroff`

	_, err := s.SaltClient.CmdRun(ctx, s.Target, 
		fmt.Sprintf("echo '%s' > /etc/systemd/logind.conf.d/disable-sleep.conf", logindConf))
	if err == nil {
		changes = append(changes, patterns.Change{
			Type:        "logind_config",
			Description: "Configured logind to disable sleep",
		})
	}

	// Restart systemd-logind
	_, err = s.SaltClient.CmdRun(ctx, s.Target, "systemctl restart systemd-logind")
	if err == nil {
		changes = append(changes, patterns.Change{
			Type:        "restart_service",
			Description: "Restarted systemd-logind",
		})
	}

	return &patterns.InterventionResult{
		Success: true,
		Message: "sleep functionality disabled",
		Changes: changes,
	}, nil
}

// Evaluate verifies sleep was disabled
func (s *SleepDisableOperation) Evaluate(ctx context.Context, intervention *patterns.InterventionResult) (*patterns.EvaluationResult, error) {
	validations := make(map[string]patterns.ValidationResult)

	// Check sleep targets are masked
	sleepTargets := []string{
		"sleep.target",
		"suspend.target", 
		"hibernate.target",
		"hybrid-sleep.target",
	}

	for _, target := range sleepTargets {
		state, _ := s.SaltClient.CmdRun(ctx, s.Target, 
			fmt.Sprintf("systemctl is-enabled %s", target))
		if strings.TrimSpace(state) == "masked" {
			validations[fmt.Sprintf("%s_masked", target)] = patterns.ValidationResult{
				Passed:  true,
				Message: fmt.Sprintf("%s is masked", target),
			}
		} else {
			validations[fmt.Sprintf("%s_masked", target)] = patterns.ValidationResult{
				Passed:  false,
				Message: fmt.Sprintf("%s is not masked: %s", target, state),
			}
		}
	}

	// Check logind configuration
	configCheck, _ := s.SaltClient.CmdRun(ctx, s.Target, 
		"grep -q 'HandleSuspendKey=ignore' /etc/systemd/logind.conf.d/disable-sleep.conf && echo configured || echo missing")
	if strings.TrimSpace(configCheck) == "configured" {
		validations["logind_configured"] = patterns.ValidationResult{
			Passed:  true,
			Message: "logind sleep configuration applied",
		}
	} else {
		validations["logind_configured"] = patterns.ValidationResult{
			Passed:  false,
			Message: "logind sleep configuration missing",
		}
	}

	// Check if all validations passed
	allPassed := true
	for _, v := range validations {
		if !v.Passed {
			allPassed = false
			break
		}
	}

	return &patterns.EvaluationResult{
		Success:     allPassed,
		Message:     "sleep disable validation completed",
		Validations: validations,
	}, nil
}

// PortKillOperation implements AIE pattern for killing processes by port
type PortKillOperation struct {
	Port       int
	Target     string
	SaltClient *saltstack.Client
	Logger     otelzap.LoggerWithCtx
}

// Assess checks if processes can be killed on the port
func (p *PortKillOperation) Assess(ctx context.Context) (*patterns.AssessmentResult, error) {
	p.Logger.Info("Assessing port kill operation",
		zap.Int("port", p.Port),
		zap.String("target", p.Target))

	// Find processes using the port
	output, err := p.SaltClient.CmdRun(ctx, p.Target, 
		fmt.Sprintf("lsof -ti:%d 2>/dev/null || echo none", p.Port))
	if err != nil {
		return &patterns.AssessmentResult{
			CanProceed: false,
			Reason:     "failed to check port usage",
		}, err
	}

	output = strings.TrimSpace(output)
	if output == "none" || output == "" {
		return &patterns.AssessmentResult{
			CanProceed: false,
			Reason:     "no processes found on port",
		}, nil
	}

	pids := strings.Split(output, "\n")
	return &patterns.AssessmentResult{
		CanProceed: true,
		Prerequisites: map[string]bool{
			"processes_found": true,
		},
		Context: map[string]interface{}{
			"pids":       pids,
			"pid_count":  len(pids),
		},
	}, nil
}

// Intervene kills processes on the port
func (p *PortKillOperation) Intervene(ctx context.Context, assessment *patterns.AssessmentResult) (*patterns.InterventionResult, error) {
	p.Logger.Info("Killing processes on port",
		zap.Int("port", p.Port))

	// Kill processes
	_, err := p.SaltClient.CmdRun(ctx, p.Target, 
		fmt.Sprintf("lsof -ti:%d | xargs -r kill -9", p.Port))
	if err != nil {
		return &patterns.InterventionResult{
			Success: false,
			Message: fmt.Sprintf("failed to kill processes: %v", err),
		}, err
	}

	pids := assessment.Context["pids"].([]string)
	changes := make([]patterns.Change, len(pids))
	for i, pid := range pids {
		changes[i] = patterns.Change{
			Type:        "process_kill",
			Description: fmt.Sprintf("Killed process PID %s on port %d", pid, p.Port),
		}
	}

	return &patterns.InterventionResult{
		Success: true,
		Message: fmt.Sprintf("killed processes on port %d", p.Port),
		Changes: changes,
	}, nil
}

// Evaluate verifies processes were killed
func (p *PortKillOperation) Evaluate(ctx context.Context, intervention *patterns.InterventionResult) (*patterns.EvaluationResult, error) {
	// Check if any processes still exist on the port
	output, _ := p.SaltClient.CmdRun(ctx, p.Target, 
		fmt.Sprintf("lsof -ti:%d 2>/dev/null | wc -l", p.Port))
	
	count, err := strconv.Atoi(strings.TrimSpace(output))
	if err != nil {
		count = -1
	}

	if count == 0 {
		return &patterns.EvaluationResult{
			Success: true,
			Message: "no processes remain on port",
			Validations: map[string]patterns.ValidationResult{
				"port_clear": {
					Passed:  true,
					Message: "port is now free",
				},
			},
		}, nil
	}

	return &patterns.EvaluationResult{
		Success: false,
		Message: "processes still exist on port",
		Validations: map[string]patterns.ValidationResult{
			"port_clear": {
				Passed:  false,
				Message: fmt.Sprintf("%d processes still on port", count),
			},
		},
	}, nil
}

// Helper functions for common service operations

// ManageService performs a service operation using AIE pattern
func ManageService(ctx context.Context, logger otelzap.LoggerWithCtx, saltClient *saltstack.Client, 
	target, serviceName, action string) error {
	
	operation := &ServiceOperation{
		ServiceName: serviceName,
		Action:      action,
		Target:      target,
		SaltClient:  saltClient,
		Logger:      logger,
	}

	executor := patterns.NewExecutor(logger)
	return executor.Execute(ctx, operation, fmt.Sprintf("service_%s_%s", action, serviceName))
}

// DisableSystemSleep disables system sleep functionality using AIE pattern
func DisableSystemSleep(ctx context.Context, logger otelzap.LoggerWithCtx, saltClient *saltstack.Client, 
	target string) error {
	
	operation := &SleepDisableOperation{
		Target:     target,
		SaltClient: saltClient,
		Logger:     logger,
	}

	executor := patterns.NewExecutor(logger)
	return executor.Execute(ctx, operation, "disable_system_sleep")
}

// KillProcessesByPort kills processes using a specific port using AIE pattern
func KillProcessesByPort(ctx context.Context, logger otelzap.LoggerWithCtx, saltClient *saltstack.Client, 
	target string, port int) error {
	
	operation := &PortKillOperation{
		Port:       port,
		Target:     target,
		SaltClient: saltClient,
		Logger:     logger,
	}

	executor := patterns.NewExecutor(logger)
	return executor.Execute(ctx, operation, fmt.Sprintf("kill_port_%d", port))
}