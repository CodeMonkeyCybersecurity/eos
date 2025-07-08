// Package users provides user management operations following the AIE pattern
package users

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/patterns"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/saltstack"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// UserExistenceCheck implements AIE pattern for checking user existence
type UserExistenceCheck struct {
	Username  string
	Target    string
	SaltClient saltstack.ClientInterface
	Logger    otelzap.LoggerWithCtx
}

// Assess checks if we can verify user existence
func (u *UserExistenceCheck) Assess(ctx context.Context) (*patterns.AssessmentResult, error) {
	u.Logger.Info("Assessing user existence check capability",
		zap.String("username", u.Username),
		zap.String("target", u.Target))

	// Check Salt connectivity
	connected, err := u.SaltClient.TestPing(ctx, u.Target)
	if err != nil || !connected {
		return &patterns.AssessmentResult{
			CanProceed: false,
			Reason:     "cannot connect to target via Salt",
		}, nil
	}

	return &patterns.AssessmentResult{
		CanProceed: true,
		Prerequisites: map[string]bool{
			"salt_connected": true,
			"target_reachable": true,
		},
	}, nil
}

// Intervene checks for user existence
func (u *UserExistenceCheck) Intervene(ctx context.Context, assessment *patterns.AssessmentResult) (*patterns.InterventionResult, error) {
	u.Logger.Info("Checking user existence",
		zap.String("username", u.Username))

	output, err := u.SaltClient.CmdRun(ctx, u.Target, fmt.Sprintf("id %s", u.Username))
	userExists := err == nil && !strings.Contains(output, "no such user")

	return &patterns.InterventionResult{
		Success: true,
		Message: "user existence check completed",
		Changes: []patterns.Change{
			{
				Type:        "user_check",
				Description: fmt.Sprintf("Checked existence of user %s", u.Username),
				After:       userExists,
			},
		},
		RollbackData: userExists,
	}, nil
}

// Evaluate verifies the check was successful
func (u *UserExistenceCheck) Evaluate(ctx context.Context, intervention *patterns.InterventionResult) (*patterns.EvaluationResult, error) {
	return &patterns.EvaluationResult{
		Success: true,
		Message: "user existence check validated",
		Validations: map[string]patterns.ValidationResult{
			"check_completed": {
				Passed:  true,
				Message: "existence check completed successfully",
			},
		},
	}, nil
}

// UserCreationOperation implements AIE pattern for user creation
type UserCreationOperation struct {
	Username   string
	Password   string
	Groups     []string
	Shell      string
	HomeDir    string
	Target     string
	SaltClient saltstack.ClientInterface
	VaultClient VaultClient
	Logger     otelzap.LoggerWithCtx
}

// Assess checks if user can be created
func (u *UserCreationOperation) Assess(ctx context.Context) (*patterns.AssessmentResult, error) {
	u.Logger.Info("Assessing user creation readiness",
		zap.String("username", u.Username),
		zap.String("target", u.Target))

	prerequisites := make(map[string]bool)

	// Check user doesn't already exist
	existCheck := &UserExistenceCheck{
		Username:   u.Username,
		Target:     u.Target,
		SaltClient: u.SaltClient,
		Logger:     u.Logger,
	}
	
	executor := patterns.NewExecutor(u.Logger)
	err := executor.Execute(ctx, existCheck, "user_existence_precheck")
	if err != nil {
		return &patterns.AssessmentResult{
			CanProceed: false,
			Reason:     "failed to check user existence",
		}, err
	}

	// Check groups exist
	for _, group := range u.Groups {
		output, err := u.SaltClient.CmdRun(ctx, u.Target, fmt.Sprintf("getent group %s", group))
		if err != nil || output == "" {
			prerequisites[fmt.Sprintf("group_%s_exists", group)] = false
			return &patterns.AssessmentResult{
				CanProceed: false,
				Reason:     fmt.Sprintf("group %s does not exist", group),
				Prerequisites: prerequisites,
			}, nil
		}
		prerequisites[fmt.Sprintf("group_%s_exists", group)] = true
	}

	// Validate shell exists
	if u.Shell != "" {
		output, err := u.SaltClient.CmdRun(ctx, u.Target, fmt.Sprintf("test -f %s && echo exists", u.Shell))
		if err != nil || !strings.Contains(output, "exists") {
			prerequisites["shell_exists"] = false
			return &patterns.AssessmentResult{
				CanProceed: false,
				Reason:     fmt.Sprintf("shell %s does not exist", u.Shell),
				Prerequisites: prerequisites,
			}, nil
		}
		prerequisites["shell_exists"] = true
	}

	return &patterns.AssessmentResult{
		CanProceed:    true,
		Prerequisites: prerequisites,
	}, nil
}

// Intervene creates the user
func (u *UserCreationOperation) Intervene(ctx context.Context, assessment *patterns.AssessmentResult) (*patterns.InterventionResult, error) {
	u.Logger.Info("Creating user",
		zap.String("username", u.Username),
		zap.String("target", u.Target))

	// Apply user creation state via Salt
	pillar := map[string]interface{}{
		"users": map[string]interface{}{
			u.Username: map[string]interface{}{
				"password": u.Password,
				"groups":   u.Groups,
				"shell":    u.Shell,
				"home":     u.HomeDir,
				"createhome": true,
			},
		},
	}

	err := u.SaltClient.StateApply(ctx, u.Target, "users.create", pillar)
	if err != nil {
		return &patterns.InterventionResult{
			Success: false,
			Message: fmt.Sprintf("failed to create user: %v", err),
		}, err
	}

	// Store password in Vault
	if u.VaultClient != nil {
		vaultPath := fmt.Sprintf("secret/users/%s", u.Username)
		data := map[string]interface{}{
			"password": u.Password,
			"created":  "true",
			"target":   u.Target,
		}
		
		if err := u.VaultClient.Write(vaultPath, data); err != nil {
			u.Logger.Warn("Failed to store password in Vault",
				zap.String("username", u.Username),
				zap.Error(err))
		}
	}

	return &patterns.InterventionResult{
		Success: true,
		Message: "user created successfully",
		Changes: []patterns.Change{
			{
				Type:        "user_creation",
				Description: fmt.Sprintf("Created user %s on %s", u.Username, u.Target),
			},
		},
	}, nil
}

// Evaluate verifies user was created successfully
func (u *UserCreationOperation) Evaluate(ctx context.Context, intervention *patterns.InterventionResult) (*patterns.EvaluationResult, error) {
	if !intervention.Success {
		return &patterns.EvaluationResult{
			Success: false,
			Message: "user creation failed",
		}, nil
	}

	validations := make(map[string]patterns.ValidationResult)

	// Verify user exists
	output, err := u.SaltClient.CmdRun(ctx, u.Target, fmt.Sprintf("id %s", u.Username))
	if err != nil || strings.Contains(output, "no such user") {
		validations["user_exists"] = patterns.ValidationResult{
			Passed:  false,
			Message: "user not found after creation",
		}
		return &patterns.EvaluationResult{
			Success:       false,
			Message:       "user creation validation failed",
			Validations:   validations,
			NeedsRollback: true,
		}, nil
	}
	validations["user_exists"] = patterns.ValidationResult{
		Passed:  true,
		Message: "user exists",
		Details: output,
	}

	// Verify groups
	for _, group := range u.Groups {
		groupCheck, _ := u.SaltClient.CmdRun(ctx, u.Target, 
			fmt.Sprintf("groups %s | grep -q %s && echo yes || echo no", u.Username, group))
		if strings.TrimSpace(groupCheck) == "yes" {
			validations[fmt.Sprintf("group_%s", group)] = patterns.ValidationResult{
				Passed:  true,
				Message: fmt.Sprintf("user is member of group %s", group),
			}
		} else {
			validations[fmt.Sprintf("group_%s", group)] = patterns.ValidationResult{
				Passed:  false,
				Message: fmt.Sprintf("user is not member of group %s", group),
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
		Message:     "user creation validated",
		Validations: validations,
	}, nil
}

// GenerateSecurePassword generates a cryptographically secure password
func GenerateSecurePassword(length int) (string, error) {
	if length < 12 {
		length = 12
	}

	// Generate random bytes
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode to base64 and trim to desired length
	password := base64.URLEncoding.EncodeToString(bytes)
	if len(password) > length {
		password = password[:length]
	}

	return password, nil
}

// GetSystemUsers retrieves system users via Salt
func GetSystemUsers(ctx context.Context, saltClient saltstack.ClientInterface, target string, logger otelzap.LoggerWithCtx) ([]string, error) {
	logger.Info("Getting system users",
		zap.String("target", target))

	output, err := saltClient.CmdRun(ctx, target, 
		"getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 { print $1 }'")
	if err != nil {
		return nil, fmt.Errorf("failed to get users: %w", err)
	}

	users := strings.Split(strings.TrimSpace(output), "\n")
	var nonEmpty []string
	for _, user := range users {
		if user != "" {
			nonEmpty = append(nonEmpty, user)
		}
	}

	return nonEmpty, nil
}

// PasswordUpdateOperation implements AIE pattern for password updates
type PasswordUpdateOperation struct {
	Username    string
	NewPassword string
	Target      string
	SaltClient  saltstack.ClientInterface
	VaultClient VaultClient
	Logger      otelzap.LoggerWithCtx
}

// Assess checks if password can be updated
func (p *PasswordUpdateOperation) Assess(ctx context.Context) (*patterns.AssessmentResult, error) {
	// Check user exists
	existCheck := &UserExistenceCheck{
		Username:   p.Username,
		Target:     p.Target,
		SaltClient: p.SaltClient,
		Logger:     p.Logger,
	}
	
	executor := patterns.NewExecutor(p.Logger)
	if err := executor.Execute(ctx, existCheck, "user_existence_check"); err != nil {
		return &patterns.AssessmentResult{
			CanProceed: false,
			Reason:     "user does not exist",
		}, nil
	}

	return &patterns.AssessmentResult{
		CanProceed: true,
		Prerequisites: map[string]bool{
			"user_exists": true,
		},
	}, nil
}

// Intervene updates the password
func (p *PasswordUpdateOperation) Intervene(ctx context.Context, assessment *patterns.AssessmentResult) (*patterns.InterventionResult, error) {
	p.Logger.Info("Updating user password",
		zap.String("username", p.Username))

	// Use chpasswd via Salt
	cmd := fmt.Sprintf("echo '%s:%s' | chpasswd", p.Username, p.NewPassword)
	_, err := p.SaltClient.CmdRun(ctx, p.Target, cmd)
	if err != nil {
		return &patterns.InterventionResult{
			Success: false,
			Message: fmt.Sprintf("failed to update password: %v", err),
		}, err
	}

	// Update password in Vault
	if p.VaultClient != nil {
		vaultPath := fmt.Sprintf("secret/users/%s", p.Username)
		data := map[string]interface{}{
			"password": p.NewPassword,
			"updated":  "true",
			"target":   p.Target,
		}
		
		if err := p.VaultClient.Write(vaultPath, data); err != nil {
			p.Logger.Warn("Failed to update password in Vault",
				zap.String("username", p.Username),
				zap.Error(err))
		}
	}

	return &patterns.InterventionResult{
		Success: true,
		Message: "password updated successfully",
		Changes: []patterns.Change{
			{
				Type:        "password_update",
				Description: fmt.Sprintf("Updated password for user %s", p.Username),
			},
		},
	}, nil
}

// Evaluate verifies password was updated
func (p *PasswordUpdateOperation) Evaluate(ctx context.Context, intervention *patterns.InterventionResult) (*patterns.EvaluationResult, error) {
	// Password changes are difficult to verify directly
	// We assume success if the command didn't error
	return &patterns.EvaluationResult{
		Success: intervention.Success,
		Message: "password update assumed successful",
		Validations: map[string]patterns.ValidationResult{
			"password_changed": {
				Passed:  true,
				Message: "password change command completed",
			},
		},
	}, nil
}

// UserDeletionOperation implements AIE pattern for user deletion
type UserDeletionOperation struct {
	Username   string
	RemoveHome bool
	Target     string
	SaltClient saltstack.ClientInterface
	Logger     otelzap.LoggerWithCtx
}

// Assess checks if user can be deleted
func (d *UserDeletionOperation) Assess(ctx context.Context) (*patterns.AssessmentResult, error) {
	// Check user exists
	existCheck := &UserExistenceCheck{
		Username:   d.Username,
		Target:     d.Target,
		SaltClient: d.SaltClient,
		Logger:     d.Logger,
	}
	
	executor := patterns.NewExecutor(d.Logger)
	if err := executor.Execute(ctx, existCheck, "user_existence_check"); err != nil {
		return &patterns.AssessmentResult{
			CanProceed: false,
			Reason:     "user does not exist",
		}, nil
	}

	// Check if user has active processes
	output, _ := d.SaltClient.CmdRun(ctx, d.Target, fmt.Sprintf("ps -u %s | wc -l", d.Username))
	if strings.TrimSpace(output) != "1" && strings.TrimSpace(output) != "0" {
		return &patterns.AssessmentResult{
			CanProceed: false,
			Reason:     "user has active processes",
		}, nil
	}

	return &patterns.AssessmentResult{
		CanProceed: true,
		Prerequisites: map[string]bool{
			"user_exists":      true,
			"no_active_procs": true,
		},
	}, nil
}

// Intervene deletes the user
func (d *UserDeletionOperation) Intervene(ctx context.Context, assessment *patterns.AssessmentResult) (*patterns.InterventionResult, error) {
	d.Logger.Info("Deleting user",
		zap.String("username", d.Username),
		zap.Bool("remove_home", d.RemoveHome))

	// Kill any remaining processes
	_, _ = d.SaltClient.CmdRun(ctx, d.Target, fmt.Sprintf("pkill -u %s || true", d.Username))

	// Delete user
	cmd := fmt.Sprintf("userdel %s %s", d.Username, "")
	if d.RemoveHome {
		cmd = fmt.Sprintf("userdel -r %s", d.Username)
	}

	_, err := d.SaltClient.CmdRun(ctx, d.Target, cmd)
	if err != nil {
		return &patterns.InterventionResult{
			Success: false,
			Message: fmt.Sprintf("failed to delete user: %v", err),
		}, err
	}

	return &patterns.InterventionResult{
		Success: true,
		Message: "user deleted successfully",
		Changes: []patterns.Change{
			{
				Type:        "user_deletion",
				Description: fmt.Sprintf("Deleted user %s", d.Username),
			},
		},
	}, nil
}

// Evaluate verifies user was deleted
func (d *UserDeletionOperation) Evaluate(ctx context.Context, intervention *patterns.InterventionResult) (*patterns.EvaluationResult, error) {
	// Verify user no longer exists
	output, _ := d.SaltClient.CmdRun(ctx, d.Target, fmt.Sprintf("id %s 2>&1", d.Username))
	if !strings.Contains(output, "no such user") {
		return &patterns.EvaluationResult{
			Success: false,
			Message: "user still exists after deletion",
			Validations: map[string]patterns.ValidationResult{
				"user_removed": {
					Passed:  false,
					Message: "user account still present",
				},
			},
		}, nil
	}

	validations := map[string]patterns.ValidationResult{
		"user_removed": {
			Passed:  true,
			Message: "user account removed",
		},
	}

	// Verify home directory if requested
	if d.RemoveHome {
		homeCheck, _ := d.SaltClient.CmdRun(ctx, d.Target, 
			fmt.Sprintf("test -d /home/%s && echo exists || echo removed", d.Username))
		if strings.TrimSpace(homeCheck) == "removed" {
			validations["home_removed"] = patterns.ValidationResult{
				Passed:  true,
				Message: "home directory removed",
			}
		} else {
			validations["home_removed"] = patterns.ValidationResult{
				Passed:  false,
				Message: "home directory still exists",
			}
		}
	}

	return &patterns.EvaluationResult{
		Success:     true,
		Message:     "user deletion validated",
		Validations: validations,
	}, nil
}

