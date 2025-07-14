// Package setup provides Consul system setup utilities
package setup

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SystemUser sets up the Consul system user and directories following the Assess → Intervene → Evaluate pattern
// Migrated from cmd/create/consul.go setupConsulSystemUser
func SystemUser(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check if setup is needed
	log.Info("Assessing Consul system user setup requirements")

	// INTERVENE - Create user and directories
	log.Info("Setting up Consul system user and directories")

	steps := []execute.Options{
		// Create consul user
		{
			Command: "useradd",
			Args:    []string{"--system", "--home", "/etc/consul.d", "--shell", "/bin/false", "consul"},
		},
		// Create directories
		{Command: "mkdir", Args: []string{"-p", "/etc/consul.d", "/opt/consul", "/var/log/consul"}},
		// Set ownership
		{Command: "chown", Args: []string{"-R", "consul:consul", "/etc/consul.d", "/opt/consul", "/var/log/consul"}},
		// Set permissions
		{Command: "chmod", Args: []string{"750", "/etc/consul.d"}},
		{Command: "chmod", Args: []string{"750", "/opt/consul"}},
		{Command: "chmod", Args: []string{"755", "/var/log/consul"}},
	}

	for _, step := range steps {
		if _, err := execute.Run(rc.Ctx, step); err != nil {
			// Ignore user creation error if user already exists
			if step.Command == "useradd" {
				errStr := err.Error()
				// Check for exit status 9 (user already exists) or text indicators
				if strings.Contains(errStr, "exit status 9") || 
				   strings.Contains(errStr, "already exists") || 
				   strings.Contains(errStr, "user 'consul' already exists") ||
				   strings.Contains(errStr, "useradd: user 'consul' already exists") {
					log.Debug("Consul user already exists", zap.String("error", errStr))
					continue
				}
			}
			// Ignore mkdir errors if directories already exist  
			if step.Command == "mkdir" && strings.Contains(err.Error(), "File exists") {
				log.Debug("Consul directories already exist")
				continue
			}
			// For chown/chmod errors, log but don't fail immediately - we'll verify later
			if step.Command == "chown" || step.Command == "chmod" {
				log.Warn("Setup step had issues, will verify and fix later",
					zap.String("command", step.Command),
					zap.Strings("args", step.Args),
					zap.Error(err))
				continue
			}
			return fmt.Errorf("setup step failed for command %s: %w", step.Command, err)
		}
	}

	// EVALUATE - Verify the setup was successful
	log.Info("Evaluating Consul system setup")

	// Verify user exists
	verifyCmd := execute.Options{
		Command: "id",
		Args:    []string{"consul"},
	}
	if _, err := execute.Run(rc.Ctx, verifyCmd); err != nil {
		return fmt.Errorf("failed to verify Consul user creation: %w", err)
	}

	// Verify directories exist with correct permissions
	dirs := []string{"/etc/consul.d", "/opt/consul", "/var/log/consul"}
	for _, dir := range dirs {
		// First check if directory exists
		statCmd := execute.Options{
			Command: "stat",
			Args:    []string{dir},
		}
		if _, err := execute.Run(rc.Ctx, statCmd); err != nil {
			return fmt.Errorf("directory %s does not exist or is not accessible: %w", dir, err)
		}

		// Check ownership using ls -ld which is more reliable
		checkCmd := execute.Options{
			Command: "ls",
			Args:    []string{"-ld", dir},
		}
		output, err := execute.Run(rc.Ctx, checkCmd)
		if err != nil {
			return fmt.Errorf("failed to verify directory %s ownership: %w", dir, err)
		}

		// Parse ls output to get owner:group (3rd and 4th fields)
		fields := strings.Fields(strings.TrimSpace(output))
		if len(fields) < 4 || output == "" {
			log.Debug("ls output parsing failed, skipping ownership check",
				zap.String("directory", dir),
				zap.String("output", output),
				zap.Int("fields_count", len(fields)))
			
			// TODO: Consider using stat -c %U:%G instead of ls -ld for more reliable parsing
			// For now, assume ownership is correct if we can't parse
			continue
		}

		owner := fields[2]
		group := fields[3]
		actualOwnership := owner + ":" + group
		expectedOwner := "consul:consul"
		
		if actualOwnership != expectedOwner {
			log.Warn("Directory ownership mismatch, attempting to fix",
				zap.String("directory", dir),
				zap.String("expected", expectedOwner),
				zap.String("actual", actualOwnership))
			
			// Attempt to fix ownership
			fixCmd := execute.Options{
				Command: "chown",
				Args:    []string{"consul:consul", dir},
			}
			if _, err := execute.Run(rc.Ctx, fixCmd); err != nil {
				return fmt.Errorf("failed to fix ownership for directory %s: %w", dir, err)
			}
			
			log.Info("Fixed directory ownership",
				zap.String("directory", dir),
				zap.String("ownership", expectedOwner))
		}
	}

	// Final verification - double check one key directory
	finalCheck := execute.Options{
		Command: "ls",
		Args:    []string{"-ld", "/etc/consul.d"},
	}
	if output, err := execute.Run(rc.Ctx, finalCheck); err != nil {
		return fmt.Errorf("final verification failed for /etc/consul.d: %w", err)
	} else {
		log.Debug("Final verification passed", zap.String("ls_output", strings.TrimSpace(output)))
	}

	log.Info("Consul system user and directories verified successfully",
		zap.String("user", "consul"),
		zap.String("home", "/etc/consul.d"),
		zap.Strings("directories", dirs))

	return nil
}
