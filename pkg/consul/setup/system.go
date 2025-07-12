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
			if step.Command == "useradd" && strings.Contains(err.Error(), "already exists") {
				log.Debug("Consul user already exists")
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
		checkCmd := execute.Options{
			Command: "stat",
			Args:    []string{"-c", "%U:%G", dir},
		}
		output, err := execute.Run(rc.Ctx, checkCmd)
		if err != nil {
			return fmt.Errorf("failed to verify directory %s: %w", dir, err)
		}

		expectedOwner := "consul:consul"
		if strings.TrimSpace(output) != expectedOwner {
			return fmt.Errorf("directory %s has incorrect ownership: expected %s, got %s", dir, expectedOwner, output)
		}
	}

	log.Info("Consul system user and directories created successfully",
		zap.String("user", "consul"),
		zap.String("home", "/etc/consul.d"),
		zap.Strings("directories", dirs))

	return nil
}
