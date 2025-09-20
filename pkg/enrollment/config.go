package enrollment

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// ParseEnrollmentFlags parses command line flags into EnrollmentConfig
// Migrated from cmd/self/enroll.go parseEnrollmentFlags
func ParseEnrollmentFlags(cmd *cobra.Command) (*EnrollmentConfig, error) {
	// ASSESS - Extract flag values
	role, _ := cmd.Flags().GetString("role")
	ess, _ := cmd.Flags().GetString("master-address")
	datacenter, _ := cmd.Flags().GetString("datacenter")
	networkMode, _ := cmd.Flags().GetString("network-mode")
	autoDetect, _ := cmd.Flags().GetBool("auto-detect")
	transitionMode, _ := cmd.Flags().GetBool("transition-mode")
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	// INTERVENE - Create configuration
	config := &EnrollmentConfig{
		Role:           role,
		ess:            ess,
		Datacenter:     datacenter,
		NetworkMode:    networkMode,
		AutoDetect:     autoDetect,
		TransitionMode: transitionMode,
		DryRun:         dryRun,
	}

	// EVALUATE - Return parsed configuration
	return config, nil
}

// ParseEnrollmentFlagsWithPrompts parses command line flags and prompts for missing required values
func ParseEnrollmentFlagsWithPrompts(rc *eos_io.RuntimeContext, cmd *cobra.Command) (*EnrollmentConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Extract flag values
	role, _ := cmd.Flags().GetString("role")
	ess, _ := cmd.Flags().GetString("master-address")
	datacenter, _ := cmd.Flags().GetString("datacenter")
	networkMode, _ := cmd.Flags().GetString("network-mode")
	autoDetect, _ := cmd.Flags().GetBool("auto-detect")
	transitionMode, _ := cmd.Flags().GetBool("transition-mode")
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	// INTERVENE - Prompt for missing required values
	if datacenter == "" {
		logger.Info("Datacenter not provided via flag, prompting user")
		var err error
		datacenter, err = eos_io.PromptInputWithValidation(rc, "Enter datacenter identifier: ", "datacenter")
		if err != nil {
			return nil, fmt.Errorf("failed to read datacenter: %w", err)
		}
	}

	if !autoDetect && role == "" {
		logger.Info("Role not provided via flag and auto-detect disabled, prompting user")
		var err error
		role, err = eos_io.PromptInputWithValidation(rc, "Enter role (master or minion): ", "role")
		if err != nil {
			return nil, fmt.Errorf("failed to read role: %w", err)
		}
	}

	if role == "client" && ess == "" {
		logger.Info("Consul address not provided via flag for client role, prompting user")
		var err error
		ess, err = eos_io.PromptInputWithValidation(rc, "Enter HashiCorp Consul address: ", "consul-address")
		if err != nil {
			return nil, fmt.Errorf("failed to read master address: %w", err)
		}
	}

	// Create configuration
	config := &EnrollmentConfig{
		Role:           role,
		ess:            ess,
		Datacenter:     datacenter,
		NetworkMode:    networkMode,
		AutoDetect:     autoDetect,
		TransitionMode: transitionMode,
		DryRun:         dryRun,
	}

	// EVALUATE - Return parsed configuration
	return config, nil
}

// ValidateEnrollmentConfig validates the enrollment configuration
// Migrated from cmd/self/enroll.go validateEnrollmentConfig
func ValidateEnrollmentConfig(config *EnrollmentConfig) error {
	// ASSESS - Check required fields
	if config.Datacenter == "" {
		return fmt.Errorf("datacenter is required")
	}

	if !config.AutoDetect && config.Role == "" {
		return fmt.Errorf("role is required unless --auto-detect is specified")
	}

	// INTERVENE - Validate role-specific requirements for HashiCorp
	if config.Role == "client" && config.ess == "" {
		return fmt.Errorf("consul-address is required for client role")
	}

	if config.Role == RoleMaster && config.ess != "" {
		return fmt.Errorf("master-address should not be specified for master role")
	}

	// Validate network mode
	validNetworkModes := []string{NetworkModeDirect, NetworkModeConsul, NetworkModeWireGuard}
	if config.NetworkMode != "" {
		found := false
		for _, mode := range validNetworkModes {
			if config.NetworkMode == mode {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("invalid network-mode: %s (valid options: %v)", config.NetworkMode, validNetworkModes)
		}
	}

	// EVALUATE - Configuration is valid
	return nil
}
