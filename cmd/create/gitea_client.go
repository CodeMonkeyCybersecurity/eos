// cmd/create/gitea_client.go
// Command to configure SSH client access to a Gitea instance

package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/gitea"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreateGiteaClientCmd configures SSH client access to a self-hosted Gitea instance
var CreateGiteaClientCmd = &cobra.Command{
	Use:   "gitea-client",
	Short: "Configure SSH client access to a self-hosted Gitea instance",
	Long: `Configure SSH-based authentication for a self-hosted Gitea instance.

This command will:
1. Generate an SSH key pair for Gitea authentication
2. Add an entry to ~/.ssh/config for easy access
3. Save the instance configuration for future use

After running this command, you'll need to:
1. Add the generated public key to your Gitea account
2. Create the repository in Gitea (if it doesn't exist)
3. Add the remote to your local git repository

Examples:
  # Interactive setup (prompts for all values)
  eos create gitea-client

  # Specify all options via flags
  eos create gitea-client --name vhost7 --host vhost7 --http-port 8167 --ssh-port 2222

  # Include organization
  eos create gitea-client --name prod-gitea --host git.example.com --org mycompany

  # Test connection to configured instance
  eos create gitea-client --test

  # List configured instances
  eos create gitea-client --list`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// P0: Validate no flag-like args
		if err := verify.ValidateNoFlagLikeArgs(args); err != nil {
			return err
		}

		// Handle --list flag
		listFlag, _ := cmd.Flags().GetBool("list")
		if listFlag {
			return listGiteaClientInstances(rc)
		}

		// Handle --test flag
		testFlag, _ := cmd.Flags().GetBool("test")
		instanceName, _ := cmd.Flags().GetString("instance")
		if testFlag {
			return testGiteaClientConnection(rc, instanceName)
		}

		// Regular setup flow
		logger.Info("Starting Gitea integration setup")

		config, err := gatherGiteaClientConfig(rc, cmd)
		if err != nil {
			return fmt.Errorf("failed to gather configuration: %w", err)
		}

		result, err := gitea.Setup(rc, config)
		if err != nil {
			return fmt.Errorf("setup failed: %w", err)
		}

		// Display results
		fmt.Print(result.Instructions)

		// Log warnings
		for _, warning := range result.Warnings {
			logger.Warn("Setup warning", zap.String("message", warning))
		}

		return nil
	}),
}

// gatherGiteaClientConfig collects configuration from flags or interactive prompts
func gatherGiteaClientConfig(rc *eos_io.RuntimeContext, cmd *cobra.Command) (*gitea.Config, error) {
	logger := otelzap.Ctx(rc.Ctx)
	config := gitea.DefaultConfig()

	// Instance name
	nameFlag, _ := cmd.Flags().GetString("name")
	nameWasSet := cmd.Flags().Changed("name")
	nameResult, err := interaction.GetRequiredString(rc, nameFlag, nameWasSet, &interaction.RequiredFlagConfig{
		FlagName:      "name",
		PromptMessage: "Enter instance name (e.g., 'vhost7' or 'prod-gitea'): ",
		HelpText:      "A friendly name to identify this Gitea instance",
	})
	if err != nil {
		return nil, err
	}
	config.InstanceName = nameResult.Value
	logger.Info("Using instance name", zap.String("source", string(nameResult.Source)))

	// Hostname
	hostFlag, _ := cmd.Flags().GetString("host")
	hostWasSet := cmd.Flags().Changed("host")
	hostResult, err := interaction.GetRequiredString(rc, hostFlag, hostWasSet, &interaction.RequiredFlagConfig{
		FlagName:      "host",
		EnvVarName:    "GITEA_HOST",
		PromptMessage: "Enter Gitea hostname or IP (e.g., 'vhost7' or '192.168.1.50'): ",
		HelpText:      "The hostname or IP address of your Gitea server",
	})
	if err != nil {
		return nil, err
	}
	config.Hostname = hostResult.Value
	logger.Info("Using hostname", zap.String("source", string(hostResult.Source)))

	// HTTP Port
	httpPortFlag, _ := cmd.Flags().GetInt("http-port")
	httpPortWasSet := cmd.Flags().Changed("http-port")
	httpPort, httpPortSource, err := interaction.GetRequiredInt(rc, httpPortFlag, httpPortWasSet, &interaction.RequiredFlagConfig{
		FlagName:      "http-port",
		EnvVarName:    "GITEA_HTTP_PORT",
		PromptMessage: "Enter Gitea web UI port (e.g., 3000, 8167): ",
		HelpText:      "The HTTP port for Gitea web interface",
		Validator: func(s string) error {
			// Validation is handled by GetRequiredInt
			return nil
		},
	})
	if err != nil {
		return nil, err
	}
	config.HTTPPort = httpPort
	logger.Info("Using HTTP port", zap.String("source", string(httpPortSource)))

	// SSH Port
	sshPortFlag, _ := cmd.Flags().GetInt("ssh-port")
	sshPortWasSet := cmd.Flags().Changed("ssh-port")
	sshPort, sshPortSource, err := interaction.GetRequiredInt(rc, sshPortFlag, sshPortWasSet, &interaction.RequiredFlagConfig{
		FlagName:      "ssh-port",
		EnvVarName:    "GITEA_SSH_PORT",
		PromptMessage: "Enter Gitea SSH port (common: 22, 2222): ",
		HelpText:      "The SSH port for git operations. Docker setups often use 2222",
		DefaultValue:  "2222",
		AllowEmpty:    true,
	})
	if err != nil {
		return nil, err
	}
	config.SSHPort = sshPort
	logger.Info("Using SSH port", zap.String("source", string(sshPortSource)))

	// Organization (optional)
	orgFlag, _ := cmd.Flags().GetString("org")
	if orgFlag != "" {
		config.Organization = orgFlag
		logger.Info("Using organization", zap.String("org", orgFlag))
	} else if interaction.IsTTY() {
		// Prompt for optional organization
		logger.Info("terminal prompt: Organization is optional - press Enter to skip")
		orgValue, err := eos_io.PromptInput(rc, "Enter default organization (optional, press Enter to skip): ", "organization")
		if err != nil {
			logger.Warn("Failed to prompt for organization", zap.Error(err))
		} else if orgValue != "" {
			config.Organization = orgValue
			logger.Info("Using organization from prompt", zap.String("org", orgValue))
		}
	}

	// Key name (derived from instance name if not specified)
	keyNameFlag, _ := cmd.Flags().GetString("key-name")
	if keyNameFlag != "" {
		config.SSHKeyName = keyNameFlag
	}

	// Set as default
	defaultFlag, _ := cmd.Flags().GetBool("default")
	config.Default = defaultFlag

	return config, nil
}

// listGiteaClientInstances displays all configured Gitea instances
func listGiteaClientInstances(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	instances, defaultInstance, err := gitea.ListInstances(rc)
	if err != nil {
		return err
	}

	if len(instances) == 0 {
		fmt.Println("No Gitea instances configured.")
		fmt.Println("Run 'eos create gitea-client' to configure one.")
		return nil
	}

	fmt.Println("Configured Gitea Instances:")
	fmt.Println("----------------------------")
	for _, inst := range instances {
		defaultMarker := ""
		if inst.Name == defaultInstance {
			defaultMarker = " (default)"
		}
		fmt.Printf("  %s%s\n", inst.Name, defaultMarker)
		fmt.Printf("    Hostname:   %s\n", inst.Hostname)
		fmt.Printf("    HTTP Port:  %d\n", inst.HTTPPort)
		fmt.Printf("    SSH Port:   %d\n", inst.SSHPort)
		fmt.Printf("    SSH Host:   %s\n", inst.SSHConfigHost)
		if inst.Organization != "" {
			fmt.Printf("    Organization: %s\n", inst.Organization)
		}
		fmt.Println()
	}

	logger.Info("Listed gitea instances", zap.Int("count", len(instances)))
	return nil
}

// testGiteaClientConnection tests SSH connectivity to a Gitea instance
func testGiteaClientConnection(rc *eos_io.RuntimeContext, instanceName string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Testing SSH connection", zap.String("instance", instanceName))

	if err := gitea.TestConnection(rc, instanceName); err != nil {
		return err
	}

	fmt.Println("SSH connection test successful!")
	return nil
}

func init() {
	CreateCmd.AddCommand(CreateGiteaClientCmd)

	// Instance identification
	CreateGiteaClientCmd.Flags().String("name", "", "Friendly name for this Gitea instance (e.g., 'vhost7')")
	CreateGiteaClientCmd.Flags().String("host", "", "Gitea hostname or IP address")

	// Port configuration
	CreateGiteaClientCmd.Flags().Int("http-port", 0, "HTTP port for Gitea web UI (e.g., 3000, 8167)")
	CreateGiteaClientCmd.Flags().Int("ssh-port", 2222, "SSH port for git operations (often 22 or 2222)")

	// Optional configuration
	CreateGiteaClientCmd.Flags().String("org", "", "Default organization for repositories")
	CreateGiteaClientCmd.Flags().String("key-name", "", "Name for the SSH key (defaults to 'gitea-<instance>')")
	CreateGiteaClientCmd.Flags().Bool("default", false, "Set this as the default Gitea instance")

	// Utility flags
	CreateGiteaClientCmd.Flags().Bool("list", false, "List all configured Gitea instances")
	CreateGiteaClientCmd.Flags().Bool("test", false, "Test SSH connection to configured instance")
	CreateGiteaClientCmd.Flags().String("instance", "", "Instance name for --test (uses default if not specified)")
}
