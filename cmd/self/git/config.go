package git

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/git_management"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// newConfigCmd creates the Git configuration command
func newConfigCmd() *cobra.Command {
	var (
		name          string
		email         string
		defaultBranch string
		pullRebase    bool
		noColorUI     bool
		global        bool
		interactive   bool
		outputJSON    bool
		showConfig    bool
	)

	cmd := &cobra.Command{
		Use:     "config",
		Aliases: []string{"cfg"},
		Short:   "Configure Git settings",
		Long: `Configure Git settings locally or globally.

This command provides comprehensive Git configuration management:
- Set user name and email
- Configure default branch name
- Set pull behavior (rebase vs merge)
- Enable/disable color output
- Interactive configuration mode

Examples:
  eos git config --global --interactive          # Interactive global config
  eos git config --name "John Doe" --global      # Set global name
  eos git config --email "john@example.com"      # Set local email
  eos git config --show --json                   # Show current config as JSON
  eos git config --default-branch main --global  # Set default branch`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

			manager := git_management.NewGitManager()

			// Show current configuration if requested
			if showConfig {
				return showCurrentConfig(rc, manager, global, outputJSON)
			}

			// Interactive mode
			if interactive {
				return runInteractiveConfig(rc, manager, global)
			}

			// Build configuration from flags
			config := &git_management.GitConfig{
				Name:          name,
				Email:         email,
				DefaultBranch: defaultBranch,
				PullRebase:    pullRebase,
				ColorUI:       !noColorUI,
				Custom:        make(map[string]string),
			}

			// Only configure if at least one setting is provided
			if name == "" && email == "" && defaultBranch == "" && !cmd.Flags().Changed("pull-rebase") && !cmd.Flags().Changed("no-color") {
				return showCurrentConfig(rc, manager, global, outputJSON)
			}

			logger.Info("Configuring Git", 
				zap.Bool("global", global),
				zap.String("name", name),
				zap.String("email", email))

			return manager.ConfigureGit(rc, config, global)
		}),
	}

	cmd.Flags().StringVar(&name, "name", "", "Git user name")
	cmd.Flags().StringVar(&email, "email", "", "Git user email")
	cmd.Flags().StringVar(&defaultBranch, "default-branch", "", "Default branch name (e.g., main)")
	cmd.Flags().BoolVar(&pullRebase, "pull-rebase", false, "Use rebase for git pull")
	cmd.Flags().BoolVar(&noColorUI, "no-color", false, "Disable color output")
	cmd.Flags().BoolVar(&global, "global", false, "Configure globally (default: local)")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Interactive configuration mode")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output configuration in JSON format")
	cmd.Flags().BoolVar(&showConfig, "show", false, "Show current configuration")

	return cmd
}

func showCurrentConfig(rc *eos_io.RuntimeContext, manager *git_management.GitManager, global, outputJSON bool) error {
	path := "."
	if global {
		path = ""
	}

	config, err := manager.GetConfig(rc, path, global)
	if err != nil {
		return fmt.Errorf("failed to get configuration: %w", err)
	}

	if outputJSON {
		data, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	scope := "Local"
	if global {
		scope = "Global"
	}

	fmt.Printf("Git Configuration (%s)\n", scope)
	fmt.Printf("========================\n\n")

	fmt.Fprintf(w, "Name:\t%s\n", config.Name)
	fmt.Fprintf(w, "Email:\t%s\n", config.Email)
	fmt.Fprintf(w, "Default Branch:\t%s\n", config.DefaultBranch)
	fmt.Fprintf(w, "Pull Rebase:\t%t\n", config.PullRebase)
	fmt.Fprintf(w, "Color UI:\t%t\n", config.ColorUI)

	if len(config.Custom) > 0 {
		fmt.Printf("\nCustom Settings:\n")
		for key, value := range config.Custom {
			fmt.Fprintf(w, "%s:\t%s\n", key, value)
		}
	}

	return nil
}

func runInteractiveConfig(rc *eos_io.RuntimeContext, manager *git_management.GitManager, global bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	config := &git_management.GitConfig{
		Custom: make(map[string]string),
	}

	// Get current configuration
	path := "."
	if global {
		path = ""
	}
	currentConfig, err := manager.GetConfig(rc, path, global)
	if err != nil {
		logger.Warn("Could not get current configuration", zap.Error(err))
		currentConfig = &git_management.GitConfig{}
	}

	fmt.Printf("Interactive Git Configuration\n")
	fmt.Printf("============================\n\n")

	// Name
	fmt.Printf("Current name: %s\n", currentConfig.Name)
	fmt.Print("Enter your name (or press Enter to keep current): ")
	var name string
	fmt.Scanln(&name)
	if name != "" {
		config.Name = name
	} else {
		config.Name = currentConfig.Name
	}

	// Email
	fmt.Printf("Current email: %s\n", currentConfig.Email)
	fmt.Print("Enter your email (or press Enter to keep current): ")
	var email string
	fmt.Scanln(&email)
	if email != "" {
		config.Email = email
	} else {
		config.Email = currentConfig.Email
	}

	// Default branch
	fmt.Printf("Current default branch: %s\n", currentConfig.DefaultBranch)
	fmt.Print("Enter default branch name [main] (or press Enter to keep current): ")
	var branch string
	fmt.Scanln(&branch)
	if branch != "" {
		config.DefaultBranch = branch
	} else if currentConfig.DefaultBranch == "" {
		config.DefaultBranch = "main"
	} else {
		config.DefaultBranch = currentConfig.DefaultBranch
	}

	// Pull rebase
	fmt.Printf("Current pull rebase: %t\n", currentConfig.PullRebase)
	fmt.Print("Use rebase for git pull? [y/N]: ")
	var rebaseResponse string
	fmt.Scanln(&rebaseResponse)
	config.PullRebase = rebaseResponse == "y" || rebaseResponse == "Y"

	// Color UI
	fmt.Printf("Current color UI: %t\n", currentConfig.ColorUI)
	fmt.Print("Enable color output? [Y/n]: ")
	var colorResponse string
	fmt.Scanln(&colorResponse)
	config.ColorUI = colorResponse != "n" && colorResponse != "N"

	logger.Info("Applying interactive Git configuration", zap.Bool("global", global))
	return manager.ConfigureGit(rc, config, global)
}