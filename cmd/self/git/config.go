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

var ConfigCmd = &cobra.Command{
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
		name, _ := cmd.Flags().GetString("name")
		email, _ := cmd.Flags().GetString("email")
		defaultBranch, _ := cmd.Flags().GetString("default-branch")
		pullRebase, _ := cmd.Flags().GetBool("pull-rebase")
		noColorUI, _ := cmd.Flags().GetBool("no-color")
		global, _ := cmd.Flags().GetBool("global")
		interactive, _ := cmd.Flags().GetBool("interactive")
		outputJSON, _ := cmd.Flags().GetBool("json")
		showConfig, _ := cmd.Flags().GetBool("show")
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

func init() {
	ConfigCmd.Flags().String("name", "", "Git user name")
	ConfigCmd.Flags().String("email", "", "Git user email")
	ConfigCmd.Flags().String("default-branch", "", "Default branch name (e.g., main)")
	ConfigCmd.Flags().Bool("pull-rebase", false, "Use rebase for git pull")
	ConfigCmd.Flags().Bool("no-color", false, "Disable color output")
	ConfigCmd.Flags().Bool("global", false, "Configure globally (default: local)")
	ConfigCmd.Flags().BoolP("interactive", "i", false, "Interactive configuration mode")
	ConfigCmd.Flags().Bool("json", false, "Output configuration in JSON format")
	ConfigCmd.Flags().Bool("show", false, "Show current configuration")
}

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
func showCurrentConfig(rc *eos_io.RuntimeContext, manager *git_management.GitManager, global, outputJSON bool) error {
	logger := otelzap.Ctx(rc.Ctx)
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
		logger.Info("terminal prompt: " + string(data))
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer func() {
		if err := w.Flush(); err != nil {
			logger.Info("terminal prompt: Warning: Failed to flush tabwriter", zap.Error(err))
		}
	}()

	scope := "Local"
	if global {
		scope = "Global"
	}

	logger.Info(fmt.Sprintf("terminal prompt: Git Configuration (%s)", scope))
	logger.Info("terminal prompt: ========================")

	_, _ = fmt.Fprintf(w, "Name:\t%s\n", config.Name)
	_, _ = fmt.Fprintf(w, "Email:\t%s\n", config.Email)
	_, _ = fmt.Fprintf(w, "Default Branch:\t%s\n", config.DefaultBranch)
	_, _ = fmt.Fprintf(w, "Pull Rebase:\t%t\n", config.PullRebase)
	_, _ = fmt.Fprintf(w, "Color UI:\t%t\n", config.ColorUI)

	if len(config.Custom) > 0 {
		logger.Info("terminal prompt: Custom Settings:")
		for key, value := range config.Custom {
			_, _ = fmt.Fprintf(w, "%s:\t%s\n", key, value)
		}
	}

	return nil
}

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
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

	logger.Info("terminal prompt: Interactive Git Configuration")
	logger.Info("terminal prompt: ============================\n")

	// Name
	logger.Info(fmt.Sprintf("terminal prompt: Current name: %s", currentConfig.Name))
	logger.Info("terminal prompt: Enter your name (or press Enter to keep current): ")
	var name string
	_, _ = fmt.Scanln(&name)
	if name != "" {
		config.Name = name
	} else {
		config.Name = currentConfig.Name
	}

	// Email
	logger.Info(fmt.Sprintf("terminal prompt: Current email: %s", currentConfig.Email))
	logger.Info("terminal prompt: Enter your email (or press Enter to keep current): ")
	var email string
	_, _ = fmt.Scanln(&email)
	if email != "" {
		config.Email = email
	} else {
		config.Email = currentConfig.Email
	}

	// Default branch
	logger.Info(fmt.Sprintf("terminal prompt: Current default branch: %s", currentConfig.DefaultBranch))
	logger.Info("terminal prompt: Enter default branch name [main] (or press Enter to keep current): ")
	var branch string
	_, _ = fmt.Scanln(&branch)
	if branch != "" {
		config.DefaultBranch = branch
	} else if currentConfig.DefaultBranch == "" {
		config.DefaultBranch = "main"
	} else {
		config.DefaultBranch = currentConfig.DefaultBranch
	}

	// Pull rebase
	logger.Info(fmt.Sprintf("terminal prompt: Current pull rebase: %t", currentConfig.PullRebase))
	logger.Info("terminal prompt: Use rebase for git pull? [y/N]: ")
	var rebaseResponse string
	_, _ = fmt.Scanln(&rebaseResponse)
	config.PullRebase = rebaseResponse == "y" || rebaseResponse == "Y"

	// Color UI
	logger.Info(fmt.Sprintf("terminal prompt: Current color UI: %t", currentConfig.ColorUI))
	logger.Info("terminal prompt: Enable color output? [Y/n]: ")
	var colorResponse string
	_, _ = fmt.Scanln(&colorResponse)
	config.ColorUI = colorResponse != "n" && colorResponse != "N"

	logger.Info("Applying interactive Git configuration", zap.Bool("global", global))
	return manager.ConfigureGit(rc, config, global)
}
