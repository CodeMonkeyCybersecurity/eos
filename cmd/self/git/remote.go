package git

import (
	"encoding/json"
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/git/remote"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/git_management"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// remoteCmd manages Git remote repositories
var remoteCmd = &cobra.Command{
	Use:     "remote",
	Aliases: []string{"rm"},
	Short:   "Manage Git remotes",
	Long: `Manage Git remote repositories.

This command provides comprehensive remote management:
- Add new remotes
- Remove existing remotes  
- Change remote URLs
- Rename remotes
- List current remotes

Examples:
  eos git remote list                              # List all remotes
  eos git remote add origin https://github.com/user/repo.git
  eos git remote set-url origin https://new-url.git
  eos git remote remove upstream                   # Remove remote
  eos git remote rename origin upstream           # Rename remote`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for remote command")
		_ = cmd.Help()
		return nil
	}),
}

// remoteListCmd lists all configured Git remotes
var remoteListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List Git remotes",
	Long:    "List all configured Git remotes for the repository.",

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		config := remote.NewConfig()
		config.OutputJSON, _ = cmd.Flags().GetBool("json")

		if pathFlag, _ := cmd.Flags().GetString("path"); pathFlag != "" {
			config.Path = pathFlag
		}

		if err := config.SetDefaultPath(rc); err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}

		manager := git_management.NewGitManager()

		if !manager.IsGitRepository(rc, config.Path) {
			return fmt.Errorf("not a git repository: %s", config.Path)
		}

		repo, err := manager.GetRepositoryInfo(rc, config.Path)
		if err != nil {
			return fmt.Errorf("failed to get repository info: %w", err)
		}

		if config.OutputJSON {
			data, err := json.MarshalIndent(repo.RemoteURLs, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal JSON: %w", err)
			}
			logger.Info("terminal prompt: " + string(data))
			return nil
		}

		logger.Info("terminal prompt: Git Remotes")
		logger.Info("terminal prompt: ===========\n")

		if len(repo.RemoteURLs) == 0 {
			logger.Info("terminal prompt: No remotes configured")
			return nil
		}

		for name, url := range repo.RemoteURLs {
			logger.Info(fmt.Sprintf("terminal prompt: %s\t%s", name, url))
		}

		return nil
	}),
}

// remoteAddCmd adds a new Git remote
var remoteAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new Git remote",
	Long: `Add a new Git remote repository.

Examples:
  eos git remote add origin https://github.com/user/repo.git
  eos git remote add upstream https://github.com/upstream/repo.git`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		config := remote.NewConfig()
		if pathFlag, _ := cmd.Flags().GetString("path"); pathFlag != "" {
			config.Path = pathFlag
		}
		if nameFlag, _ := cmd.Flags().GetString("name"); nameFlag != "" {
			config.AddName = nameFlag
		}
		if urlFlag, _ := cmd.Flags().GetString("url"); urlFlag != "" {
			config.AddURL = urlFlag
		}

		if err := config.SetDefaultPath(rc); err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}

		if err := config.ValidateAddOperation(args); err != nil {
			return err
		}

		manager := git_management.NewGitManager()

		if !manager.IsGitRepository(rc, config.Path) {
			return fmt.Errorf("not a git repository: %s", config.Path)
		}

		operation := &git_management.GitRemoteOperation{
			Operation: "add",
			Name:      config.AddName,
			URL:       config.AddURL,
		}

		logger.Info(" Adding Git remote",
			zap.String("name", config.AddName),
			zap.String("url", config.AddURL))

		return manager.ManageRemote(rc, config.Path, operation)
	}),
}

// remoteSetURLCmd changes the URL of an existing Git remote
var remoteSetURLCmd = &cobra.Command{
	Use:   "set-url",
	Short: "Change the URL of an existing Git remote",
	Long: `Change the URL of an existing Git remote.

Examples:
  eos git remote set-url origin https://new-url.git
  eos git remote set-url --name origin --url https://new-url.git`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		config := remote.NewConfig()
		if pathFlag, _ := cmd.Flags().GetString("path"); pathFlag != "" {
			config.Path = pathFlag
		}
		if nameFlag, _ := cmd.Flags().GetString("name"); nameFlag != "" {
			config.SetURLName = nameFlag
		}
		if urlFlag, _ := cmd.Flags().GetString("url"); urlFlag != "" {
			config.SetURLURL = urlFlag
		}

		if err := config.SetDefaultPath(rc); err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}

		if err := config.ValidateSetURLOperation(args); err != nil {
			return err
		}

		manager := git_management.NewGitManager()

		if !manager.IsGitRepository(rc, config.Path) {
			return fmt.Errorf("not a git repository: %s", config.Path)
		}

		operation := &git_management.GitRemoteOperation{
			Operation: "set-url",
			Name:      config.SetURLName,
			URL:       config.SetURLURL,
		}

		logger.Info(" Changing Git remote URL",
			zap.String("name", config.SetURLName),
			zap.String("new_url", config.SetURLURL))

		return manager.ManageRemote(rc, config.Path, operation)
	}),
}

// remoteRemoveCmd removes a Git remote
var remoteRemoveCmd = &cobra.Command{
	Use:     "remove",
	Aliases: []string{"rm"},
	Short:   "Remove a Git remote",
	Long: `Remove an existing Git remote.

Examples:
  eos git remote remove origin
  eos git remote rm upstream`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		config := remote.NewConfig()
		if pathFlag, _ := cmd.Flags().GetString("path"); pathFlag != "" {
			config.Path = pathFlag
		}
		if nameFlag, _ := cmd.Flags().GetString("name"); nameFlag != "" {
			config.RemoveName = nameFlag
		}

		if err := config.SetDefaultPath(rc); err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}

		if err := config.ValidateRemoveOperation(args); err != nil {
			return err
		}

		manager := git_management.NewGitManager()

		if !manager.IsGitRepository(rc, config.Path) {
			return fmt.Errorf("not a git repository: %s", config.Path)
		}

		operation := &git_management.GitRemoteOperation{
			Operation: "remove",
			Name:      config.RemoveName,
		}

		logger.Info(" Removing Git remote", zap.String("name", config.RemoveName))

		return manager.ManageRemote(rc, config.Path, operation)
	}),
}

// remoteRenameCmd renames a Git remote
var remoteRenameCmd = &cobra.Command{
	Use:   "rename",
	Short: "Rename a Git remote",
	Long: `Rename an existing Git remote.

Examples:
  eos git remote rename origin upstream
  eos git remote rename --old-name origin --new-name upstream`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		config := remote.NewConfig()
		if pathFlag, _ := cmd.Flags().GetString("path"); pathFlag != "" {
			config.Path = pathFlag
		}
		if oldNameFlag, _ := cmd.Flags().GetString("old-name"); oldNameFlag != "" {
			config.RenameOldName = oldNameFlag
		}
		if newNameFlag, _ := cmd.Flags().GetString("new-name"); newNameFlag != "" {
			config.RenameNewName = newNameFlag
		}

		if err := config.SetDefaultPath(rc); err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}

		if err := config.ValidateRenameOperation(args); err != nil {
			return err
		}

		manager := git_management.NewGitManager()

		if !manager.IsGitRepository(rc, config.Path) {
			return fmt.Errorf("not a git repository: %s", config.Path)
		}

		operation := &git_management.GitRemoteOperation{
			Operation: "rename",
			Name:      config.RenameOldName,
			NewName:   config.RenameNewName,
		}

		logger.Info("🏷️ Renaming Git remote",
			zap.String("old_name", config.RenameOldName),
			zap.String("new_name", config.RenameNewName))

		return manager.ManageRemote(rc, config.Path, operation)
	}),
}

func init() {
	// Add subcommands
	remoteCmd.AddCommand(remoteListCmd)
	remoteCmd.AddCommand(remoteAddCmd)
	remoteCmd.AddCommand(remoteSetURLCmd)
	remoteCmd.AddCommand(remoteRemoveCmd)
	remoteCmd.AddCommand(remoteRenameCmd)

	// Configure flags for remote list
	remoteListCmd.Flags().StringP("path", "p", "", "Path to Git repository (default: current directory)")
	remoteListCmd.Flags().Bool("json", false, "Output in JSON format")

	// Configure flags for remote add
	remoteAddCmd.Flags().StringP("path", "p", "", "Path to Git repository (default: current directory)")
	remoteAddCmd.Flags().String("name", "", "Remote name")
	remoteAddCmd.Flags().String("url", "", "Remote URL")

	// Configure flags for remote set-url
	remoteSetURLCmd.Flags().StringP("path", "p", "", "Path to Git repository (default: current directory)")
	remoteSetURLCmd.Flags().String("name", "", "Remote name")
	remoteSetURLCmd.Flags().String("url", "", "New remote URL")

	// Configure flags for remote remove
	remoteRemoveCmd.Flags().StringP("path", "p", "", "Path to Git repository (default: current directory)")
	remoteRemoveCmd.Flags().String("name", "", "Remote name to remove")

	// Configure flags for remote rename
	remoteRenameCmd.Flags().StringP("path", "p", "", "Path to Git repository (default: current directory)")
	remoteRenameCmd.Flags().String("old-name", "", "Current remote name")
	remoteRenameCmd.Flags().String("new-name", "", "New remote name")
}

// All helper functions have been migrated to pkg/git/remote/
