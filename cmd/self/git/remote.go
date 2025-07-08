package git

import (
	"encoding/json"
	"fmt"
	"os"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/git_management"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// newRemoteCmd creates the Git remote management command
func newRemoteCmd() *cobra.Command {
	cmd := &cobra.Command{
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

	// Add subcommands
	cmd.AddCommand(newRemoteListCmd())
	cmd.AddCommand(newRemoteAddCmd())
	cmd.AddCommand(newRemoteSetURLCmd())
	cmd.AddCommand(newRemoteRemoveCmd())
	cmd.AddCommand(newRemoteRenameCmd())

	return cmd
}

func newRemoteListCmd() *cobra.Command {
	var (
		path       string
		outputJSON bool
	)

	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List Git remotes",
		Long:    "List all configured Git remotes for the repository.",

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			if path == "" {
				var err error
				path, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("failed to get current directory: %w", err)
				}
			}

			manager := git_management.NewGitManager()
			
			if !manager.IsGitRepository(rc, path) {
				return fmt.Errorf("not a git repository: %s", path)
			}

			repo, err := manager.GetRepositoryInfo(rc, path)
			if err != nil {
				return fmt.Errorf("failed to get repository info: %w", err)
			}

			if outputJSON {
				data, err := json.MarshalIndent(repo.RemoteURLs, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to marshal JSON: %w", err)
				}
				fmt.Println(string(data))
				return nil
			}

			fmt.Printf("Git Remotes\n")
			fmt.Printf("===========\n\n")

			if len(repo.RemoteURLs) == 0 {
				fmt.Println("No remotes configured")
				return nil
			}

			for name, url := range repo.RemoteURLs {
				fmt.Printf("%s\t%s\n", name, url)
			}

			return nil
		}),
	}

	cmd.Flags().StringVarP(&path, "path", "p", "", "Path to Git repository (default: current directory)")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output in JSON format")

	return cmd
}

func newRemoteAddCmd() *cobra.Command {
	var (
		path string
		name string
		url  string
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new Git remote",
		Long: `Add a new Git remote repository.

Examples:
  eos git remote add origin https://github.com/user/repo.git
  eos git remote add upstream https://github.com/upstream/repo.git`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

			if path == "" {
				var err error
				path, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("failed to get current directory: %w", err)
				}
			}

			// Get name and URL from args if not provided via flags
			if len(args) >= 2 && name == "" && url == "" {
				name = args[0]
				url = args[1]
			}

			if name == "" || url == "" {
				return fmt.Errorf("both remote name and URL are required")
			}

			manager := git_management.NewGitManager()
			
			if !manager.IsGitRepository(rc, path) {
				return fmt.Errorf("not a git repository: %s", path)
			}

			operation := &git_management.GitRemoteOperation{
				Operation: "add",
				Name:      name,
				URL:       url,
			}

			logger.Info("Adding Git remote", 
				zap.String("name", name),
				zap.String("url", url))

			return manager.ManageRemote(rc, path, operation)
		}),
	}

	cmd.Flags().StringVarP(&path, "path", "p", "", "Path to Git repository (default: current directory)")
	cmd.Flags().StringVar(&name, "name", "", "Remote name")
	cmd.Flags().StringVar(&url, "url", "", "Remote URL")

	return cmd
}

func newRemoteSetURLCmd() *cobra.Command {
	var (
		path string
		name string
		url  string
	)

	cmd := &cobra.Command{
		Use:   "set-url",
		Short: "Change the URL of an existing Git remote",
		Long: `Change the URL of an existing Git remote.

Examples:
  eos git remote set-url origin https://new-url.git
  eos git remote set-url --name origin --url https://new-url.git`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

			if path == "" {
				var err error
				path, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("failed to get current directory: %w", err)
				}
			}

			// Get name and URL from args if not provided via flags
			if len(args) >= 2 && name == "" && url == "" {
				name = args[0]
				url = args[1]
			}

			if name == "" || url == "" {
				return fmt.Errorf("both remote name and new URL are required")
			}

			manager := git_management.NewGitManager()
			
			if !manager.IsGitRepository(rc, path) {
				return fmt.Errorf("not a git repository: %s", path)
			}

			operation := &git_management.GitRemoteOperation{
				Operation: "set-url",
				Name:      name,
				URL:       url,
			}

			logger.Info("Changing Git remote URL", 
				zap.String("name", name),
				zap.String("new_url", url))

			return manager.ManageRemote(rc, path, operation)
		}),
	}

	cmd.Flags().StringVarP(&path, "path", "p", "", "Path to Git repository (default: current directory)")
	cmd.Flags().StringVar(&name, "name", "", "Remote name")
	cmd.Flags().StringVar(&url, "url", "", "New remote URL")

	return cmd
}

func newRemoteRemoveCmd() *cobra.Command {
	var (
		path string
		name string
	)

	cmd := &cobra.Command{
		Use:     "remove",
		Aliases: []string{"rm"},
		Short:   "Remove a Git remote",
		Long: `Remove an existing Git remote.

Examples:
  eos git remote remove origin
  eos git remote rm upstream`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

			if path == "" {
				var err error
				path, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("failed to get current directory: %w", err)
				}
			}

			// Get name from args if not provided via flag
			if len(args) >= 1 && name == "" {
				name = args[0]
			}

			if name == "" {
				return fmt.Errorf("remote name is required")
			}

			manager := git_management.NewGitManager()
			
			if !manager.IsGitRepository(rc, path) {
				return fmt.Errorf("not a git repository: %s", path)
			}

			operation := &git_management.GitRemoteOperation{
				Operation: "remove",
				Name:      name,
			}

			logger.Info("Removing Git remote", zap.String("name", name))

			return manager.ManageRemote(rc, path, operation)
		}),
	}

	cmd.Flags().StringVarP(&path, "path", "p", "", "Path to Git repository (default: current directory)")
	cmd.Flags().StringVar(&name, "name", "", "Remote name to remove")

	return cmd
}

func newRemoteRenameCmd() *cobra.Command {
	var (
		path    string
		oldName string
		newName string
	)

	cmd := &cobra.Command{
		Use:   "rename",
		Short: "Rename a Git remote",
		Long: `Rename an existing Git remote.

Examples:
  eos git remote rename origin upstream
  eos git remote rename --old-name origin --new-name upstream`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

			if path == "" {
				var err error
				path, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("failed to get current directory: %w", err)
				}
			}

			// Get names from args if not provided via flags
			if len(args) >= 2 && oldName == "" && newName == "" {
				oldName = args[0]
				newName = args[1]
			}

			if oldName == "" || newName == "" {
				return fmt.Errorf("both old and new remote names are required")
			}

			manager := git_management.NewGitManager()
			
			if !manager.IsGitRepository(rc, path) {
				return fmt.Errorf("not a git repository: %s", path)
			}

			operation := &git_management.GitRemoteOperation{
				Operation: "rename",
				Name:      oldName,
				NewName:   newName,
			}

			logger.Info("Renaming Git remote", 
				zap.String("old_name", oldName),
				zap.String("new_name", newName))

			return manager.ManageRemote(rc, path, operation)
		}),
	}

	cmd.Flags().StringVarP(&path, "path", "p", "", "Path to Git repository (default: current directory)")
	cmd.Flags().StringVar(&oldName, "old-name", "", "Current remote name")
	cmd.Flags().StringVar(&newName, "new-name", "", "New remote name")

	return cmd
}