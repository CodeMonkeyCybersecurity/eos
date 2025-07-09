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

}

// Package-level variables for remote list command flags
var (
	remoteListPath       string
	remoteListOutputJSON bool
)

// remoteListCmd lists all configured Git remotes
var remoteListCmd = &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List Git remotes",
		Long:    "List all configured Git remotes for the repository.",

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			if remoteListPath == "" {
				var err error
				remoteListPath, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("failed to get current directory: %w", err)
				}
			}

			manager := git_management.NewGitManager()
			
			if !manager.IsGitRepository(rc, remoteListPath) {
				return fmt.Errorf("not a git repository: %s", remoteListPath)
			}

			repo, err := manager.GetRepositoryInfo(rc, remoteListPath)
			if err != nil {
				return fmt.Errorf("failed to get repository info: %w", err)
			}

			if remoteListOutputJSON {
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

}

// Package-level variables for remote add command flags
var (
	remoteAddPath string
	remoteAddName string
	remoteAddURL  string
)

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

			if remoteAddPath == "" {
				var err error
				remoteAddPath, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("failed to get current directory: %w", err)
				}
			}

			// Get name and URL from args if not provided via flags
			if len(args) >= 2 && remoteAddName == "" && remoteAddURL == "" {
				remoteAddName = args[0]
				remoteAddURL = args[1]
			}

			if remoteAddName == "" || remoteAddURL == "" {
				return fmt.Errorf("both remote name and URL are required")
			}

			manager := git_management.NewGitManager()
			
			if !manager.IsGitRepository(rc, remoteAddPath) {
				return fmt.Errorf("not a git repository: %s", remoteAddPath)
			}

			operation := &git_management.GitRemoteOperation{
				Operation: "add",
				Name:      remoteAddName,
				URL:       remoteAddURL,
			}

			logger.Info("Adding Git remote", 
				zap.String("name", remoteAddName),
				zap.String("url", remoteAddURL))

			return manager.ManageRemote(rc, remoteAddPath, operation)
		}),
	}

}

// Package-level variables for remote set-url command flags
var (
	remoteSetURLPath string
	remoteSetURLName string
	remoteSetURLURL  string
)

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

			if remoteSetURLPath == "" {
				var err error
				remoteSetURLPath, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("failed to get current directory: %w", err)
				}
			}

			// Get name and URL from args if not provided via flags
			if len(args) >= 2 && remoteSetURLName == "" && remoteSetURLURL == "" {
				remoteSetURLName = args[0]
				remoteSetURLURL = args[1]
			}

			if remoteSetURLName == "" || remoteSetURLURL == "" {
				return fmt.Errorf("both remote name and new URL are required")
			}

			manager := git_management.NewGitManager()
			
			if !manager.IsGitRepository(rc, remoteSetURLPath) {
				return fmt.Errorf("not a git repository: %s", remoteSetURLPath)
			}

			operation := &git_management.GitRemoteOperation{
				Operation: "set-url",
				Name:      remoteSetURLName,
				URL:       remoteSetURLURL,
			}

			logger.Info("Changing Git remote URL", 
				zap.String("name", remoteSetURLName),
				zap.String("new_url", remoteSetURLURL))

			return manager.ManageRemote(rc, remoteSetURLPath, operation)
		}),
	}

}

// Package-level variables for remote remove command flags
var (
	remoteRemovePath string
	remoteRemoveName string
)

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

			if remoteRemovePath == "" {
				var err error
				remoteRemovePath, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("failed to get current directory: %w", err)
				}
			}

			// Get name from args if not provided via flag
			if len(args) >= 1 && remoteRemoveName == "" {
				remoteRemoveName = args[0]
			}

			if remoteRemoveName == "" {
				return fmt.Errorf("remote name is required")
			}

			manager := git_management.NewGitManager()
			
			if !manager.IsGitRepository(rc, remoteRemovePath) {
				return fmt.Errorf("not a git repository: %s", remoteRemovePath)
			}

			operation := &git_management.GitRemoteOperation{
				Operation: "remove",
				Name:      remoteRemoveName,
			}

			logger.Info("Removing Git remote", zap.String("name", remoteRemoveName))

			return manager.ManageRemote(rc, remoteRemovePath, operation)
		}),
	}

}

// Package-level variables for remote rename command flags
var (
	remoteRenamePath    string
	remoteRenameOldName string
	remoteRenameNewName string
)

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

			if remoteRenamePath == "" {
				var err error
				remoteRenamePath, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("failed to get current directory: %w", err)
				}
			}

			// Get names from args if not provided via flags
			if len(args) >= 2 && remoteRenameOldName == "" && remoteRenameNewName == "" {
				remoteRenameOldName = args[0]
				remoteRenameNewName = args[1]
			}

			if remoteRenameOldName == "" || remoteRenameNewName == "" {
				return fmt.Errorf("both old and new remote names are required")
			}

			manager := git_management.NewGitManager()
			
			if !manager.IsGitRepository(rc, remoteRenamePath) {
				return fmt.Errorf("not a git repository: %s", remoteRenamePath)
			}

			operation := &git_management.GitRemoteOperation{
				Operation: "rename",
				Name:      remoteRenameOldName,
				NewName:   remoteRenameNewName,
			}

			logger.Info("Renaming Git remote", 
				zap.String("old_name", remoteRenameOldName),
				zap.String("new_name", remoteRenameNewName))

			return manager.ManageRemote(rc, remoteRenamePath, operation)
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
	remoteListCmd.Flags().StringVarP(&remoteListPath, "path", "p", "", "Path to Git repository (default: current directory)")
	remoteListCmd.Flags().BoolVar(&remoteListOutputJSON, "json", false, "Output in JSON format")
	
	// Configure flags for remote add
	remoteAddCmd.Flags().StringVarP(&remoteAddPath, "path", "p", "", "Path to Git repository (default: current directory)")
	remoteAddCmd.Flags().StringVar(&remoteAddName, "name", "", "Remote name")
	remoteAddCmd.Flags().StringVar(&remoteAddURL, "url", "", "Remote URL")
	
	// Configure flags for remote set-url
	remoteSetURLCmd.Flags().StringVarP(&remoteSetURLPath, "path", "p", "", "Path to Git repository (default: current directory)")
	remoteSetURLCmd.Flags().StringVar(&remoteSetURLName, "name", "", "Remote name")
	remoteSetURLCmd.Flags().StringVar(&remoteSetURLURL, "url", "", "New remote URL")
	
	// Configure flags for remote remove
	remoteRemoveCmd.Flags().StringVarP(&remoteRemovePath, "path", "p", "", "Path to Git repository (default: current directory)")
	remoteRemoveCmd.Flags().StringVar(&remoteRemoveName, "name", "", "Remote name to remove")
	
	// Configure flags for remote rename
	remoteRenameCmd.Flags().StringVarP(&remoteRenamePath, "path", "p", "", "Path to Git repository (default: current directory)")
	remoteRenameCmd.Flags().StringVar(&remoteRenameOldName, "old-name", "", "Current remote name")
	remoteRenameCmd.Flags().StringVar(&remoteRenameNewName, "new-name", "", "New remote name")
}