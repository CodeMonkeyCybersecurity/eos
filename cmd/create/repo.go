package create

import (
	"fmt"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/repository"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var createRepoCmd = &cobra.Command{
	Use:   "repo [path]",
	Short: "Create a local git repository and provision a matching Gitea remote",
	Long: `Initialize a local git repository, create a remote on Gitea, add it as a git remote, and push the initial commit.

The command supports interactive and non-interactive usage. When required information is missing it will prompt
for details unless --non-interactive is specified. To review the intended actions without applying them, use --dry-run.

Examples:
  eos create repo .
  eos create repo . --name my-service --private
  eos create repo ./service --org codemonkey --remote upstream
  eos create repo . --dry-run
  eos create repo . --non-interactive --name hecate --private --no-push`,
	Args: cobra.MaximumNArgs(1),
	RunE: eos.Wrap(runCreateRepo),
}

func init() {
	CreateCmd.AddCommand(createRepoCmd)

	createRepoCmd.Flags().StringP("name", "n", "", "Repository name (default: directory name)")
	createRepoCmd.Flags().StringP("description", "d", "", "Repository description")
	createRepoCmd.Flags().BoolP("private", "p", false, "Make repository private")
	createRepoCmd.Flags().StringP("org", "o", "", "Create repository under an organization")
	createRepoCmd.Flags().String("remote", "origin", "Git remote name to use")
	createRepoCmd.Flags().String("branch", "main", "Default branch name")
	createRepoCmd.Flags().Bool("no-push", false, "Do not push to the remote after creation")
	createRepoCmd.Flags().Bool("dry-run", false, "Show planned actions without applying changes")
	createRepoCmd.Flags().Bool("non-interactive", false, "Disable interactive prompts")
	createRepoCmd.Flags().Bool("save-config", false, "Persist answers for future runs in .eos/create-repo.yaml")
}

func runCreateRepo(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	path := "."
	if len(args) > 0 {
		path = args[0]
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	name, _ := cmd.Flags().GetString("name")
	description, _ := cmd.Flags().GetString("description")
	private, _ := cmd.Flags().GetBool("private")
	org, _ := cmd.Flags().GetString("org")
	remote, _ := cmd.Flags().GetString("remote")
	branch, _ := cmd.Flags().GetString("branch")
	noPush, _ := cmd.Flags().GetBool("no-push")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	nonInteractive, _ := cmd.Flags().GetBool("non-interactive")
	saveConfig, _ := cmd.Flags().GetBool("save-config")

	opts := &repository.RepoOptions{
		Path:           absPath,
		Name:           name,
		Description:    description,
		Private:        private,
		Organization:   org,
		Remote:         remote,
		Branch:         branch,
		DryRun:         dryRun,
		NoPush:         noPush,
		NonInteractive: nonInteractive,
		SaveConfig:     saveConfig,
	}

	prefsPath := repository.PreferencesPath(absPath)
	prefs, err := repository.LoadRepoPreferences(prefsPath)
	if err != nil {
		return fmt.Errorf("failed to load repository preferences: %w", err)
	}

	opts.ApplyDefaults(prefs)
	opts.EnsurePathDefaults()

	needsPrompt := !nonInteractive && (!cmd.Flags().Changed("name") ||
		!cmd.Flags().Changed("private") ||
		!cmd.Flags().Changed("org") ||
		!cmd.Flags().Changed("branch") ||
		!cmd.Flags().Changed("remote"))

	if !nonInteractive && needsPrompt {
		if _, err := repository.PromptRepoOptions(absPath, opts, prefs); err != nil {
			return fmt.Errorf("interactive prompt failed: %w", err)
		}
	}

	var giteaClient *repository.GiteaClient
	credOpts := repository.CredentialOptions{
		Interactive: !nonInteractive,
	}
	cfg, cfgErr := repository.GetGiteaConfig(rc, credOpts)
	if cfgErr != nil {
		if dryRun {
			logger.Warn("Gitea credentials unavailable; dry-run will skip remote operations", zap.Error(cfgErr))
		} else {
			return fmt.Errorf("failed to load Gitea configuration: %w", cfgErr)
		}
	} else {
		client, err := repository.NewGiteaClient(cfg)
		if err != nil {
			if dryRun {
				logger.Warn("Failed to initialize Gitea client; remote operations skipped", zap.Error(err))
			} else {
				return fmt.Errorf("failed to create Gitea client: %w", err)
			}
		} else {
			giteaClient = client
		}
	}

	gitWrapper := &repository.GitWrapper{Path: absPath}

	creator := repository.NewCreator(rc, opts, gitWrapper, giteaClient, prefs, prefsPath)
	if _, err := creator.Create(); err != nil {
		return err
	}

	return nil
}
