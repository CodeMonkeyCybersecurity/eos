package repository

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"code.gitea.io/sdk/gitea"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Creator orchestrates local git initialization and remote Gitea provisioning.
type Creator struct {
	rc           *eos_io.RuntimeContext
	opts         *RepoOptions
	git          *GitWrapper
	giteaClient  *GiteaClient
	prefsPath    string
	prefs        *RepoPreferences
	existingRepo *gitea.Repository
	gitCreated   bool
}

// NewCreator builds a Creator with all dependencies.
func NewCreator(rc *eos_io.RuntimeContext, opts *RepoOptions, git *GitWrapper, client *GiteaClient, prefs *RepoPreferences, prefsPath string) *Creator {
	return &Creator{
		rc:          rc,
		opts:        opts,
		git:         git,
		giteaClient: client,
		prefs:       prefs,
		prefsPath:   prefsPath,
	}
}

// Create executes the workflow.
func (c *Creator) Create() (*CreationResult, error) {
	logger := otelzap.Ctx(c.rc.Ctx)

	if err := c.ensurePath(); err != nil {
		return nil, err
	}

	c.opts.ApplyDefaults(c.prefs)
	c.opts.EnsurePathDefaults()

	if c.opts.DryRun {
		return nil, c.describeDryRun()
	}

	if err := c.ensureGitRepository(); err != nil {
		return nil, err
	}

	if err := c.ensureBranch(); err != nil {
		return nil, err
	}

	if err := c.ensureInitialCommit(); err != nil {
		return nil, err
	}

	var remoteRepo *gitea.Repository
	pushed := false

	if c.giteaClient != nil {
		repo, err := c.ensureRemoteRepository()
		if err != nil {
			return nil, err
		}
		remoteRepo = repo

		if err := c.ensureRemoteConfigured(repo); err != nil {
			return nil, err
		}

		if !c.opts.NoPush {
			if err := c.git.Push(c.opts.Remote, c.opts.Branch); err != nil {
				return nil, fmt.Errorf("failed to push to remote: %w", err)
			}
			logger.Info("Git repository pushed to remote",
				zap.String("remote", c.opts.Remote),
				zap.String("branch", c.opts.Branch))
			pushed = true
		} else {
			logger.Info("Skipping push to remote repository (flag --no-push set)")
		}
	} else {
		logger.Warn("Gitea client not configured - skipping remote repository creation")
	}

	if c.opts.SaveConfig {
		if err := c.persistPreferences(); err != nil {
			logger.Warn("Failed to persist create repo preferences", zap.Error(err))
		}
	}

	result := &CreationResult{
		Name:      c.opts.Name,
		Remote:    c.opts.Remote,
		Branch:    c.opts.Branch,
		WasNewGit: c.gitCreated,
		Pushed:    pushed,
	}
	if remoteRepo != nil {
		result.Owner = remoteRepo.Owner.UserName
		result.HTMLURL = remoteRepo.HTMLURL
		result.CloneURL = remoteRepo.CloneURL
	}

	c.printSuccess(remoteRepo)

	return result, nil
}

func (c *Creator) ensurePath() error {
	info, err := os.Stat(c.opts.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("path %s does not exist", c.opts.Path)
		}
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("path %s is not a directory", c.opts.Path)
	}
	return nil
}

func (c *Creator) ensureGitRepository() error {
	logger := otelzap.Ctx(c.rc.Ctx)

	if c.git.IsRepository() {
		logger.Info("Git repository already initialized", zap.String("path", c.opts.Path))
		return nil
	}

	logger.Info("Initializing new git repository", zap.String("path", c.opts.Path))
	if err := c.git.InitRepository(); err != nil {
		return fmt.Errorf("failed to initialize git repository: %w", err)
	}
	c.gitCreated = true

	if err := c.git.SetDefaultBranch(c.opts.Branch); err != nil {
		logger.Warn("Failed to set git default branch", zap.Error(err))
	}

	return nil
}

func (c *Creator) ensureBranch() error {
	logger := otelzap.Ctx(c.rc.Ctx)

	if err := c.git.EnsureBranch(c.opts.Branch); err != nil {
		// Provide helpful hint if branch commands fail before first commit.
		if strings.Contains(err.Error(), "did you intend to checkout") {
			logger.Warn("Failed to checkout branch prior to first commit; proceeding with default HEAD")
			return nil
		}
		return fmt.Errorf("failed to switch to branch %s: %w", c.opts.Branch, err)
	}

	return nil
}

func (c *Creator) ensureInitialCommit() error {
	logger := otelzap.Ctx(c.rc.Ctx)

	hasCommits, err := c.git.HasCommits()
	if err != nil {
		return fmt.Errorf("failed to inspect git history: %w", err)
	}
	if hasCommits {
		logger.Info("Git repository already has commits; skipping initial commit")
		return nil
	}

	logger.Info("Creating initial commit in git repository")
	if err := c.git.CreateInitialCommit("Initial commit (created by EOS)"); err != nil {
		return fmt.Errorf("failed to create initial commit: %w", err)
	}
	return nil
}

func (c *Creator) ensureRemoteRepository() (*gitea.Repository, error) {
	logger := otelzap.Ctx(c.rc.Ctx)

	owner := strings.TrimSpace(c.opts.Organization)
	c.opts.Organization = owner

	if owner != "" {
		exists, err := c.giteaClient.OrgExists(owner)
		if err != nil {
			return nil, err
		}
		if !exists {
			if c.opts.NonInteractive {
				return nil, fmt.Errorf("organization %s not found on Gitea; create it first or choose an existing organization", owner)
			}

			personalOwner := c.giteaClient.Username()
			if !promptYesNo(fmt.Sprintf("Organization %q was not found on Gitea. Create the repository under your personal account (%s) instead?", owner, personalOwner), false) {
				return nil, fmt.Errorf("organization %s not found on Gitea; create it first or choose an existing organization", owner)
			}

			logger.Warn("Organization not found on Gitea; falling back to personal namespace",
				zap.String("organization", owner),
				zap.String("username", personalOwner))
			c.opts.Organization = ""
			owner = ""
		}
	}

	if owner == "" {
		owner = c.giteaClient.Username()
	}

	repo, exists, err := c.giteaClient.RepoExists(owner, c.opts.Name)
	if err != nil {
		return nil, err
	}

	if exists {
		logger.Info("Remote repository already exists", zap.String("owner", owner), zap.String("name", c.opts.Name))
		c.existingRepo = repo
		if c.opts.NonInteractive {
			return nil, fmt.Errorf("repository %s/%s already exists on Gitea", owner, c.opts.Name)
		}
		if !promptYesNo(fmt.Sprintf("Repository %s/%s exists. Use existing remote?", owner, c.opts.Name), true) {
			return nil, fmt.Errorf("remote repository already exists - choose a different name or organization")
		}
		return repo, nil
	}

	logger.Info("Creating remote repository on Gitea",
		zap.String("owner", owner),
		zap.String("name", c.opts.Name),
		zap.Bool("private", c.opts.Private))

	createOpts := &gitea.CreateRepoOption{
		Name:          c.opts.Name,
		Description:   c.opts.Description,
		Private:       c.opts.Private,
		AutoInit:      false,
		DefaultBranch: c.opts.Branch,
	}

	if c.opts.Organization != "" {
		return c.giteaClient.CreateOrgRepo(c.opts.Organization, createOpts)
	}
	return c.giteaClient.CreateUserRepo(createOpts)
}

func (c *Creator) ensureRemoteConfigured(repo *gitea.Repository) error {
	if repo == nil {
		return nil
	}

	logger := otelzap.Ctx(c.rc.Ctx)

	remoteExists, err := c.git.RemoteExists(c.opts.Remote)
	if err != nil {
		return fmt.Errorf("failed to inspect git remote %s: %w", c.opts.Remote, err)
	}

	targetURL := repo.CloneURL
	if targetURL == "" {
		if repo.SSHURL != "" {
			targetURL = repo.SSHURL
		} else {
			targetURL = repo.HTMLURL
		}
	}

	if remoteExists {
		if c.opts.NonInteractive {
			logger.Info("Updating existing git remote",
				zap.String("remote", c.opts.Remote),
				zap.String("url", targetURL))
			return c.git.SetRemote(c.opts.Remote, targetURL)
		}

		if promptYesNo(fmt.Sprintf("Remote %s already exists. Update URL to %s?", c.opts.Remote, targetURL), true) {
			return c.git.SetRemote(c.opts.Remote, targetURL)
		}

		return fmt.Errorf("remote %s already exists - aborting to avoid overwriting URL", c.opts.Remote)
	}

	logger.Info("Adding git remote",
		zap.String("remote", c.opts.Remote),
		zap.String("url", targetURL))
	return c.git.AddRemote(c.opts.Remote, targetURL)
}

func (c *Creator) persistPreferences() error {
	prefs := &RepoPreferences{
		Remote:          c.opts.Remote,
		Branch:          c.opts.Branch,
		Organization:    c.opts.Organization,
		DefaultPrivate:  c.opts.Private,
		RememberPrivate: true,
	}
	return SaveRepoPreferences(c.prefsPath, prefs)
}

func (c *Creator) describeDryRun() error {
	logger := otelzap.Ctx(c.rc.Ctx)

	logger.Info("[dry-run] Evaluating repository creation steps",
		zap.String("path", c.opts.Path),
		zap.String("name", c.opts.Name))

	if !c.git.IsRepository() {
		logger.Info("[dry-run] Would initialize git repository")
	} else {
		logger.Info("[dry-run] Git repository already present")
	}

	hasCommits, err := c.git.HasCommits()
	if err != nil {
		logger.Warn("[dry-run] Unable to determine commit status", zap.Error(err))
	} else if !hasCommits {
		logger.Info("[dry-run] Would create initial commit")
	} else {
		logger.Info("[dry-run] Initial commit already exists")
	}

	if c.giteaClient != nil {
		owner := c.opts.Organization
		if owner == "" {
			owner = c.giteaClient.Username()
		}
		_, exists, err := c.giteaClient.RepoExists(owner, c.opts.Name)
		if err != nil {
			logger.Warn("[dry-run] Failed to check remote repository existence", zap.Error(err))
		} else if exists {
			logger.Info("[dry-run] Remote repository already exists on Gitea",
				zap.String("owner", owner),
				zap.String("repo", c.opts.Name))
		} else {
			logger.Info("[dry-run] Would create remote repository on Gitea",
				zap.String("owner", owner),
				zap.Bool("private", c.opts.Private))
		}
	} else {
		logger.Info("[dry-run] No Gitea credentials detected; skipping remote operations")
	}

	logger.Info("[dry-run] No changes were made")
	return nil
}

func (c *Creator) printSuccess(repo *gitea.Repository) {
	logger := otelzap.Ctx(c.rc.Ctx)
	if repo == nil {
		logger.Info("Repository prepared locally (no remote configured)")
		return
	}

	logger.Info("Repository created successfully",
		zap.String("name", repo.Name),
		zap.String("owner", repo.Owner.UserName),
		zap.Bool("private", repo.Private),
		zap.String("url", repo.HTMLURL),
		zap.String("clone_url", repo.CloneURL))

	fmt.Println("Repository created successfully!")
	fmt.Printf("  Name:        %s\n", repo.Name)
	fmt.Printf("  Owner:       %s\n", repo.Owner.UserName)
	fmt.Printf("  Visibility:  %s\n", visibilityLabel(repo.Private))
	fmt.Printf("  URL:         %s\n", repo.HTMLURL)
	fmt.Printf("  Clone:       %s\n", repo.CloneURL)

	if c.opts.NoPush {
		fmt.Println("Next steps:")
		fmt.Printf("  git push %s %s\n", c.opts.Remote, c.opts.Branch)
	} else {
		fmt.Println("Next steps:")
		fmt.Println("  git push              # Push future changes")
		fmt.Println("  git pull              # Pull latest changes")
	}
}

func visibilityLabel(private bool) string {
	if private {
		return "private"
	}
	return "public"
}

// promptYesNo prompts the user for confirmation when interactive mode is allowed.
func promptYesNo(message string, defaultYes bool) bool {
	reader := bufio.NewReader(os.Stdin)
	suffix := "y/N"
	if defaultYes {
		suffix = "Y/n"
	}
	for {
		fmt.Printf("%s [%s]: ", message, suffix)
		text, _ := reader.ReadString('\n')
		text = strings.TrimSpace(strings.ToLower(text))
		if text == "" {
			return defaultYes
		}
		switch text {
		case "y", "yes":
			return true
		case "n", "no":
			return false
		default:
			fmt.Println("Please answer yes or no.")
		}
	}
}
