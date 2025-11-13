package repository

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
    "bufio"
    "errors"
    "fmt"
    "os"
    "os/exec"
    "os/user"
    "path/filepath"
    "runtime"
    "strings"

    "code.gitea.io/sdk/gitea"
    giteaSDK "code.gitea.io/sdk/gitea"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/git/safety"
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

    // Optional: if running via sudo and requested, fix ownership to the original user
    if err := c.maybeFixOwnership(); err != nil {
        logger.Warn("Ownership fix encountered an issue", zap.Error(err))
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

        // If user prefers SSH, ensure an SSH key exists and is uploaded to Gitea
        if strings.ToLower(strings.TrimSpace(c.opts.Auth)) == "ssh" {
            if err := c.ensureSSHAuthSetup(); err != nil {
                logger.Warn("SSH auth setup failed; will fall back to HTTPS if needed", zap.Error(err))
            }
        } else if c.opts.ConfigureCredHelper {
            if err := ensureCredentialHelperConfigured(c.rc); err != nil {
                logger.Warn("Failed to configure git credential.helper", zap.Error(err))
            }
        }

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
        // Ensure git safe.directory is configured to prevent dubious ownership errors
        if err := safety.EnsureSafeDirectory(c.rc, c.opts.Path); err != nil {
            logger.Warn("Failed to register repository as safe for git", zap.Error(err))
        }
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

    // Configure git safe.directory for the newly created repository
    if err := safety.EnsureSafeDirectory(c.rc, c.opts.Path); err != nil {
        logger.Warn("Failed to register repository as safe for git", zap.Error(err))
    }

    return nil
}

// maybeFixOwnership attempts to change repository ownership to the invoking user when
// run via sudo (root euid with SUDO_USER set). In interactive mode, asks for consent
// unless AutoFixOwnership is true. Non-interactive requires AutoFixOwnership.
func (c *Creator) maybeFixOwnership() error {
    logger := otelzap.Ctx(c.rc.Ctx)
    if os.Geteuid() != 0 {
        return nil
    }
    sudoUser := strings.TrimSpace(os.Getenv("SUDO_USER"))
    if sudoUser == "" {
        return nil
    }

    // Only fix if requested or user confirms
    proceed := c.opts.AutoFixOwnership
    if !c.opts.NonInteractive && !proceed {
        proceed = promptYesNo(fmt.Sprintf("Detected sudo context. Change ownership of %s to %s?", c.opts.Path, sudoUser), true)
    }
    if c.opts.NonInteractive && !proceed {
        logger.Info("Skipping ownership change (non-interactive and no auto-fix)")
        return nil
    }

    u, err := user.Lookup(sudoUser)
    if err != nil {
        return fmt.Errorf("lookup sudo user %s: %w", sudoUser, err)
    }
    // Convert to numeric UID,GID
    // On Unix, u.Uid/u.Gid are strings; parse to ints
    // Use Chown with uid/gid
    uid, gid, convErr := parseUIDGID(u)
    if convErr != nil {
        return convErr
    }

    logger.Info("Adjusting repository ownership",
        zap.String("path", c.opts.Path),
        zap.String("user", sudoUser))

    return chownRecursive(c.opts.Path, uid, gid)
}

func parseUIDGID(u *user.User) (int, int, error) {
    // Only valid on Unix-like systems
    //nolint:gomnd
    var uid, gid int
    var err error
    if uid, err = atoi(u.Uid); err != nil {
        return 0, 0, fmt.Errorf("parse uid: %w", err)
    }
    if gid, err = atoi(u.Gid); err != nil {
        return 0, 0, fmt.Errorf("parse gid: %w", err)
    }
    return uid, gid, nil
}

func atoi(s string) (int, error) {
    var n int
    _, err := fmt.Sscanf(s, "%d", &n)
    if err != nil {
        return 0, err
    }
    return n, nil
}

func chownRecursive(root string, uid, gid int) error {
    return filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
        if err != nil {
            return err
        }
        // Use Lchown semantics for symlinks if available; os.Chown follows symlink target
        // For simplicity and safety here, skip symlinks
        if d.Type()&os.ModeSymlink != 0 {
            return nil
        }
        if chErr := os.Chown(p, uid, gid); chErr != nil {
            return chErr
        }
        return nil
    })
}

// ensureSSHAuthSetup ensures an SSH key exists locally and is uploaded to Gitea.
// Best-effort; logs warnings and continues on failure.
func (c *Creator) ensureSSHAuthSetup() error {
    logger := otelzap.Ctx(c.rc.Ctx)
    // Determine default key path
    homeDir, err := os.UserHomeDir()
    if err != nil {
        return fmt.Errorf("resolve home dir: %w", err)
    }
    sshDir := filepath.Join(homeDir, ".ssh")
    pub := filepath.Join(sshDir, "id_ed25519.pub")
    pri := filepath.Join(sshDir, "id_ed25519")

    if _, err := os.Stat(pub); err != nil {
        if os.IsNotExist(err) {
            if !c.opts.NonInteractive && !c.opts.SSHGenerateKey {
                // Ask if we should generate a key
                if !promptYesNo("No SSH key found. Generate an ed25519 key now?", true) {
                    return fmt.Errorf("no SSH key present and user declined generation")
                }
            }
            if c.opts.NonInteractive && !c.opts.SSHGenerateKey {
                return fmt.Errorf("no SSH key present and ssh-generate-key is false")
            }
            if genErr := generateSSHKey(pri); genErr != nil {
                return genErr
            }
        } else {
            return fmt.Errorf("check ssh key: %w", err)
        }
    }

    // Ensure key is registered in Gitea
    if c.giteaClient != nil {
        if err := ensureKeyInGitea(c.giteaClient.client, pub); err != nil {
            logger.Warn("Failed to upload SSH key to Gitea", zap.Error(err))
        } else {
            logger.Info("SSH key is present in Gitea")
        }
    }
    return nil
}

func generateSSHKey(privatePath string) error {
    // Ensure directory exists
    if err := os.MkdirAll(filepath.Dir(privatePath), shared.SecretDirPerm); err != nil {
        return fmt.Errorf("create .ssh dir: %w", err)
    }
    // Use ssh-keygen to create key without passphrase (interactive passphrases are out-of-scope here)
    cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", privatePath)
    if out, err := cmd.CombinedOutput(); err != nil {
        return fmt.Errorf("ssh-keygen failed: %w (%s)", err, strings.TrimSpace(string(out)))
    }
    return nil
}

func ensureKeyInGitea(c *giteaSDK.Client, pubPath string) error {
    data, err := os.ReadFile(pubPath)
    if err != nil {
        return fmt.Errorf("read public key: %w", err)
    }
    pub := strings.TrimSpace(string(data))
    // List existing keys
    keys, _, err := c.ListMyPublicKeys(giteaSDK.ListPublicKeysOptions{})
    if err != nil {
        return fmt.Errorf("list public keys: %w", err)
    }
    for _, k := range keys {
        if strings.TrimSpace(k.Key) == pub {
            return nil // already present
        }
    }
    title := fmt.Sprintf("EOS %s", filepath.Base(pubPath))
    _, _, err = c.CreatePublicKey(giteaSDK.CreateKeyOption{Title: title, Key: pub})
    if err != nil {
        return fmt.Errorf("create public key: %w", err)
    }
    return nil
}

// ensureCredentialHelperConfigured sets a platform-appropriate credential.helper for HTTPS
func ensureCredentialHelperConfigured(rc *eos_io.RuntimeContext) error {
    var helper string
    // Very simple platform detection
    goos := runtime.GOOS
    switch goos {
    case "darwin":
        helper = "osxkeychain"
    case "windows":
        helper = "manager"
    default:
        helper = "libsecret"
    }
    // Check current value
    cmd := exec.Command("git", "config", "--global", "credential.helper")
    if out, err := cmd.CombinedOutput(); err == nil {
        if strings.TrimSpace(string(out)) != "" {
            return nil // already set
        }
    }
    set := exec.Command("git", "config", "--global", "credential.helper", helper)
    if out, err := set.CombinedOutput(); err != nil {
        return fmt.Errorf("set credential.helper: %w (%s)", err, strings.TrimSpace(string(out)))
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

    // Choose URL based on preferred auth
    targetURL := ""
    preferSSH := strings.ToLower(strings.TrimSpace(c.opts.Auth)) != "https"
    if preferSSH && repo.SSHURL != "" {
        targetURL = repo.SSHURL
    } else if repo.CloneURL != "" {
        targetURL = repo.CloneURL
    } else if repo.HTMLURL != "" {
        targetURL = repo.HTMLURL
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
