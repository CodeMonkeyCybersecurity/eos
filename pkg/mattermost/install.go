// install.go - Consolidated Mattermost installation using Docker Compose.
// Follows Assess -> Intervene -> Evaluate pattern. Idempotent.

package mattermost

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/git"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// InstallConfig holds the configuration for Mattermost installation.
// All fields have sensible defaults via DefaultInstallConfig().
type InstallConfig struct {
	// Port is the host port Mattermost will be accessible on.
	Port int

	// PostgresPassword is the database password. Generated if empty.
	PostgresPassword string

	// SupportEmail is the contact shown in the Mattermost UI.
	SupportEmail string

	// DryRun previews changes without applying them.
	DryRun bool
}

// DefaultInstallConfig returns a configuration with sensible defaults.
func DefaultInstallConfig() *InstallConfig {
	return &InstallConfig{
		Port:         DefaultPort,
		SupportEmail: DefaultSupportEmail,
	}
}

// Validate checks the install configuration for correctness.
func (c *InstallConfig) Validate() error {
	if c.Port <= 0 || c.Port > maxValidPort {
		return fmt.Errorf("invalid port %d: must be between 1 and %d", c.Port, maxValidPort)
	}
	return nil
}

// installer holds the dependencies for the install pipeline, enabling
// unit testing of the full pipeline by swapping real implementations
// for test doubles.
type installer struct {
	// checkDocker validates that Docker is available.
	checkDocker func(rc *eos_io.RuntimeContext) error

	// gitClone clones a git repository.
	gitClone func(url, target string) error

	// mkdirP creates directories recursively.
	mkdirP func(rc *eos_io.RuntimeContext, path string, perm os.FileMode) error

	// copyR recursively copies a directory tree.
	copyR func(rc *eos_io.RuntimeContext, src, dst string) error

	// removeAll removes a path and all its children.
	removeAll func(path string) error

	// chown sets ownership on a path.
	chown func(path, ownership string) error

	// ensureNetwork creates the shared Docker network.
	ensureNetwork func(rc *eos_io.RuntimeContext) error

	// composeUp starts containers via Docker Compose.
	composeUp func(rc *eos_io.RuntimeContext, dir string) error

	// checkContainers verifies container health.
	checkContainers func(rc *eos_io.RuntimeContext) error

	// stat checks if a path exists.
	stat func(path string) (os.FileInfo, error)

	// readFile reads a file's contents.
	readFile func(path string) ([]byte, error)

	// writeFile writes data to a file.
	writeFile func(path string, data []byte, perm os.FileMode) error

	// patchEnvFile patches an .env file with key-value overrides.
	patchEnvFile func(path string, updates map[string]string) error

	// mkdirAll creates a directory path and all parents.
	mkdirAll func(path string, perm os.FileMode) error
}

// prodInstaller returns the real production installer dependencies.
func prodInstaller() *installer {
	return &installer{
		checkDocker: container.CheckIfDockerInstalled,
		gitClone:    git.Clone,
		mkdirP: func(rc *eos_io.RuntimeContext, path string, perm os.FileMode) error {
			return eos_unix.MkdirP(rc.Ctx, path, perm)
		},
		copyR: func(rc *eos_io.RuntimeContext, src, dst string) error {
			return eos_unix.CopyR(rc.Ctx, src, dst)
		},
		removeAll: os.RemoveAll,
		chown: func(path, ownership string) error {
			// #nosec G204 -- ownership is a package-derived constant
			out, err := exec.Command("chown", "-R", ownership, path).CombinedOutput()
			if err != nil {
				return fmt.Errorf("%v (%s)", err, out)
			}
			return nil
		},
		ensureNetwork:   container.EnsureArachneNetwork,
		composeUp:       container.ComposeUpInDir,
		checkContainers: container.CheckDockerContainers,
		stat:            os.Stat,
		readFile:        os.ReadFile,
		writeFile:       os.WriteFile,
		patchEnvFile:    PatchEnvInPlace,
		mkdirAll: func(path string, perm os.FileMode) error {
			return os.MkdirAll(path, perm)
		},
	}
}

// Install performs the complete Mattermost installation.
//
// The process follows Assess -> Intervene -> Evaluate:
//  1. ASSESS: Check prerequisites (Docker, existing deployment)
//  2. INTERVENE: Clone repo, configure, deploy
//  3. EVALUATE: Verify containers are running
//
// Idempotent: skips steps that are already complete.
func Install(rc *eos_io.RuntimeContext, cfg *InstallConfig) error {
	return installWith(rc, cfg, prodInstaller())
}

// installWith is the testable core of Install. Accepts injected dependencies.
func installWith(rc *eos_io.RuntimeContext, cfg *InstallConfig, ins *installer) error {
	logger := otelzap.Ctx(rc.Ctx)

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// --- ASSESS ---
	logger.Info("Assessing prerequisites for Mattermost installation",
		zap.Int("port", cfg.Port),
		zap.Bool("dry_run", cfg.DryRun))

	if err := ins.checkDocker(rc); err != nil {
		return fmt.Errorf("docker is required but not installed: %w\n"+
			"Install Docker:\n"+
			"  Ubuntu: sudo apt install docker.io docker-compose-v2\n"+
			"  Or visit: https://docs.docker.com/engine/install/ubuntu/", err)
	}
	logger.Debug("Docker is available")

	alreadyDeployed := isAlreadyDeployedWith(ins)
	if alreadyDeployed {
		logger.Info("Existing Mattermost deployment found",
			zap.String("install_dir", InstallDir))
	}

	if cfg.DryRun {
		logger.Info("Dry run complete",
			zap.Bool("already_deployed", alreadyDeployed),
			zap.String("action", actionDescription(alreadyDeployed)))
		return nil
	}

	// --- INTERVENE ---
	logger.Info("Installing Mattermost",
		zap.Bool("existing_deployment", alreadyDeployed))

	if !alreadyDeployed {
		if err := cloneAndPrepareWith(rc, cfg, ins); err != nil {
			return fmt.Errorf("failed to prepare Mattermost: %w", err)
		}
	} else {
		logger.Info("Skipping clone - deployment already exists, updating configuration")
		if err := patchEnvWith(rc, cfg, ins); err != nil {
			return fmt.Errorf("failed to update configuration: %w", err)
		}
	}

	if err := ensureVolumesWith(rc, ins); err != nil {
		return fmt.Errorf("failed to setup volumes: %w", err)
	}

	if err := deployContainersWith(rc, ins); err != nil {
		return fmt.Errorf("failed to deploy containers: %w", err)
	}

	// --- EVALUATE ---
	logger.Info("Evaluating Mattermost deployment")
	if err := ins.checkContainers(rc); err != nil {
		logger.Warn("Container verification returned warnings", zap.Error(err))
	}

	logger.Info("Mattermost installation completed successfully",
		zap.String("url", fmt.Sprintf("http://localhost:%d", cfg.Port)),
		zap.String("install_dir", InstallDir),
		zap.String("secret_storage", "managed by secrets.Manager"))

	return nil
}

// --- Internal functions ---

// isAlreadyDeployedWith checks if Mattermost is already installed.
func isAlreadyDeployedWith(ins *installer) bool {
	composePath := filepath.Join(InstallDir, ComposeFileName)
	_, err := ins.stat(composePath)
	return err == nil
}

// actionDescription returns a human-readable description of what would happen.
func actionDescription(alreadyDeployed bool) string {
	if alreadyDeployed {
		return "would update existing deployment"
	}
	return "would perform fresh installation"
}

// cloneAndPrepareWith clones the Mattermost Docker repo and configures it.
func cloneAndPrepareWith(rc *eos_io.RuntimeContext, cfg *InstallConfig, ins *installer) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Clean up any stale temp dir (non-fatal if it doesn't exist)
	if err := ins.removeAll(CloneTempDir); err != nil {
		logger.Debug("Stale temp dir cleanup (non-fatal)", zap.Error(err))
	}

	logger.Info("Cloning Mattermost Docker repository",
		zap.String("repo", RepoURL),
		zap.String("temp_dir", CloneTempDir))

	if err := ins.gitClone(RepoURL, CloneTempDir); err != nil {
		return fmt.Errorf("git clone failed: %w\n"+
			"Ensure network connectivity and try again", err)
	}

	// Ensure target directory exists
	if err := ins.mkdirP(rc, InstallDir, InstallDirPerm); err != nil {
		return fmt.Errorf("failed to create install directory %s: %w", InstallDir, err)
	}

	// Copy from temp to final location
	if err := ins.copyR(rc, CloneTempDir, InstallDir); err != nil {
		return fmt.Errorf("failed to copy files to %s: %w", InstallDir, err)
	}

	// Clean up temp dir (non-fatal)
	if err := ins.removeAll(CloneTempDir); err != nil {
		logger.Warn("Failed to clean up temp dir (non-fatal)", zap.Error(err))
	}
	logger.Info("Repository cloned and copied", zap.String("target", InstallDir))

	// Patch .env
	return patchEnvWith(rc, cfg, ins)
}

// patchEnvWith creates or patches the .env file with Eos-standard values.
func patchEnvWith(rc *eos_io.RuntimeContext, cfg *InstallConfig, ins *installer) error {
	logger := otelzap.Ctx(rc.Ctx)

	envPath := filepath.Join(InstallDir, EnvFileName)
	envExamplePath := filepath.Join(InstallDir, EnvExampleFileName)

	// Copy env.example to .env if .env doesn't exist
	if _, err := ins.stat(envPath); os.IsNotExist(err) {
		input, readErr := ins.readFile(envExamplePath)
		if readErr != nil {
			return fmt.Errorf("failed to read %s: %w\n"+
				"Ensure the Mattermost repo was cloned correctly", envExamplePath, readErr)
		}
		if writeErr := ins.writeFile(envPath, input, EnvFilePerm); writeErr != nil {
			return fmt.Errorf("failed to write %s: %w", envPath, writeErr)
		}
		logger.Info("Created .env from template", zap.String("path", envPath))
	}

	// Build overrides
	overrides := make(map[string]string, len(DefaultEnvOverrides)+3)
	for k, v := range DefaultEnvOverrides {
		overrides[k] = v
	}
	overrides["PORT"] = strconv.Itoa(cfg.Port)
	overrides["MM_SUPPORTSETTINGS_SUPPORTEMAIL"] = cfg.SupportEmail
	if cfg.PostgresPassword != "" {
		overrides["POSTGRES_PASSWORD"] = cfg.PostgresPassword
	}

	if err := ins.patchEnvFile(envPath, overrides); err != nil {
		return fmt.Errorf("failed to patch .env: %w", err)
	}

	logger.Info("Configuration patched",
		zap.String("path", envPath),
		zap.Int("port", cfg.Port))

	return nil
}

// ensureVolumesWith creates volume directories and sets ownership.
func ensureVolumesWith(rc *eos_io.RuntimeContext, ins *installer) error {
	logger := otelzap.Ctx(rc.Ctx)

	base := filepath.Join(InstallDir, VolumesBaseDir)
	for _, sub := range VolumeSubdirs {
		dir := filepath.Join(base, sub)
		if err := ins.mkdirAll(dir, VolumeDirPerm); err != nil {
			return fmt.Errorf("failed to create volume directory %s: %w", dir, err)
		}
	}

	if err := ins.chown(base, ContainerOwnership); err != nil {
		return fmt.Errorf("failed to set volume ownership: %w\n"+
			"Try: sudo chown -R %s %s", err, ContainerOwnership, base)
	}

	logger.Info("Volume directories ready",
		zap.String("base", base),
		zap.String("ownership", ContainerOwnership),
		zap.Int("subdirs", len(VolumeSubdirs)))

	return nil
}

// deployContainersWith runs docker compose up.
func deployContainersWith(rc *eos_io.RuntimeContext, ins *installer) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Ensure shared Docker network exists
	if err := ins.ensureNetwork(rc); err != nil {
		logger.Warn("Could not ensure arachne-net (non-fatal)", zap.Error(err))
	}

	logger.Info("Starting Mattermost containers",
		zap.String("dir", InstallDir))

	return ins.composeUp(rc, InstallDir)
}

// PatchEnvInPlace patches an .env file in-place with the given overrides.
// Exported for use by the patch subpackage and tests.
func PatchEnvInPlace(path string, updates map[string]string) error {
	return patchEnvInPlace(path, updates)
}

