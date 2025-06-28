// pkg/container/docker.go

package container

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	cerr "github.com/cockroachdb/errors"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RunDockerAction wraps `docker <action> <args...>`
func RunDockerAction(rc *eos_io.RuntimeContext, action string, args ...string) error {
	fullArgs := append([]string{action}, args...)
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    fullArgs,
	})
	return err
}

// UninstallConflictingPackages removes any preinstalled Docker versions or conflicts
func UninstallConflictingPackages(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Removing conflicting Docker packages")

	packages := []string{
		"docker.io", "docker-doc", "docker-compose", "docker-compose-v2",
		"podman-docker", "containerd", "runc",
	}

	for _, pkg := range packages {
		logger.Debug(" Attempting to remove package", zap.String("package", pkg))
		if err := execute.RunSimple(rc.Ctx, "apt-get", "remove", "-y", pkg); err != nil {
			logger.Debug("Package removal failed (likely not installed)",
				zap.String("package", pkg),
				zap.Error(err))
		} else {
			logger.Debug(" Package removed successfully", zap.String("package", pkg))
		}
	}

	logger.Info(" Conflicting package removal completed")
}

// UninstallSnapDocker removes the Snap version of Docker
func UninstallSnapDocker(rc *eos_io.RuntimeContext) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Removing Docker snap package")

	if err := execute.RunSimple(rc.Ctx, "snap", "remove", "docker"); err != nil {
		logger.Debug("Docker snap removal failed (likely not installed)", zap.Error(err))
	} else {
		logger.Info(" Docker snap package removed successfully")
	}
}

// InstallPrerequisitesAndGpg sets up apt and Docker GPG keys
func InstallPrerequisitesAndGpg(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Installing Docker prerequisites and GPG keys")

	steps := []execute.Options{
		{Command: "apt-get", Args: []string{"install", "-y", "ca-certificates", "curl"}},
		{Command: "install", Args: []string{"-m", "0755", "-d", "/etc/apt/keyrings"}},
		{Command: "curl", Args: []string{"-fsSL", "https://download.docker.com/linux/ubuntu/gpg", "-o", "/etc/apt/keyrings/docker.asc"}},
		{Command: "chmod", Args: []string{"a+r", "/etc/apt/keyrings/docker.asc"}},
	}

	for i, step := range steps {
		logger.Debug(" Executing prerequisite step",
			zap.Int("step", i+1),
			zap.String("command", step.Command),
			zap.Strings("args", step.Args))

		if _, err := execute.Run(rc.Ctx, step); err != nil {
			logger.Error(" Prerequisite step failed",
				zap.Int("step", i+1),
				zap.String("command", step.Command),
				zap.Error(err))
			return cerr.Wrapf(err, "execute prerequisite step %d: %s", i+1, step.Command)
		}
	}

	logger.Info(" Docker prerequisites and GPG keys installed successfully")
	return nil
}

// AddDockerRepository adds the official Docker repository to APT sources
func AddDockerRepository(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Adding Docker repository to APT sources")

	arch := eos_unix.GetArchitecture()
	codename := eos_unix.GetUbuntuCodename(rc)

	logger.Debug(" Detected system information",
		zap.String("architecture", arch),
		zap.String("codename", codename))

	repoLine := fmt.Sprintf(
		"deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu %s stable\n",
		arch, codename,
	)

	logger.Debug(" Writing Docker repository configuration",
		zap.String("repo_line", strings.TrimSpace(repoLine)),
		zap.String("file_path", "/etc/apt/sources.list.d/docker.list"))

	if err := os.WriteFile("/etc/apt/sources.list.d/docker.list", []byte(repoLine), 0644); err != nil {
		logger.Error(" Failed to write Docker repository file", zap.Error(err))
		return cerr.Wrap(err, "write Docker repository file")
	}

	logger.Info(" Updating APT repositories")
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "apt-get",
		Args:    []string{"update"},
	}); err != nil {
		logger.Error(" Failed to update APT repositories", zap.Error(err))
		return cerr.Wrap(err, "update APT repositories")
	}

	logger.Info(" Docker repository added and APT updated successfully")
	return nil
}

// InstallDockerEngine installs Docker CE and related components
func InstallDockerEngine(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Installing Docker engine and components")

	packages := []string{
		"docker-ce",
		"docker-ce-cli",
		"containerd.io",
		"docker-buildx-plugin",
		"docker-compose-plugin",
	}

	logger.Debug(" Installing Docker packages",
		zap.Strings("packages", packages))

	args := append([]string{"install", "-y"}, packages...)

	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "apt",
		Args:    args,
	}); err != nil {
		logger.Error(" Docker installation failed", zap.Error(err))
		return cerr.Wrap(err, "install Docker packages")
	}

	logger.Info(" Docker engine and components installed successfully")
	return nil
}

// VerifyDockerInstallation verifies Docker installation by running hello-world
func VerifyDockerInstallation(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Verifying Docker installation with hello-world container")

	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "docker",
		Args:    []string{"run", "--rm", "hello-world"},
		Capture: true,
	})
	if err != nil {
		logger.Error(" Docker hello-world verification failed", zap.Error(err))
		return cerr.Wrap(err, "run Docker hello-world")
	}

	// Clean and normalize the output for verification
	cleanOutput := strings.TrimSpace(output)
	logger.Info(" Docker hello-world output received",
		zap.String("output", cleanOutput),
		zap.Int("output_length", len(cleanOutput)))

	// Check for multiple possible success indicators
	successIndicators := []string{
		"Hello from Docker!",
		"Hello from Docker",
		"installation appears to be working correctly",
		"Docker took the following steps",
	}

	found := false
	for _, indicator := range successIndicators {
		if strings.Contains(cleanOutput, indicator) {
			logger.Info(" Docker verification successful",
				zap.String("found_indicator", indicator))
			found = true
			break
		}
	}

	if !found {
		logger.Error(" Docker hello-world output doesn't contain expected success message",
			zap.String("output", cleanOutput),
			zap.Strings("expected_indicators", successIndicators))
		return cerr.New("Docker hello-world verification failed - unexpected output")
	}

	logger.Info(" Docker installation verified successfully")
	return nil
}

// SetupDockerNonRoot configures Docker for non-root user access
func SetupDockerNonRoot(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Setting up Docker for non-root user access")

	// Create docker group (may already exist)
	logger.Debug(" Creating docker group")
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "groupadd",
		Args:    []string{"docker"},
	}); err != nil {
		logger.Debug("Docker group creation failed (likely already exists)", zap.Error(err))
		// This is not a critical error as the group might already exist
	}

	// Determine the user to add to docker group with improved detection
	user := os.Getenv("SUDO_USER")
	if user == "" {
		user = os.Getenv("USER")
	}
	
	// Additional fallback: check who actually invoked sudo
	originalUser := ""
	if logname, err := execute.Run(rc.Ctx, execute.Options{
		Command: "logname",
		Args:    []string{},
		Capture: true,
	}); err == nil {
		originalUser = strings.TrimSpace(logname)
	}

	logger.Info(" Detected user information",
		zap.String("sudo_user", os.Getenv("SUDO_USER")),
		zap.String("user", os.Getenv("USER")),
		zap.String("logname", originalUser),
		zap.String("selected_user", user))

	// Use logname as fallback if SUDO_USER is not available
	if (user == "" || user == "root") && originalUser != "" && originalUser != "root" {
		user = originalUser
		logger.Info(" Using logname as fallback user", zap.String("user", user))
	}

	if user == "" || user == "root" {
		logger.Warn(" No non-root user detected; skipping usermod step",
			zap.String("sudo_user", os.Getenv("SUDO_USER")),
			zap.String("user_env", os.Getenv("USER")),
			zap.String("logname", originalUser))
		logger.Warn(" IMPORTANT: You may need to manually add your user to docker group:")
		logger.Warn("   sudo usermod -aG docker YOUR_USERNAME")
		return nil
	}

	// Add user to docker group
	logger.Info(" Adding user to docker group", zap.String("user", user))
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "usermod",
		Args:    []string{"-aG", "docker", user},
	}); err != nil {
		logger.Error(" Failed to add user to docker group",
			zap.String("user", user),
			zap.Error(err))
		return cerr.Wrapf(err, "add user %s to docker group", user)
	}

	logger.Info(" User added to docker group successfully",
		zap.String("user", user))
	
	// Verify the user was added to the group
	if output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "groups",
		Args:    []string{user},
	}); err == nil {
		if strings.Contains(output, "docker") {
			logger.Info(" Confirmed: User is now in docker group",
				zap.String("user", user))
		} else {
			logger.Warn(" Warning: User does not appear in docker group yet",
				zap.String("user", user),
				zap.String("groups", output))
		}
	}
	
	logger.Info(" IMPORTANT: To use Docker without sudo, you must:")
	logger.Info("   1. Log out and log back in (recommended), OR")
	logger.Info("   2. Run 'newgrp docker' in your current shell")
	logger.Info("   3. Test with: docker ps")

	return nil
}

// InstallDocker performs a complete Docker installation with all steps
func InstallDocker(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Starting complete Docker installation process")

	// Step 1: Uninstall conflicting packages
	logger.Info(" Removing conflicting Docker packages")
	UninstallConflictingPackages(rc)

	// Step 2: Remove Docker snap
	logger.Info(" Removing Docker snap package")
	UninstallSnapDocker(rc)

	// Step 3: Install prerequisites and GPG keys
	if err := InstallPrerequisitesAndGpg(rc); err != nil {
		return cerr.Wrap(err, "install prerequisites and GPG keys")
	}

	// Step 4: Add Docker repository
	if err := AddDockerRepository(rc); err != nil {
		return cerr.Wrap(err, "add Docker repository")
	}

	// Step 5: Install Docker engine
	if err := InstallDockerEngine(rc); err != nil {
		return cerr.Wrap(err, "install Docker engine")
	}

	// Step 6: Verify installation as root
	logger.Info(" Verifying Docker installation as root")
	if err := VerifyDockerInstallation(rc); err != nil {
		return cerr.Wrap(err, "verify Docker installation as root")
	}

	// Step 7: Setup non-root access
	if err := SetupDockerNonRoot(rc); err != nil {
		return cerr.Wrap(err, "setup Docker non-root access")
	}

	// Step 8: Verify installation as non-root (if possible)
	logger.Info(" Attempting to verify Docker installation for non-root user")
	if err := VerifyDockerInstallation(rc); err != nil {
		logger.Warn("Non-root Docker verification failed (user may need to log out/in)",
			zap.Error(err))
		// Don't return error here as this is expected until user logs out/in
	}

	logger.Info(" Docker installation completed successfully")
	logger.Info(" ")
	logger.Info(" NEXT STEPS:")
	logger.Info("   • Log out and log back in to activate Docker group membership")
	logger.Info("   • OR run: newgrp docker")
	logger.Info("   • Test Docker access: docker ps")
	logger.Info("   • If you still get permission denied, reboot the system")

	return nil
}
