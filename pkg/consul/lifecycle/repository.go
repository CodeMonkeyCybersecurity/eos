// pkg/consul/installer/repository.go
// APT repository installation for Consul

package lifecycle

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RepositoryInstaller handles Consul installation via APT repository
type RepositoryInstaller struct {
	rc     *eos_io.RuntimeContext
	logger otelzap.LoggerWithCtx
}

// NewRepositoryInstaller creates a new repository installer instance
func NewRepositoryInstaller(rc *eos_io.RuntimeContext) *RepositoryInstaller {
	return &RepositoryInstaller{
		rc:     rc,
		logger: otelzap.Ctx(rc.Ctx),
	}
}

// Install installs Consul using HashiCorp APT repository
func (ri *RepositoryInstaller) Install(version string) error {
	ri.logger.Info("Installing Consul via HashiCorp APT repository",
		zap.String("version", version))

	// Add HashiCorp GPG key
	if err := ri.addGPGKey(); err != nil {
		return fmt.Errorf("failed to add GPG key: %w", err)
	}

	// Add HashiCorp repository
	if err := ri.addRepository(); err != nil {
		return fmt.Errorf("failed to add repository: %w", err)
	}

	// Update package list
	if err := ri.updatePackageList(); err != nil {
		return fmt.Errorf("failed to update package list: %w", err)
	}

	// Install Consul package
	if err := ri.installPackage(version); err != nil {
		return fmt.Errorf("failed to install Consul package: %w", err)
	}

	ri.logger.Info("Consul installed successfully via APT repository")
	return nil
}

// addGPGKey adds the HashiCorp GPG key for package verification
func (ri *RepositoryInstaller) addGPGKey() error {
	ri.logger.Info("Adding HashiCorp GPG key")

	cmd := exec.Command("sh", "-c",
		"wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("GPG key installation failed: %w (output: %s)", err, string(output))
	}

	ri.logger.Info("HashiCorp GPG key added successfully")
	return nil
}

// addRepository adds the HashiCorp APT repository
func (ri *RepositoryInstaller) addRepository() error {
	ri.logger.Info("Adding HashiCorp repository")

	codename := ri.getUbuntuCodename()
	repoLine := fmt.Sprintf("deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com %s main",
		codename)

	if err := os.WriteFile("/etc/apt/sources.list.d/hashicorp.list", []byte(repoLine), consul.ConsulConfigPerm); err != nil {
		return fmt.Errorf("failed to write repository file: %w", err)
	}

	ri.logger.Info("HashiCorp repository added",
		zap.String("codename", codename))
	return nil
}

// updatePackageList updates the APT package list
func (ri *RepositoryInstaller) updatePackageList() error {
	ri.logger.Info("Updating package list")

	cmd := exec.Command("apt-get", "update")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("apt-get update failed: %w", err)
	}

	ri.logger.Info("Package list updated successfully")
	return nil
}

// installPackage installs the Consul package
func (ri *RepositoryInstaller) installPackage(version string) error {
	ri.logger.Info("Installing Consul package",
		zap.String("version", version))

	var args []string
	if version != "latest" {
		args = []string{"apt-get", "install", "-y", fmt.Sprintf("consul=%s", version)}
	} else {
		args = []string{"apt-get", "install", "-y", "consul"}
	}

	cmd := exec.Command(args[0], args[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("apt-get install failed: %w (output: %s)", err, string(output))
	}

	ri.logger.Info("Consul package installed successfully")
	return nil
}

// getUbuntuCodename returns the Ubuntu codename for APT repository
func (ri *RepositoryInstaller) getUbuntuCodename() string {
	cmd := exec.Command("lsb_release", "-cs")
	output, err := cmd.Output()
	if err != nil {
		ri.logger.Warn("Failed to detect Ubuntu codename, using default",
			zap.Error(err))
		return "noble" // Default to latest LTS
	}

	codename := strings.TrimSpace(string(output))
	ri.logger.Debug("Detected Ubuntu codename",
		zap.String("codename", codename))

	return codename
}
