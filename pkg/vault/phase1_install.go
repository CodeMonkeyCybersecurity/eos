// pkg/vault/phase1_install.go

package vault

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// DEPRECATED: Direct Package Manager Installation
//--------------------------------------------------------------------
// 
// This file contains deprecated functions for direct package manager installation.
// All new deployments should use the SaltStack-based installation via:
//   eos create vault-salt
//
// These functions are maintained only for backward compatibility and will be
// removed in a future version.

// PHASE 1 — PhaseInstallVault()
//             └── InstallVaultViaApt()
//             └── InstallVaultViaDnf()

// PhaseInstallVault ensures Vault binary is installed via APT or DNF,
// depending on detected Linux distribution. No-op if already installed.
func PhaseInstallVault(rc *eos_io.RuntimeContext) error {
	otelzap.Ctx(rc.Ctx).Info("[1/13] Ensuring Vault is installed")

	distro := platform.DetectLinuxDistro(rc)
	otelzap.Ctx(rc.Ctx).Info("Detected Linux distribution", zap.String("distro", distro))

	switch distro {
	case "debian":
		otelzap.Ctx(rc.Ctx).Info("Using APT to install Vault", zap.String("installer", "apt-get"))
		if err := InstallVaultViaApt(rc); err != nil {
			otelzap.Ctx(rc.Ctx).Error(" Vault installation via APT failed", zap.Error(err))
			return fmt.Errorf("vault install via apt failed: %w", err)
		}
	case "rhel":
		otelzap.Ctx(rc.Ctx).Info("Using DNF to install Vault", zap.String("installer", "dnf"))
		if err := InstallVaultViaDnf(rc); err != nil {
			otelzap.Ctx(rc.Ctx).Error(" Vault installation via DNF failed", zap.Error(err))
			return fmt.Errorf("vault install via dnf failed: %w", err)
		}
	default:
		otelzap.Ctx(rc.Ctx).Error(" Unsupported Linux distro for Vault install", zap.String("distro", distro))
		return fmt.Errorf("unsupported distro for Vault install: %s", distro)
	}

	otelzap.Ctx(rc.Ctx).Info(" Vault installed successfully")
	return nil
}

// InstallVaultViaApt ensures the Vault binary is installed on Debian-based systems via APT.
// It adds the official HashiCorp repository if needed, installs Vault, and verifies the binary path.
func InstallVaultViaApt(rc *eos_io.RuntimeContext) error {
	otelzap.Ctx(rc.Ctx).Info(" Checking if Vault is already installed via apt")
	if _, err := exec.LookPath("vault"); err == nil {
		otelzap.Ctx(rc.Ctx).Info(" Vault is already installed")
		return nil
	}

	otelzap.Ctx(rc.Ctx).Info(" Vault binary not found, proceeding with installation via apt")

	// Step 1: Download and save the HashiCorp GPG key
	otelzap.Ctx(rc.Ctx).Info(" Downloading HashiCorp GPG key")
	curlCmd := exec.CommandContext(rc.Ctx, "curl", "-fsSL", "https://apt.releases.hashicorp.com/gpg")
	gpgCmd := exec.CommandContext(rc.Ctx, "gpg", "--dearmor", "-o", "/usr/share/keyrings/hashicorp-archive-keyring.gpg")

	pipeReader, pipeWriter := io.Pipe()
	curlCmd.Stdout = pipeWriter
	gpgCmd.Stdin = pipeReader

	curlCmd.Stderr = os.Stderr
	gpgCmd.Stdout = os.Stdout
	gpgCmd.Stderr = os.Stderr

	if err := curlCmd.Start(); err != nil {
		return fmt.Errorf("failed to start curl: %w", err)
	}
	if err := gpgCmd.Start(); err != nil {
		return fmt.Errorf("failed to start gpg: %w", err)
	}

	if err := curlCmd.Wait(); err != nil {
		return fmt.Errorf("curl command failed: %w", err)
	}
	if err := pipeWriter.Close(); err != nil {
		otelzap.Ctx(rc.Ctx).Warn("Failed to close pipeWriter", zap.Error(err))
	}

	if err := gpgCmd.Wait(); err != nil {
		return fmt.Errorf("gpg command failed: %w", err)
	}

	// Step 2: Write the APT source list
	otelzap.Ctx(rc.Ctx).Info(" Adding HashiCorp APT repository")
	distroCodenameCmd := exec.CommandContext(rc.Ctx, "lsb_release", "-cs")
	codenameBytes, err := distroCodenameCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to detect distro codename: %w", err)
	}
	codename := strings.TrimSpace(string(codenameBytes))

	repoEntry := fmt.Sprintf(
		"deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com %s main\n",
		codename)

	if err := os.WriteFile("/etc/apt/sources.list.d/hashicorp.list", []byte(repoEntry), 0644); err != nil {
		return fmt.Errorf("failed to write APT source file: %w", err)
	}

	// Step 3: Update and install
	otelzap.Ctx(rc.Ctx).Info("♻️ Updating APT package cache")
	if err := exec.CommandContext(rc.Ctx, "apt-get", "update").Run(); err != nil {
		return fmt.Errorf("apt-get update failed: %w", err)
	}

	otelzap.Ctx(rc.Ctx).Info(" Installing Vault from HashiCorp repo via apt")
	installCmd := exec.CommandContext(rc.Ctx, "apt-get", "install", "-y", "vault")
	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr
	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("vault installation via apt-get failed: %w", err)
	}

	info, err := os.Stat(shared.VaultBinaryPath)
	if err != nil {
		return fmt.Errorf("vault binary missing after install: %w", err)
	}
	if info.Mode()&0111 == 0 {
		return fmt.Errorf("vault binary is not executable (permissions issue)")
	}
	otelzap.Ctx(rc.Ctx).Info(" Vault binary found", zap.String("path", shared.VaultBinaryPath))
	return nil
}

func InstallVaultViaDnf(rc *eos_io.RuntimeContext) error {
	otelzap.Ctx(rc.Ctx).Info(" Checking if Vault is already installed via dnf")
	if _, err := exec.LookPath("vault"); err == nil {
		otelzap.Ctx(rc.Ctx).Info(" Vault is already installed")
		return nil
	}

	otelzap.Ctx(rc.Ctx).Info(" Vault binary not found, proceeding with installation via dnf")

	repoFile := "/etc/yum.repos.d/hashicorp.repo"
	if _, err := os.Stat(repoFile); os.IsNotExist(err) {
		otelzap.Ctx(rc.Ctx).Info(" Adding HashiCorp YUM repo")
		repoContent := `[hashicorp]
name=HashiCorp Stable - $basearch
baseurl=https://rpm.releases.hashicorp.com/RHEL/9/$basearch/stable
enabled=1
gpgcheck=1
gpgkey=https://rpm.releases.hashicorp.com/gpg`
		if err := os.WriteFile(repoFile, []byte(repoContent), 0644); err != nil {
			return fmt.Errorf("failed to write YUM repo file: %w", err)
		}
	}

	otelzap.Ctx(rc.Ctx).Info("♻️ Cleaning and refreshing DNF cache")
	_ = exec.CommandContext(rc.Ctx, "dnf", "clean", "all").Run()
	_ = exec.CommandContext(rc.Ctx, "dnf", "makecache").Run()

	otelzap.Ctx(rc.Ctx).Info(" Installing Vault via dnf")
	dnfCmd := exec.CommandContext(rc.Ctx, "dnf", "install", "-y", "vault")
	dnfCmd.Stdout = os.Stdout
	dnfCmd.Stderr = os.Stderr
	if err := dnfCmd.Run(); err != nil {
		return fmt.Errorf("vault installation via dnf failed: %w", err)
	}

	otelzap.Ctx(rc.Ctx).Info(" Vault installed successfully via dnf")
	return nil
}
