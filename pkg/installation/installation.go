package installation

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Common installation utilities to reduce duplication across the codebase

// InstallationMethod represents different installation approaches
type InstallationMethod string

const (
	MethodApt     InstallationMethod = "apt"
	MethodSnap    InstallationMethod = "snap"
	MethodDpkg    InstallationMethod = "dpkg"
	MethodWget    InstallationMethod = "wget"
	MethodGit     InstallationMethod = "git"
	MethodDocker  InstallationMethod = "docker"
	MethodPip     InstallationMethod = "pip"
	MethodCurl    InstallationMethod = "curl"
)

// InstallationConfig holds configuration for package installation
type InstallationConfig struct {
	// Basic configuration
	Name        string             `json:"name"`
	Method      InstallationMethod `json:"method"`
	Description string             `json:"description"`
	
	// Package specific
	PackageName string   `json:"package_name,omitempty"`
	Version     string   `json:"version,omitempty"`
	Repository  string   `json:"repository,omitempty"`
	URL         string   `json:"url,omitempty"`
	
	// Installation paths
	InstallPath string `json:"install_path,omitempty"`
	ConfigPath  string `json:"config_path,omitempty"`
	BinaryPath  string `json:"binary_path,omitempty"`
	
	// Prerequisites
	Dependencies []string `json:"dependencies,omitempty"`
	
	// Post-installation
	ServiceFile    string            `json:"service_file,omitempty"`
	ConfigFiles    []string          `json:"config_files,omitempty"`
	EnvironmentVars map[string]string `json:"environment_vars,omitempty"`
	
	// Options
	Force          bool     `json:"force"`
	CreateUser     bool     `json:"create_user"`
	Username       string   `json:"username,omitempty"`
	ExtraArgs      []string `json:"extra_args,omitempty"`
}

// InstallationResult holds the result of an installation operation
type InstallationResult struct {
	Success     bool              `json:"success"`
	Method      InstallationMethod `json:"method"`
	Version     string            `json:"version,omitempty"`
	InstalledTo string            `json:"installed_to,omitempty"`
	ConfigFiles []string          `json:"config_files,omitempty"`
	Messages    []string          `json:"messages,omitempty"`
	Errors      []string          `json:"errors,omitempty"`
}

// InstallationFramework provides a standardized approach to software installation
type InstallationFramework struct {
	rc     *eos_io.RuntimeContext
	logger otelzap.LoggerWithCtx
}

// NewInstallationFramework creates a new installation framework instance
func NewInstallationFramework(rc *eos_io.RuntimeContext) *InstallationFramework {
	return &InstallationFramework{
		rc:     rc,
		logger: otelzap.Ctx(rc.Ctx),
	}
}

// Install performs installation following the Assess → Intervene → Evaluate pattern
func (f *InstallationFramework) Install(config *InstallationConfig) (*InstallationResult, error) {
	result := &InstallationResult{
		Method: config.Method,
	}
	
	// ASSESS - Check prerequisites and current state
	f.logger.Info("Assessing installation requirements",
		zap.String("package", config.Name),
		zap.String("method", string(config.Method)))
	
	if err := f.assessPrerequisites(config); err != nil {
		return result, shared.WrapPrerequisiteError(config.Name, err)
	}
	
	// Check if already installed
	if installed, version := f.isInstalled(config); installed && !config.Force {
		f.logger.Info("Package already installed",
			zap.String("package", config.Name),
			zap.String("version", version))
		result.Success = true
		result.Version = version
		result.Messages = append(result.Messages, fmt.Sprintf("%s is already installed (version %s)", config.Name, version))
		return result, nil
	}
	
	// INTERVENE - Perform installation
	f.logger.Info("Installing package",
		zap.String("package", config.Name),
		zap.String("method", string(config.Method)))
	
	if err := f.performInstallation(config, result); err != nil {
		return result, shared.WrapInstallationError(config.Name, string(config.Method), err)
	}
	
	// EVALUATE - Verify installation
	f.logger.Info("Verifying installation",
		zap.String("package", config.Name))
	
	if err := f.verifyInstallation(config, result); err != nil {
		return result, fmt.Errorf("installation verification failed for %s: %w", config.Name, err)
	}
	
	result.Success = true
	f.logger.Info("Installation completed successfully",
		zap.String("package", config.Name),
		zap.String("version", result.Version))
	
	return result, nil
}

// assessPrerequisites checks if installation can proceed
func (f *InstallationFramework) assessPrerequisites(config *InstallationConfig) error {
	// Check root permissions if needed
	if f.requiresRoot(config.Method) && os.Geteuid() != 0 {
		return fmt.Errorf("installation requires root privileges")
	}
	
	// Check network connectivity for download methods
	if f.requiresNetwork(config.Method) {
		f.logger.Debug("Network-based installation method detected",
			zap.String("method", string(config.Method)))
		// TODO: Add network connectivity check when needed
	}
	
	// Install dependencies first
	if len(config.Dependencies) > 0 {
		f.logger.Info("Installing dependencies",
			zap.Strings("dependencies", config.Dependencies))
		
		for _, dep := range config.Dependencies {
			if err := f.installDependency(dep); err != nil {
				return fmt.Errorf("failed to install dependency %s: %w", dep, err)
			}
		}
	}
	
	return nil
}

// performInstallation executes the actual installation
func (f *InstallationFramework) performInstallation(config *InstallationConfig, result *InstallationResult) error {
	switch config.Method {
	case MethodApt:
		return f.installViaApt(config, result)
	case MethodSnap:
		return f.installViaSnap(config, result)
	case MethodDpkg:
		return f.installViaDpkg(config, result)
	case MethodWget:
		return f.installViaWget(config, result)
	case MethodGit:
		return f.installViaGit(config, result)
	case MethodDocker:
		return f.installViaDocker(config, result)
	case MethodPip:
		return f.installViaPip(config, result)
	case MethodCurl:
		return f.installViaCurl(config, result)
	default:
		return fmt.Errorf("unsupported installation method: %s", config.Method)
	}
}

// installViaApt installs using apt package manager
func (f *InstallationFramework) installViaApt(config *InstallationConfig, result *InstallationResult) error {
	args := []string{"install", "-y"}
	if config.Force {
		args = append(args, "--reinstall")
	}
	args = append(args, config.PackageName)
	
	if err := f.runCommand( "apt-get", args...); err != nil {
		return err
	}
	
	result.InstalledTo = "/usr/bin/" + config.PackageName
	return nil
}

// installViaSnap installs using snap package manager
func (f *InstallationFramework) installViaSnap(config *InstallationConfig, result *InstallationResult) error {
	args := []string{"install"}
	if config.Force {
		args = append(args, "--dangerous")
	}
	args = append(args, config.PackageName)
	
	if err := f.runCommand( "snap", args...); err != nil {
		return err
	}
	
	result.InstalledTo = "/snap/bin/" + config.PackageName
	return nil
}

// installViaDpkg installs using dpkg
func (f *InstallationFramework) installViaDpkg(config *InstallationConfig, result *InstallationResult) error {
	if config.URL == "" {
		return fmt.Errorf("dpkg installation requires URL")
	}
	
	// Download package first
	tempFile := filepath.Join("/tmp", config.PackageName+".deb")
	if err := f.downloadFile(config.URL, tempFile); err != nil {
		return err
	}
	defer func() {
		if err := os.Remove(tempFile); err != nil {
			f.logger.Warn("Failed to remove temporary file", zap.String("file", tempFile), zap.Error(err))
		}
	}()
	
	// Install with dpkg
	if err := f.runCommand( "dpkg", "-i", tempFile); err != nil {
		// Try to fix dependencies
		if fixErr := f.runCommand( "apt-get", "install", "-f", "-y"); fixErr != nil {
			f.logger.Warn("Failed to fix dependencies after dpkg failure", zap.Error(fixErr))
		}
		return err
	}
	
	return nil
}

// installViaWget installs by downloading and extracting
func (f *InstallationFramework) installViaWget(config *InstallationConfig, result *InstallationResult) error {
	if config.URL == "" || config.InstallPath == "" {
		return fmt.Errorf("wget installation requires URL and install path")
	}
	
	// Ensure install directory exists
	if err := shared.EnsureDirectoryExists(config.InstallPath, 0755); err != nil {
		return err
	}
	
	// Download and extract
	tempFile := filepath.Join("/tmp", filepath.Base(config.URL))
	if err := f.downloadFile(config.URL, tempFile); err != nil {
		return err
	}
	defer func() {
		if err := os.Remove(tempFile); err != nil {
			f.logger.Warn("Failed to remove temporary file", zap.String("file", tempFile), zap.Error(err))
		}
	}()
	
	// Extract if it's an archive
	if f.isArchive(tempFile) {
		return f.extractArchive(tempFile, config.InstallPath)
	}
	
	// Copy binary
	finalPath := filepath.Join(config.InstallPath, config.Name)
	if err := shared.CopyFile(tempFile, finalPath); err != nil {
		return err
	}
	
	// Make executable
	if err := shared.MakeExecutable(finalPath); err != nil {
		return err
	}
	
	result.InstalledTo = finalPath
	return nil
}

// installViaGit clones and builds from git repository
func (f *InstallationFramework) installViaGit(config *InstallationConfig, result *InstallationResult) error {
	if config.Repository == "" || config.InstallPath == "" {
		return fmt.Errorf("git installation requires repository and install path")
	}
	
	// Clone repository
	if err := f.runCommand( "git", "clone", config.Repository, config.InstallPath); err != nil {
		return err
	}
	
	// TODO: Add build steps if needed
	result.InstalledTo = config.InstallPath
	return nil
}

// installViaDocker pulls docker image
func (f *InstallationFramework) installViaDocker(config *InstallationConfig, result *InstallationResult) error {
	if config.PackageName == "" {
		return fmt.Errorf("docker installation requires image name")
	}
	
	image := config.PackageName
	if config.Version != "" {
		image += ":" + config.Version
	}
	
	if err := f.runCommand( "docker", "pull", image); err != nil {
		return err
	}
	
	result.InstalledTo = "docker:" + image
	return nil
}

// installViaPip installs Python packages
func (f *InstallationFramework) installViaPip(config *InstallationConfig, result *InstallationResult) error {
	args := []string{"install"}
	if config.Force {
		args = append(args, "--force-reinstall")
	}
	args = append(args, config.PackageName)
	
	if err := f.runCommand( "pip3", args...); err != nil {
		return err
	}
	
	return nil
}

// installViaCurl installs by downloading with curl
func (f *InstallationFramework) installViaCurl(config *InstallationConfig, result *InstallationResult) error {
	if config.URL == "" || config.InstallPath == "" {
		return fmt.Errorf("curl installation requires URL and install path")
	}
	
	// Download directly to final location
	finalPath := filepath.Join(config.InstallPath, config.Name)
	if err := shared.EnsureDirectoryExists(config.InstallPath, 0755); err != nil {
		return err
	}
	
	if err := f.runCommand( "curl", "-fsSL", "-o", finalPath, config.URL); err != nil {
		return err
	}
	
	if err := shared.MakeExecutable(finalPath); err != nil {
		return err
	}
	
	result.InstalledTo = finalPath
	return nil
}

// verifyInstallation checks that installation was successful
func (f *InstallationFramework) verifyInstallation(config *InstallationConfig, result *InstallationResult) error {
	// Check if binary is accessible
	if config.BinaryPath != "" || result.InstalledTo != "" {
		binaryPath := config.BinaryPath
		if binaryPath == "" {
			binaryPath = result.InstalledTo
		}
		
		if !shared.FileExists(binaryPath) && !f.isInPath(config.PackageName) {
			return fmt.Errorf("binary not found after installation")
		}
	}
	
	// Get version if possible
	if version, err := f.getInstalledVersion(config); err == nil {
		result.Version = version
	}
	
	return nil
}

// Helper functions

func (f *InstallationFramework) isInstalled(config *InstallationConfig) (bool, string) {
	// Check if binary exists
	if config.BinaryPath != "" {
		if shared.FileExists(config.BinaryPath) {
			if version, err := f.getInstalledVersion(config); err == nil {
				return true, version
			}
			return true, "unknown"
		}
	}
	
	// Check if in PATH
	if f.isInPath(config.PackageName) {
		if version, err := f.getInstalledVersion(config); err == nil {
			return true, version
		}
		return true, "unknown"
	}
	
	return false, ""
}

func (f *InstallationFramework) isInPath(command string) bool {
	return f.runCommand( "which", command) == nil
}

func (f *InstallationFramework) getInstalledVersion(config *InstallationConfig) (string, error) {
	// Try common version commands
	versionCommands := [][]string{
		{config.PackageName, "--version"},
		{config.PackageName, "-v"},
		{config.PackageName, "version"},
	}
	
	for _, cmd := range versionCommands {
		if len(cmd) >= 2 {
			if err := f.runCommand( cmd[0], cmd[1:]...); err == nil {
				// TODO: Parse version from output
				return "installed", nil
			}
		}
	}
	
	return "unknown", fmt.Errorf("could not determine version")
}

func (f *InstallationFramework) requiresRoot(method InstallationMethod) bool {
	switch method {
	case MethodApt, MethodSnap, MethodDpkg:
		return true
	default:
		return false
	}
}

func (f *InstallationFramework) requiresNetwork(method InstallationMethod) bool {
	switch method {
	case MethodApt, MethodSnap, MethodWget, MethodGit, MethodDocker, MethodPip, MethodCurl:
		return true
	default:
		return false
	}
}

func (f *InstallationFramework) installDependency(dep string) error {
	// Simple apt installation for dependencies
	return f.runCommand( "apt-get", "install", "-y", dep)
}

func (f *InstallationFramework) downloadFile(url, dest string) error {
	return f.runCommand( "wget", "-O", dest, url)
}

func (f *InstallationFramework) isArchive(path string) bool {
	ext := filepath.Ext(path)
	return ext == ".tar" || ext == ".gz" || ext == ".tgz" || ext == ".zip"
}

func (f *InstallationFramework) extractArchive(archive, dest string) error {
	ext := filepath.Ext(archive)
	switch ext {
	case ".tar", ".tgz":
		return f.runCommand( "tar", "-xzf", archive, "-C", dest)
	case ".zip":
		return f.runCommand( "unzip", archive, "-d", dest)
	default:
		return fmt.Errorf("unsupported archive format: %s", ext)
	}
}

// runCommand executes a command with context and logging
func (f *InstallationFramework) runCommand(name string, args ...string) error {
	cmd := exec.CommandContext(f.rc.Ctx, name, args...)
	f.logger.Debug("Executing command",
		zap.String("command", name),
		zap.Strings("args", args))
	
	if output, err := cmd.CombinedOutput(); err != nil {
		f.logger.Error("Command execution failed",
			zap.String("command", name),
			zap.Strings("args", args),
			zap.Error(err),
			zap.String("output", string(output)))
		return fmt.Errorf("command %s failed: %w", name, err)
	}
	
	return nil
}