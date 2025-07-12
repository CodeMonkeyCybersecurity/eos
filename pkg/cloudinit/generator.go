// pkg/cloudinit/generator.go
package cloudinit

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

var (
	OutputPath   string
	TemplateMode bool
)

func RunCreateCloudInit(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Generating cloud-init configuration")

	generator := NewGenerator(rc)

	// Generate template if requested
	if TemplateMode {
		logger.Info("Generating cloud-init template", zap.String("output", OutputPath))
		if err := generator.GenerateTemplate(OutputPath); err != nil {
			return fmt.Errorf("failed to generate template: %w", err)
		}
		return nil
	}

	// Gather system information
	logger.Info("Gathering system information")
	info, err := generator.GatherSystemInfo()
	if err != nil {
		return fmt.Errorf("failed to gather system info: %w", err)
	}

	logger.Info("System information gathered",
		zap.String("hostname", info.Hostname),
		zap.String("username", info.Username),
		zap.Int("packages", len(info.InstalledPackages)),
		zap.Bool("ssh_key_found", info.SSHPublicKey != ""))

	// Generate configuration
	config, err := generator.GenerateConfig(info)
	if err != nil {
		return fmt.Errorf("failed to generate config: %w", err)
	}

	// Validate configuration
	if err := generator.ValidateConfig(config); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	// Write configuration
	if err := generator.WriteConfig(config, OutputPath); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	logger.Info("Cloud-init configuration generated successfully",
		zap.String("output", OutputPath),
		zap.String("hostname", config.Hostname),
		zap.Int("users", len(config.Users)),
		zap.Int("packages", len(config.Packages)))

	fmt.Printf("\nCloud-init configuration generated successfully!\n")
	fmt.Printf("Output: %s\n", OutputPath)
	fmt.Printf("Hostname: %s\n", config.Hostname)
	fmt.Printf(" User: %s\n", info.Username)
	fmt.Printf("Packages: %d\n", len(config.Packages))

	if info.SSHPublicKey != "" {
		fmt.Printf("SSH Key: Configured\n")
	} else {
		fmt.Printf("SSH Key: Not found - manual configuration needed\n")
	}

	return nil
}

// CloudInitConfig represents cloud-init configuration
type CloudInitConfig struct {
	Hostname       string      `yaml:"hostname"`
	ManageEtcHosts bool        `yaml:"manage_etc_hosts"`
	Network        NetworkConf `yaml:"network"`
	Users          []UserConf  `yaml:"users"`
	PackageUpdate  bool        `yaml:"package_update"`
	PackageUpgrade bool        `yaml:"package_upgrade"`
	Packages       []string    `yaml:"packages"`
	RunCmd         []string    `yaml:"runcmd"`
	WriteFiles     []WriteFile `yaml:"write_files,omitempty"`
	FinalMessage   string      `yaml:"final_message,omitempty"`
}

type NetworkConf struct {
	Version   int                `yaml:"version"`
	Ethernets map[string]EthConf `yaml:"ethernets"`
}

type EthConf struct {
	DHCP4       bool     `yaml:"dhcp4"`
	DHCP6       bool     `yaml:"dhcp6,omitempty"`
	Addresses   []string `yaml:"addresses,omitempty"`
	Gateway4    string   `yaml:"gateway4,omitempty"`
	Gateway6    string   `yaml:"gateway6,omitempty"`
	Nameservers *NSConf  `yaml:"nameservers,omitempty"`
}

type NSConf struct {
	Addresses []string `yaml:"addresses"`
}

type UserConf struct {
	Name              string   `yaml:"name"`
	Sudo              string   `yaml:"sudo"`
	Shell             string   `yaml:"shell,omitempty"`
	Home              string   `yaml:"home,omitempty"`
	SSHAuthorizedKeys []string `yaml:"ssh_authorized_keys"`
	Groups            []string `yaml:"groups,omitempty"`
}

type WriteFile struct {
	Path        string `yaml:"path"`
	Content     string `yaml:"content"`
	Permissions string `yaml:"permissions,omitempty"`
	Owner       string `yaml:"owner,omitempty"`
}

// Generator creates cloud-init configurations
type Generator struct {
	rc     *eos_io.RuntimeContext
	logger otelzap.LoggerWithCtx
}

// NewGenerator creates a new cloud-init generator
func NewGenerator(rc *eos_io.RuntimeContext) *Generator {
	return &Generator{
		rc:     rc,
		logger: otelzap.Ctx(rc.Ctx),
	}
}

// SystemInfo contains system information for cloud-init
type SystemInfo struct {
	Hostname          string
	Username          string
	SSHPublicKey      string
	InstalledPackages []string
	UserHome          string
	UserGroups        []string
}

// GatherSystemInfo collects current system information
func (g *Generator) GatherSystemInfo() (*SystemInfo, error) {
	_, span := telemetry.Start(g.rc.Ctx, "GatherSystemInfo")
	defer span.End()

	info := &SystemInfo{}

	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname: %w", err)
	}
	info.Hostname = hostname

	// Get current user
	currentUser, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("failed to get current user: %w", err)
	}
	info.Username = currentUser.Username
	info.UserHome = currentUser.HomeDir

	// Get user groups
	groups, err := g.getUserGroups(currentUser.Username)
	if err != nil {
		g.logger.Warn("Failed to get user groups", zap.Error(err))
		info.UserGroups = []string{"adm", "dialout", "cdrom", "floppy", "sudo", "audio", "dip", "video", "plugdev", "netdev", "lxd"}
	} else {
		info.UserGroups = groups
	}

	// Get SSH public key
	sshKey, err := g.getSSHPublicKey(currentUser.HomeDir)
	if err != nil {
		g.logger.Warn("Failed to get SSH key", zap.Error(err))
	} else {
		info.SSHPublicKey = sshKey
	}

	// Get installed packages
	packages, err := g.getInstalledPackages()
	if err != nil {
		g.logger.Warn("Failed to get installed packages", zap.Error(err))
	} else {
		info.InstalledPackages = packages
	}

	return info, nil
}

// getSSHPublicKey reads the user's SSH public key
func (g *Generator) getSSHPublicKey(homeDir string) (string, error) {
	// Try different key types in order of preference
	keyTypes := []string{"id_ed25519.pub", "id_rsa.pub", "id_ecdsa.pub", "id_dsa.pub"}

	for _, keyFile := range keyTypes {
		keyPath := filepath.Join(homeDir, ".ssh", keyFile)
		if content, err := os.ReadFile(keyPath); err == nil {
			return strings.TrimSpace(string(content)), nil
		}
	}

	return "", fmt.Errorf("no SSH public key found")
}

// getInstalledPackages retrieves list of installed packages
func (g *Generator) getInstalledPackages() ([]string, error) {
	cmd := exec.Command("dpkg", "--get-selections")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get package list: %w", err)
	}

	var packages []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "install" {
			packages = append(packages, fields[0])
		}
	}

	return packages, nil
}

// getUserGroups gets the groups for a user
func (g *Generator) getUserGroups(username string) ([]string, error) {
	cmd := exec.Command("groups", username)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get user groups: %w", err)
	}

	// Parse output: "username : group1 group2 group3"
	parts := strings.Split(string(output), ":")
	if len(parts) < 2 {
		return nil, fmt.Errorf("unexpected groups output format")
	}

	groupsStr := strings.TrimSpace(parts[1])
	groups := strings.Fields(groupsStr)

	return groups, nil
}

// GenerateConfig creates a cloud-init configuration
func (g *Generator) GenerateConfig(info *SystemInfo) (*CloudInitConfig, error) {
	_, span := telemetry.Start(g.rc.Ctx, "GenerateConfig")
	defer span.End()

	if info.SSHPublicKey == "" {
		g.logger.Warn("No SSH public key found - cloud-init will not have SSH access configured")
	}

	var sshKeys []string
	if info.SSHPublicKey != "" {
		sshKeys = append(sshKeys, info.SSHPublicKey)
	}

	config := &CloudInitConfig{
		Hostname:       info.Hostname,
		ManageEtcHosts: true,
		Network: NetworkConf{
			Version: 2,
			Ethernets: map[string]EthConf{
				"eth0": {DHCP4: true},
			},
		},
		Users: []UserConf{
			{
				Name:              info.Username,
				Sudo:              "ALL=(ALL) NOPASSWD:ALL",
				Shell:             "/bin/bash",
				Home:              info.UserHome,
				SSHAuthorizedKeys: sshKeys,
				Groups:            info.UserGroups,
			},
		},
		PackageUpdate:  true,
		PackageUpgrade: true,
		Packages:       info.InstalledPackages,
		RunCmd: []string{
			"echo 'Cloud-init finished successfully!' >> /var/log/cloud-init-output.log",
		},
		FinalMessage: fmt.Sprintf(`Eos Cloud-Init setup completed successfully!

System Information:
- Hostname: %s
- User: %s
- SSH Key: %s
- Packages: %d installed

Check /var/log/cloud-init-output.log for detailed setup logs.`,
			info.Hostname,
			info.Username,
			func() string {
				if info.SSHPublicKey != "" {
					return "configured"
				}
				return "not found"
			}(),
			len(info.InstalledPackages)),
	}

	return config, nil
}

// WriteConfig writes the cloud-init configuration to a file
func (g *Generator) WriteConfig(config *CloudInitConfig, outputPath string) error {
	_, span := telemetry.Start(g.rc.Ctx, "WriteConfig")
	defer span.End()

	// Validate output path
	if err := validateOutputPath(outputPath); err != nil {
		return fmt.Errorf("invalid output path: %w", err)
	}

	g.logger.Info("Writing cloud-init configuration",
		zap.String("path", outputPath))

	// Ensure directory exists
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Create YAML content
	yamlData, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}

	// Prepend cloud-config header
	content := "#cloud-config\n" + string(yamlData)

	// Write file with appropriate permissions
	if err := os.WriteFile(outputPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	g.logger.Info("Cloud-init configuration written successfully",
		zap.String("path", outputPath),
		zap.Int("packages", len(config.Packages)))

	fmt.Printf("Cloud-init file generated at %s\n", outputPath)

	return nil
}

// ValidateConfig performs basic validation on the configuration
func (g *Generator) ValidateConfig(config *CloudInitConfig) error {
	_, span := telemetry.Start(g.rc.Ctx, "ValidateConfig")
	defer span.End()

	if config.Hostname == "" {
		return eos_err.NewExpectedError(g.rc.Ctx,
			fmt.Errorf("hostname is required"))
	}

	if len(config.Users) == 0 {
		return eos_err.NewExpectedError(g.rc.Ctx,
			fmt.Errorf("at least one user must be configured"))
	}

	for _, u := range config.Users {
		if u.Name == "" {
			return eos_err.NewExpectedError(g.rc.Ctx,
				fmt.Errorf("user name is required"))
		}
	}

	return nil
}

// GenerateTemplate creates a customizable cloud-init template
func (g *Generator) GenerateTemplate(outputPath string) error {
	_, span := telemetry.Start(g.rc.Ctx, "GenerateTemplate")
	defer span.End()

	template := `#cloud-config
# Eos Cloud-Init Template
# Customize this template for your specific needs

# System configuration
hostname: my-server
manage_etc_hosts: true

# Network configuration
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: true
      # Static IP example:
      # addresses: [192.168.1.100/24]
      # gateway4: 192.168.1.1
      # nameservers:
      #   addresses: [8.8.8.8, 8.8.4.4]

# User configuration
users:
  - name: myuser
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... your-ssh-key-here"
    groups: [adm, dialout, cdrom, floppy, sudo, audio, dip, video, plugdev, netdev, lxd]

# Package management
package_update: true
package_upgrade: true
packages:
  - curl
  - wget
  - git
  - vim
  - htop
  - docker.io
  # Add your packages here

# Commands to run
runcmd:
  - echo "System configured successfully" | tee -a /var/log/custom-setup.log
  - systemctl enable docker
  - usermod -aG docker myuser
  # Add your commands here

# Write files
write_files:
  - path: /etc/myapp/config.yml
    content: |
      # My application configuration
      debug: false
      port: 8080
    permissions: '0644'

# Final message
final_message: |
  Cloud-init setup completed successfully!
  Your server is now ready for use.
`

	// Ensure directory exists
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	if err := os.WriteFile(outputPath, []byte(template), 0644); err != nil {
		return fmt.Errorf("failed to write template: %w", err)
	}

	g.logger.Info("Cloud-init template generated",
		zap.String("path", outputPath))

	fmt.Printf("Cloud-init template generated at %s\n", outputPath)
	fmt.Println("Edit this file and use it with your cloud provider.")

	return nil
}

// validateOutputPath validates that an output file path is safe to use
func validateOutputPath(path string) error {
	// Check for empty path
	if path == "" {
		return fmt.Errorf("output path cannot be empty")
	}

	// Check for path traversal attempts
	if strings.Contains(path, "..") {
		return fmt.Errorf("output path cannot contain '..' (path traversal)")
	}

	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return fmt.Errorf("output path cannot contain null bytes")
	}

	// Check for control characters
	if strings.ContainsAny(path, "\n\r\t") {
		return fmt.Errorf("output path cannot contain control characters")
	}

	// Clean the path and check it hasn't changed
	cleanPath := filepath.Clean(path)
	if cleanPath != path && path != "./" + cleanPath {
		// Allow relative paths that get cleaned (e.g., "./file" -> "file")
		if !strings.HasPrefix(path, "./") || cleanPath != strings.TrimPrefix(path, "./") {
			return fmt.Errorf("output path contains unsafe elements")
		}
	}

	// Check for sensitive system paths (absolute paths only)
	if filepath.IsAbs(path) {
		sensitivePaths := []string{"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/boot", "/sys", "/proc"}
		for _, sensitive := range sensitivePaths {
			if strings.HasPrefix(cleanPath, sensitive) {
				return fmt.Errorf("cannot write to sensitive system path: %s", sensitive)
			}
		}
	}

	// Check path length limit
	if len(path) > 4096 {
		return fmt.Errorf("output path too long (max 4096 characters)")
	}

	return nil
}
