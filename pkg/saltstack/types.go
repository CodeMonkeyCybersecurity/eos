package saltstack

import (
	"time"
)

// Config represents the configuration options for SaltStack installation
type Config struct {
	MasterMode bool   // Install as master-minion instead of masterless
	SkipTest   bool   // Skip the verification test
	LogLevel   string // Salt log level (debug, info, warning, error)
}

// GetMode returns the installation mode as a string
func (c *Config) GetMode() string {
	if c.MasterMode {
		return "master-minion"
	}
	return "masterless"
}

// MinionConfig represents the Salt minion configuration
type MinionConfig struct {
	FileClient   string              `yaml:"file_client"`
	FileRoots    map[string][]string `yaml:"file_roots"`
	PillarRoots  map[string][]string `yaml:"pillar_roots"`
	LogLevel     string              `yaml:"log_level"`
	MasterHost   string              `yaml:"master,omitempty"`
	MinionID     string              `yaml:"id,omitempty"`
}

// InstallStatus represents the current installation status
type InstallStatus struct {
	Installed   bool
	Version     string
	ConfigPath  string
	StatesPath  string
	PillarPath  string
	LastChecked time.Time
}

// Constants for Salt configuration
const (
	// Paths
	SaltConfigDir    = "/etc/salt"
	MinionConfigPath = "/etc/salt/minion"
	SaltStatesDir    = "/srv/salt"
	SaltPillarDir    = "/srv/pillar"
	EosStatesDir     = "/srv/salt/eos"
	
	// Repository information
	SaltRepoKey     = "https://packages.broadcom.com/artifactory/api/gpg/key/public"
	SaltRepoKeyID   = "BCAA30E340B057F0FB2D97CB754C4B3A8C3095CF"
	SaltRepoBaseURL = "https://packages.broadcom.com/artifactory/saltproject-deb/"
	
	// Default configuration values
	DefaultLogLevel    = "warning"
	DefaultFileClient  = "local"
	DefaultMinionID    = "eos-minion"
	
	// Test state content
	TestStateName = "test"
	TestStateContent = `# EOS Salt test state
eos_test_file:
  file.managed:
    - name: /tmp/eos-salt-test.txt
    - contents: |
        EOS Salt installation verified
        Timestamp: {{ salt['cmd.run']('date') }}
    - mode: 644

eos_test_command:
  cmd.run:
    - name: echo "Salt is working correctly"
    - require:
      - file: eos_test_file
`
)

// Ubuntu release information
type UbuntuRelease struct {
	Version  string
	Codename string
	Arch     string
}

// GetSaltRepoURL returns the appropriate Salt repository URL for the Ubuntu release
func (r *UbuntuRelease) GetSaltRepoURL() string {
	// Map Ubuntu codenames to Salt repository paths
	// Salt uses specific paths for each Ubuntu release
	return SaltRepoBaseURL + "stable/ubuntu/" + r.Version + "/amd64/latest"
}

// GetRepoListPath returns the path to the apt sources list file for Salt
func GetRepoListPath() string {
	return "/etc/apt/sources.list.d/salt.list"
}