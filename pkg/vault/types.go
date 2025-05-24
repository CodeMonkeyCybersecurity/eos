package vault

import (
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

var (
	EnableOpts EnableOptions
)

// EnableOptions controls which parts of the Vault enable sequence to run.
type EnableOptions struct {
	EnableAgent    bool
	EnableAPI      bool
	EnableAppRole  bool
	EnableUserpass bool // ← this must exist
	Password       string
	NonInteractive bool
	AppRoleOptions shared.AppRoleOptions
}

type AppRoleOptions struct {
	RoleName      string
	Policies      []string
	TokenTTL      string
	TokenMaxTTL   string
	SecretIDTTL   string
	ForceRecreate bool
	RefreshCreds  bool
}

func diskFallbackPath() string {
	return filepath.Join(shared.SecretsDir, shared.TestDataFilename)
}

type Audit struct {
	Type        string            `json:"type" mapstructure:"type"`
	Description string            `json:"description" mapstructure:"description"`
	Options     map[string]string `json:"options" mapstructure:"options"`
	Local       bool              `json:"local" mapstructure:"local"`
	Path        string            `json:"path" mapstructure:"path"`
}
