package vault

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

var (
	EnableOpts EnableOptions
)

// EnableOptions controls which parts of the Vault enable sequence to run.
type EnableOptions struct {
	EnableAppRole  bool
	EnableUserpass bool
	EnableAgent    bool
	EnableAPI      bool
	NonInteractive bool
	Password       string
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
