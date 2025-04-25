// pkg/shared/vault_vars.go

package shared

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/hashicorp/vault/api"
)

var Policies = map[string]string{
	EosVaultPolicy: `
  # Give EOS full root‑style access
  path "**" {
	capabilities = ["create","read","update","delete","list","sudo"]
  }
  `,
}

var (
	// Vault Secrets + Tokens
	SecretsDir                = "/var/lib/eos/secrets"
	VaultInitPath             = filepath.Join(SecretsDir, "vault_init"+SecretsExt)
	DelphiFallbackSecretsPath = filepath.Join(SecretsDir, "delphi_fallback"+SecretsExt)
	EosUserVaultFallback      = filepath.Join(SecretsDir, "vault_userpass"+SecretsExt)
	RoleIDPath                = filepath.Join(SecretsDir, "role_id")
	SecretIDPath              = filepath.Join(SecretsDir, "secret_id")
	VaultClient               *api.Client

	// Runtime dirs
	EosRunDir           = "/run/eos"
	VaultAgentTokenPath = filepath.Join(EosRunDir, "vault_agent_eos.token")
	AgentPID            = filepath.Join(EosRunDir, "vault_agent.pid")
	VaultPID            = filepath.Join(EosRunDir, "vault.pid")
	VaultTokenSinkPath  = filepath.Join(EosRunDir, ".vault-token")
)

var VaultHealthEndpoint = fmt.Sprintf("https://%s/v1/sys/health", strings.Split(ListenerAddr, ":")[0])
