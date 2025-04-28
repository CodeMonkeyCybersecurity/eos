// pkg/vault/phase10_create_approle_auth.go

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

//--------------------------------------------------------------------
// 10. Create AppRole for EOS
//--------------------------------------------------------------------

// EnableAppRoleFlow(client, log, opts)
// ├── EnableAppRoleAuth(client, log)
// │    └── client.Sys().EnableAuthWithOptions("approle")
// ├── EnsureAppRole(client, log, opts)
// │    ├── os.Stat(RoleIDPath)
// │    ├── vault.refreshAppRoleCreds(client, log) (optional)
// │    ├── vault.EnableAppRoleAuth(client, log) (if needed)
// │    ├── client.Logical().Write(shared.RolePath, roleData)
// │    ├── vault.refreshAppRoleCreds(client, log)
// │    └── vault.WriteAppRoleFiles(roleID, secretID, log)
// │         ├── system.EnsureOwnedDir
// │         └── system.WriteOwnedFile(role_id, secret_id)
// └── Done

func PhaseEnableAppRole(client *api.Client, log *zap.Logger, opts shared.AppRoleOptions) error {
	log.Info("[Phase10] Setting up Vault AppRole")
	return EnableAppRoleFlow(client, log, opts)
}

// EnableAppRoleFlow enables AppRole authentication method
// and provisions EOS-specific AppRole credentials.
func EnableAppRoleFlow(client *api.Client, log *zap.Logger, opts shared.AppRoleOptions) error {
	log.Info("🪪 [Enable] Starting AppRole setup flow")

	log.Info("📡 Checking if AppRole auth method is enabled")
	if err := EnableAppRoleAuth(client, log); err != nil {
		return fmt.Errorf("enable approle auth: %w", err)
	}

	log.Info("🔑 Creating or reusing AppRole credentials")
	roleID, secretID, err := EnsureAppRole(client, log, opts)
	if err != nil {
		return fmt.Errorf("ensure AppRole: %w", err)
	}

	log.Info("✏️ Writing AppRole credentials to disk")
	if err := WriteAppRoleFiles(roleID, secretID, log); err != nil {
		return fmt.Errorf("write AppRole files: %w", err)
	}

	log.Info("✅ AppRole setup complete", zap.String("role_id", roleID))
	return nil
}